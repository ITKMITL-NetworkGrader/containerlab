package links

// NTG-249: a macvlan puts a student's router on the faculty LAN. Before the interface goes UP,
// containerlab installs an nft egress guard in the router's netns that only lets the router's
// own MAC/IP out, so the router cannot spoof, serve DHCP, or reach other routers in the pool.
// An interface that cannot get a guard never goes UP.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	EnvCloudIP   = "NG_CLOUD_IP"
	EnvCloudPool = "NG_CLOUD_POOL"
	EnvCloudRate = "NG_CLOUD_RATE"

	// CloudIPInUse prefixes the error when the address already answers on the LAN or is held by
	// another macvlan on this host; Elysia moves the session to another address.
	CloudIPInUse = "NG_CLOUD_IP_IN_USE"

	cloudGuardTable    = "ng_cloud"
	defaultCloudRateMB = 10
)

// CloudRegistryDir holds one file per guarded interface, read by ng-cloud-watch on the host.
var CloudRegistryDir = "/run/ng-cloud"

// EnvNode is implemented by container nodes; the guard reads its addresses from the node env.
type EnvNode interface {
	GetEnv() map[string]string
}

type cloudGuard struct {
	dev                 string
	mac                 net.HardwareAddr
	ip                  netip.Addr
	poolFirst, poolLast netip.Addr
	rateMB              int
}

func cloudGuardFromEnv(env map[string]string, dev string, mac net.HardwareAddr) (*cloudGuard, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("macvlan %s: no MAC address", dev)
	}
	ip, err := netip.ParseAddr(env[EnvCloudIP])
	if err != nil || !ip.Is4() {
		return nil, fmt.Errorf("macvlan %s: node env %s=%q must be an IPv4 address",
			dev, EnvCloudIP, env[EnvCloudIP])
	}
	first, last, ok := strings.Cut(env[EnvCloudPool], "-")
	pf, err1 := netip.ParseAddr(first)
	pl, err2 := netip.ParseAddr(last)
	if !ok || err1 != nil || err2 != nil || !pf.Is4() || !pl.Is4() || pl.Less(pf) {
		return nil, fmt.Errorf("macvlan %s: node env %s=%q must be <first>-<last>",
			dev, EnvCloudPool, env[EnvCloudPool])
	}
	if ip.Less(pf) || pl.Less(ip) {
		return nil, fmt.Errorf("macvlan %s: %s %s is outside the pool %s",
			dev, EnvCloudIP, ip, env[EnvCloudPool])
	}
	rate := defaultCloudRateMB
	if v, set := env[EnvCloudRate]; set {
		rate, err = strconv.Atoi(v)
		if err != nil || rate < 1 || rate > 100 {
			return nil, fmt.Errorf("macvlan %s: node env %s=%q must be 1-100 (MB/s)",
				dev, EnvCloudRate, v)
		}
	}
	return &cloudGuard{dev: dev, mac: mac, ip: ip, poolFirst: pf, poolLast: pl, rateMB: rate}, nil
}

// rules is one nft transaction: it replaces any table left from an earlier install.
func (g *cloudGuard) rules() string {
	return fmt.Sprintf(`table netdev %[1]s
delete table netdev %[1]s
table netdev %[1]s {
	chain out {
		type filter hook egress device %[2]q priority 0; policy drop;
		ether saddr != %[3]s drop
		ip daddr %[5]s-%[6]s ip daddr != %[4]s drop
		limit rate over %[7]d mbytes/second drop
		ip saddr %[4]s udp sport { 67, 68 } drop
		ip saddr %[4]s udp dport { 67, 68 } drop
		ether type ip ip saddr %[4]s accept
		ether type arp arp saddr ether %[3]s arp saddr ip %[4]s accept
	}
}
`, cloudGuardTable, g.dev, g.mac, g.ip, g.poolFirst, g.poolLast, g.rateMB)
}

// currentNetnsPath names the netns of the calling thread; valid only inside ns.Do.
func currentNetnsPath() string {
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}

func nftIn(nsPath, stdin string, args ...string) (string, error) {
	cmd := exec.Command("nsenter", append([]string{"--net=" + nsPath, "nft"}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// install loads the guard into the calling thread's netns (call it inside ns.Do) and records it
// for ng-cloud-watch. The caller holds the cloud lock.
func (g *cloudGuard) install() error {
	nsPath := currentNetnsPath()
	if _, err := nftIn(nsPath, g.rules(), "-f", "-"); err != nil {
		return err
	}
	listing, err := nftIn(nsPath, "", "list", "table", "netdev", cloudGuardTable)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Stat(nsPath, &st); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(listing))
	if err := os.MkdirAll(CloudRegistryDir, 0o700); err != nil {
		return err
	}
	// one line, read by the shell watcher: ip mac sha256 dev
	entry := fmt.Sprintf("%s %s %s %s\n", g.ip, g.mac, hex.EncodeToString(sum[:]), g.dev)
	return os.WriteFile(cloudRegistryPath(st.Ino, g.dev), []byte(entry), 0o600)
}

func cloudRegistryPath(nsInode uint64, dev string) string {
	return filepath.Join(CloudRegistryDir, fmt.Sprintf("%d-%s", nsInode, dev))
}

// lockCloud serializes guard installs with ng-cloud-watch, which holds the same lock.
func lockCloud() (unlock func(), err error) {
	if err := os.MkdirAll(CloudRegistryDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(CloudRegistryDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// guardAndUp installs the guard for an interface already named and addressed in the calling
// thread's netns, then brings it up. env comes from the node that owns the netns. The caller
// holds the cloud lock.
func guardAndUp(link netlink.Link, env map[string]string) error {
	g, err := cloudGuardFromEnv(env, link.Attrs().Name, link.Attrs().HardwareAddr)
	if err != nil {
		return err
	}
	// one table per netns guards one device: a second macvlan would replace the first's rules
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, other := range links {
		if other.Type() == "macvlan" && other.Attrs().Index != link.Attrs().Index {
			return fmt.Errorf("macvlan %s: netns already has macvlan %s", g.dev, other.Attrs().Name)
		}
	}
	if err := g.install(); err != nil {
		return fmt.Errorf("macvlan %s: guard: %w", g.dev, err)
	}
	return netlink.LinkSetUp(link)
}

func nodeEnv(n Node) map[string]string {
	if en, ok := n.(EnvNode); ok {
		return en.GetEnv()
	}
	return nil
}

// cloudIPHeldLocally reports whether a guarded macvlan on this host still uses ip.
func cloudIPHeldLocally(ip netip.Addr) (bool, error) {
	entries, err := os.ReadDir(CloudRegistryDir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	live := liveNetnsByInode()
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(CloudRegistryDir, e.Name()))
		if err != nil || e.Name() == "lock" {
			continue
		}
		f := strings.Fields(string(data))
		if len(f) != 4 || f[0] != ip.String() {
			continue
		}
		inode, _, _ := strings.Cut(e.Name(), "-")
		nsPath, ok := live[inode]
		if !ok {
			continue
		}
		if macvlanPresent(nsPath, f[3], f[1]) {
			return true, nil
		}
	}
	return false, nil
}

// liveNetnsByInode maps netns inodes to the named netns clab keeps for containers and parking.
func liveNetnsByInode() map[string]string {
	live := map[string]string{}
	paths, _ := filepath.Glob("/run/netns/*")
	for _, p := range paths {
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil {
			live[strconv.FormatUint(st.Ino, 10)] = p
		}
	}
	return live
}

func macvlanPresent(nsPath, dev, mac string) bool {
	h, err := ns.GetNS(nsPath)
	if err != nil {
		return false
	}
	defer h.Close()
	found := false
	_ = h.Do(func(ns.NetNS) error {
		l, err := netlink.LinkByName(dev)
		found = err == nil && l.Type() == "macvlan" && l.Attrs().HardwareAddr.String() == mac
		return nil
	})
	return found
}

// checkCloudIPFree fails with CloudIPInUse when ip is held by another macvlan on this host or
// answers ARP on the host's uplink. The caller holds the cloud lock.
func checkCloudIPFree(ctx context.Context, uplink string, ip netip.Addr) error {
	held, err := cloudIPHeldLocally(ip)
	if err != nil {
		return err
	}
	if !held {
		held, err = arpProbe(ctx, uplink, ip)
		if err != nil {
			return fmt.Errorf("ARP probe for %s on %s: %w", ip, uplink, err)
		}
	}
	if held {
		return fmt.Errorf("%s %s", CloudIPInUse, ip)
	}
	return nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// arpProbeFrame is an RFC 5227 probe: sender IP 0.0.0.0, so no neighbour learns anything.
func arpProbeFrame(src net.HardwareAddr, ip netip.Addr) []byte {
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], src)
	f[12], f[13] = 0x08, 0x06
	copy(f[14:22], []byte{0, 1, 8, 0, 6, 4, 0, 1}) // ethernet, IPv4, request
	copy(f[22:28], src)
	t := ip.As4()
	copy(f[38:42], t[:])
	return f
}

// arpClaims reports whether frame is an ARP packet whose sender is ip: a reply, or another
// host's announcement.
func arpClaims(frame []byte, ip netip.Addr) bool {
	if len(frame) < 42 || frame[12] != 0x08 || frame[13] != 0x06 {
		return false
	}
	t := ip.As4()
	return string(frame[28:32]) == string(t[:])
}

func arpProbe(ctx context.Context, ifname string, ip netip.Addr) (bool, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return false, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifi.Index}
	if err := unix.Bind(fd, sa); err != nil {
		return false, err
	}
	tv := unix.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return false, err
	}
	frame := arpProbeFrame(ifi.HardwareAddr, ip)
	buf := make([]byte, 128)
	// two probes, one second apart, listening for two seconds
	start := time.Now()
	for sent := 0; time.Since(start) < 2*time.Second; {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if sent < 2 && time.Since(start) >= time.Duration(sent)*time.Second {
			if err := unix.Sendto(fd, frame, 0, sa); err != nil {
				return false, err
			}
			sent++
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return false, err
		}
		if arpClaims(buf[:n], ip) {
			return true, nil
		}
	}
	return false, nil
}
