package links

// These tests need root, nft and nsenter: they create netns, a dummy uplink and real macvlans.
// Run them in a container with NET_ADMIN and SYS_ADMIN (see the NTG-249 PR).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	clabnodesstate "github.com/srl-labs/containerlab/nodes/state"
	clabutils "github.com/srl-labs/containerlab/utils"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type envLinkNode struct {
	GenericLinkNode
	env map[string]string
}

func (n *envLinkNode) GetEnv() map[string]string { return n.env }

func (*envLinkNode) GetLinkEndpointType() LinkEndpointType { return LinkEndpointTypeVeth }

func (*envLinkNode) GetState() clabnodesstate.NodeState { return clabnodesstate.Deployed }

const testUplink = "ngup0"

func netnsSetup(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, bin := range []string{"nft", "nsenter"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("needs %s", bin)
		}
	}
	CloudRegistryDir = t.TempDir()
	if l, err := netlink.LinkByName(testUplink); err == nil {
		_ = netlink.LinkDel(l)
	}
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: testUplink}}); err != nil {
		t.Fatal(err)
	}
	up, _ := netlink.LinkByName(testUplink)
	if err := netlink.LinkSetUp(up); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(up) })
}

var nsSeq int

func newNodeNS(t *testing.T, env map[string]string) (*envLinkNode, ns.NetNS) {
	t.Helper()
	nsSeq++
	name := "ngtest-" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + string(rune('a'+nsSeq))
	path, err := clabutils.CreateNamedNetNS(name)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ns.GetNS(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close(); _ = vnetns.DeleteNamed(name) })
	node := &envLinkNode{GenericLinkNode: GenericLinkNode{shortname: "r1", nspath: path}, env: env}
	return node, n
}

func newCloudLink(node Node) *LinkMacVlan {
	l := &LinkMacVlan{Mode: MacVlanModePrivate}
	l.HostEndpoint = NewEndpointMacVlan(NewEndpointGeneric(GetHostLinkNode(), testUplink, l))
	ep := NewEndpointMacVlan(NewEndpointGeneric(node, "eth1", l))
	ep.MAC = testMAC
	l.NodeEndpoint = ep
	return l
}

func linkIn(t *testing.T, n ns.NetNS, name string) netlink.Link {
	t.Helper()
	var l netlink.Link
	_ = n.Do(func(ns.NetNS) error {
		l, _ = netlink.LinkByName(name)
		return nil
	})
	return l
}

func nftList(t *testing.T, n ns.NetNS) string {
	out, _ := exec.Command("nsenter", "--net="+n.Path(), "nft", "list", "table", "netdev",
		cloudGuardTable).CombinedOutput()
	return string(out)
}

func macvlansOnHost(t *testing.T) []string {
	t.Helper()
	all, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range all {
		if l.Type() == "macvlan" {
			names = append(names, l.Attrs().Name)
		}
	}
	return names
}

func TestNetnsCloudDeployGuardsBeforeUp(t *testing.T) {
	netnsSetup(t)
	node, n := newNodeNS(t, testEnv())
	if err := newCloudLink(node).Deploy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	l := linkIn(t, n, "eth1")
	if l == nil || l.Type() != "macvlan" || l.Attrs().Flags&net.FlagUp == 0 ||
		l.Attrs().HardwareAddr.String() != testMAC.String() {
		t.Fatalf("link %+v", l)
	}
	listing := nftList(t, n)
	for _, want := range []string{`egress device "eth1"`, "policy drop", "10.70.38.200-10.70.38.209"} {
		if !strings.Contains(listing, want) {
			t.Fatalf("missing %q in\n%s", want, listing)
		}
	}
	var st unix.Stat_t
	if err := unix.Stat(n.Path(), &st); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cloudRegistryPath(st.Ino, "eth1"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(listing))
	want := "10.70.38.200 aa:bb:cc:00:c8:10 " + hex.EncodeToString(sum[:]) + " eth1\n"
	if string(data) != want {
		t.Fatalf("registry %q, want %q", data, want)
	}
}

func TestNetnsCloudDeployFailsClosed(t *testing.T) {
	netnsSetup(t)
	for name, env := range map[string]map[string]string{
		"no env":  nil,
		"no pool": {EnvCloudIP: "10.70.38.200"},
	} {
		t.Run(name, func(t *testing.T) {
			node, n := newNodeNS(t, env)
			if err := newCloudLink(node).Deploy(context.Background(), nil); err == nil {
				t.Fatal("deployed")
			}
			if l := linkIn(t, n, "eth1"); l != nil {
				t.Fatalf("left %s in the node", l.Attrs().Name)
			}
			if left := macvlansOnHost(t); len(left) != 0 {
				t.Fatalf("left %v on the host", left)
			}
		})
	}
}

func TestNetnsCloudAddressHeldLocally(t *testing.T) {
	netnsSetup(t)
	first, _ := newNodeNS(t, testEnv())
	if err := newCloudLink(first).Deploy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	second, n2 := newNodeNS(t, testEnv())
	err := newCloudLink(second).Deploy(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), CloudIPInUse+" 10.70.38.200") {
		t.Fatalf("err %v", err)
	}
	if l := linkIn(t, n2, "eth1"); l != nil || len(macvlansOnHost(t)) != 0 {
		t.Fatal("left a macvlan behind")
	}
}

// Activate is how restore after a recreate, a failed park and start bring a macvlan back up.
func TestNetnsCloudActivateGuards(t *testing.T) {
	netnsSetup(t)
	node, n := newNodeNS(t, nil)
	link := newCloudLink(node)
	up, _ := netlink.LinkByName(testUplink)
	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Name: "eth1", ParentIndex: up.Attrs().Index, HardwareAddr: testMAC},
		Mode:      netlink.MACVLAN_MODE_PRIVATE,
	}
	if err := netlink.LinkAdd(mv); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(mv, int(n.Fd())); err != nil {
		t.Fatal(err)
	}
	ep := link.NodeEndpoint

	if err := ep.Activate(context.Background()); err == nil {
		t.Fatal("activated without env")
	}
	if l := linkIn(t, n, "eth1"); l.Attrs().Flags&net.FlagUp != 0 {
		t.Fatal("up without a guard")
	}

	node.env = testEnv()
	if err := ep.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l := linkIn(t, n, "eth1"); l.Attrs().Flags&net.FlagUp == 0 {
		t.Fatal("not up")
	}
	if !strings.Contains(nftList(t, n), `egress device "eth1"`) {
		t.Fatal("no guard")
	}
}

func TestNetnsCloudOneMacvlanPerNetns(t *testing.T) {
	netnsSetup(t)
	node, n := newNodeNS(t, testEnv())
	if err := newCloudLink(node).Deploy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	env := testEnv()
	env[EnvCloudIP] = "10.70.38.201"
	node.env = env
	l := newCloudLink(node)
	l.NodeEndpoint.(*EndpointMacVlan).IfaceName = "eth2"
	if err := l.Deploy(context.Background(), nil); err == nil {
		t.Fatal("second macvlan deployed")
	}
	if linkIn(t, n, "eth2") != nil {
		t.Fatal("left eth2")
	}
}

// capture returns the ARP frames that leave the uplink while send runs.
func capture(t *testing.T, send func()) [][]byte {
	t.Helper()
	up, _ := netlink.LinkByName(testUplink)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL),
		Ifindex: up.Attrs().Index}); err != nil {
		t.Fatal(err)
	}
	tv := unix.NsecToTimeval((300 * time.Millisecond).Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	send()
	var frames [][]byte
	buf := make([]byte, 2048)
	for {
		k, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return frames
		}
		frames = append(frames, append([]byte(nil), buf[:k]...))
	}
}

func arpFrom(mac net.HardwareAddr, spa [4]byte) []byte {
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], mac)
	f[12], f[13] = 0x08, 0x06
	copy(f[14:22], []byte{0, 1, 8, 0, 6, 4, 0, 1})
	copy(f[22:28], mac)
	copy(f[28:32], spa[:])
	copy(f[38:42], []byte{10, 70, 38, 1})
	return f
}

// The guard is what keeps a student's router from spoofing on the faculty LAN.
func TestNetnsCloudGuardFiltersEgress(t *testing.T) {
	netnsSetup(t)
	node, n := newNodeNS(t, testEnv())
	if err := newCloudLink(node).Deploy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	spoofMAC := net.HardwareAddr{0x00, 0x0c, 0x29, 0x5c, 0x59, 0x5e}
	frames := map[string][]byte{
		"own":         arpFrom(testMAC, [4]byte{10, 70, 38, 200}),
		"spoofed mac": arpFrom(spoofMAC, [4]byte{10, 70, 38, 200}),
		"other ip":    arpFrom(testMAC, [4]byte{10, 70, 38, 13}),
	}
	// "own" goes last: it must still leave after the router sent blocked frames
	seen := capture(t, func() {
		err := n.Do(func(ns.NetNS) error {
			l, err := netlink.LinkByName("eth1")
			if err != nil {
				return err
			}
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			sa := &unix.SockaddrLinklayer{Ifindex: l.Attrs().Index}
			// iouyap stops forwarding every IOS port on a send error, so a blocked frame must
			// still report success
			for _, name := range []string{"spoofed mac", "other ip", "own"} {
				if err := unix.Sendto(fd, frames[name], 0, sa); err != nil {
					return fmt.Errorf("send %s: %w", name, err)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	got := map[string]bool{}
	for name, f := range frames {
		for _, s := range seen {
			if len(s) >= 42 && string(s[:42]) == string(f) {
				got[name] = true
			}
		}
	}
	if !got["own"] || got["spoofed mac"] || got["other ip"] {
		t.Fatalf("frames out: %v (want only own)", got)
	}
	if sink := linkIn(t, n, cloudSink); sink == nil || sink.Attrs().Statistics.TxPackets < 2 {
		t.Fatalf("sink %+v", sink)
	}
}

// A stopped node's macvlan sits in its parking netns; destroy must not leave it holding the MAC.
func TestNetnsDeleteParkingNetnsTakesTheMacvlan(t *testing.T) {
	netnsSetup(t)
	parkPath, err := clabutils.CreateNamedNetNS(clabutils.ParkingNetnsName("clab-zz-r1"))
	if err != nil {
		t.Fatal(err)
	}
	park, err := ns.GetNS(parkPath)
	if err != nil {
		t.Fatal(err)
	}
	up, _ := netlink.LinkByName(testUplink)
	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Name: "parked0", ParentIndex: up.Attrs().Index, HardwareAddr: testMAC},
		Mode:      netlink.MACVLAN_MODE_PRIVATE,
	}
	if err := netlink.LinkAdd(mv); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(mv, int(park.Fd())); err != nil {
		t.Fatal(err)
	}
	park.Close()

	if err := clabutils.DeleteParkingNetns("/clab-zz-r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(parkPath); !os.IsNotExist(err) {
		t.Fatalf("parking netns still there: %v", err)
	}
	// macvlan refuses a second child with the same MAC on one parent: once the parked one is
	// gone the MAC is free again (the kernel frees a netns asynchronously)
	deadline := time.Now().Add(5 * time.Second)
	for {
		again := &netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "again0", ParentIndex: up.Attrs().Index, HardwareAddr: testMAC},
			Mode:      netlink.MACVLAN_MODE_PRIVATE,
		}
		err := netlink.LinkAdd(again)
		if err == nil {
			_ = netlink.LinkDel(again)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("MAC still held after the parking netns was deleted: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := clabutils.DeleteParkingNetns("clab-zz-r1"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// A stopped or recreated router parks its macvlan DOWN; restore must reinstall the guard in the
// new netns, and no other router may take the address while it is parked.
func TestNetnsCloudParkAndRestore(t *testing.T) {
	netnsSetup(t)
	node, _ := newNodeNS(t, testEnv())
	link := newCloudLink(node)
	if err := link.Deploy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := node.AddEndpoint(link.NodeEndpoint); err != nil {
		t.Fatal(err)
	}
	parkPath, err := clabutils.CreateNamedNetNS(clabutils.ParkingNetnsName("clab-zz-park-r1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clabutils.DeleteParkingNetns("clab-zz-park-r1") })
	park := NewParkingNode("clab-zz-park-r1", parkPath)
	if err := park.CaptureFrom(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	// the record follows the link, or the watcher prunes it with the old netns
	var parkSt unix.Stat_t
	if err := unix.Stat(parkPath, &parkSt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cloudRegistryPath(parkSt.Ino, "eth1")); err != nil {
		t.Fatalf("record did not move to the parking netns: %v", err)
	}

	// another router asks for the same address while this one is parked
	other, _ := newNodeNS(t, testEnv())
	otherLink := newCloudLink(other)
	otherLink.NodeEndpoint.(*EndpointMacVlan).MAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0xc8, 0x01}
	err = otherLink.Deploy(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), CloudIPInUse) {
		t.Fatalf("deployed over a parked router: %v", err)
	}

	// the node comes back in a fresh netns, as after a recreate
	_, fresh := newNodeNS(t, nil)
	node.nspath = fresh.Path()
	if _, err := park.RestoreTo(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	l := linkIn(t, fresh, "eth1")
	if l == nil || l.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("not restored up: %+v", l)
	}
	if !strings.Contains(nftList(t, fresh), `egress device "eth1"`) {
		t.Fatal("restored without a guard")
	}
}

// A router coming back from a stop must not go up on an address another router took meanwhile.
func TestNetnsCloudActivateRefusesAddressHeldLocally(t *testing.T) {
	netnsSetup(t)
	holder, _ := newNodeNS(t, testEnv())
	if err := newCloudLink(holder).Deploy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	node, n := newNodeNS(t, testEnv())
	link := newCloudLink(node)
	up, _ := netlink.LinkByName(testUplink)
	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Name: "eth1", ParentIndex: up.Attrs().Index,
			HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0xc8, 0x01}},
		Mode: netlink.MACVLAN_MODE_PRIVATE,
	}
	if err := netlink.LinkAdd(mv); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(mv, int(n.Fd())); err != nil {
		t.Fatal(err)
	}
	err := link.NodeEndpoint.Activate(context.Background())
	if err == nil || !strings.Contains(err.Error(), CloudIPInUse) {
		t.Fatalf("err %v", err)
	}
	if l := linkIn(t, n, "eth1"); l.Attrs().Flags&net.FlagUp != 0 {
		t.Fatal("came up")
	}
}

// A device already named like the sink could carry blocked frames somewhere.
func TestNetnsCloudRefusesANonDummySink(t *testing.T) {
	netnsSetup(t)
	node, n := newNodeNS(t, testEnv())
	if err := n.Do(func(ns.NetNS) error {
		return netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: cloudSink}, PeerName: "peer0"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := newCloudLink(node).Deploy(context.Background(), nil); err == nil {
		t.Fatal("deployed with a veth as the sink")
	}
	if linkIn(t, n, "eth1") != nil {
		t.Fatal("left eth1")
	}
}
