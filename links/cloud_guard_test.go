package links

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0xc8, 0x10}

func testEnv() map[string]string {
	return map[string]string{
		EnvCloudIP:   "10.70.38.200",
		EnvCloudPool: "10.70.38.200-10.70.38.209",
	}
}

func TestCloudGuardRules(t *testing.T) {
	g, err := cloudGuardFromEnv(testEnv(), "eth1", testMAC)
	if err != nil {
		t.Fatal(err)
	}
	want := `table netdev ng_cloud
delete table netdev ng_cloud
table netdev ng_cloud {
	chain out {
		type filter hook egress device "eth1" priority 0; policy drop;
		ether saddr != aa:bb:cc:00:c8:10 fwd to "ngsink"
		ip daddr 10.70.38.200-10.70.38.209 ip daddr != 10.70.38.200 fwd to "ngsink"
		limit rate over 10 mbytes/second fwd to "ngsink"
		ip saddr 10.70.38.200 udp sport { 67, 68 } fwd to "ngsink"
		ip saddr 10.70.38.200 udp dport { 67, 68 } fwd to "ngsink"
		ether type ip ip saddr 10.70.38.200 accept
		ether type arp arp saddr ether aa:bb:cc:00:c8:10 arp saddr ip 10.70.38.200 accept
		fwd to "ngsink"
	}
}
`
	if got := g.rules(); got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
}

func TestCloudGuardRate(t *testing.T) {
	env := testEnv()
	env[EnvCloudRate] = "25"
	g, err := cloudGuardFromEnv(env, "eth1", testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.rules(), "limit rate over 25 mbytes/second fwd to \"ngsink\"") {
		t.Fatal(g.rules())
	}
}

func TestCloudGuardRejectsBadEnv(t *testing.T) {
	cases := map[string]func(map[string]string){
		"no ip":           func(e map[string]string) { delete(e, EnvCloudIP) },
		"ipv6 ip":         func(e map[string]string) { e[EnvCloudIP] = "fe80::1" },
		"no pool":         func(e map[string]string) { delete(e, EnvCloudPool) },
		"pool one end":    func(e map[string]string) { e[EnvCloudPool] = "10.70.38.200" },
		"pool reversed":   func(e map[string]string) { e[EnvCloudPool] = "10.70.38.209-10.70.38.200" },
		"ip below pool":   func(e map[string]string) { e[EnvCloudIP] = "10.70.38.199" },
		"ip above pool":   func(e map[string]string) { e[EnvCloudIP] = "10.70.38.210" },
		"rate zero":       func(e map[string]string) { e[EnvCloudRate] = "0" },
		"rate too high":   func(e map[string]string) { e[EnvCloudRate] = "101" },
		"rate not number": func(e map[string]string) { e[EnvCloudRate] = "fast" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			env := testEnv()
			mutate(env)
			if _, err := cloudGuardFromEnv(env, "eth1", testMAC); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("nil env", func(t *testing.T) {
		if _, err := cloudGuardFromEnv(nil, "eth1", testMAC); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no mac", func(t *testing.T) {
		if _, err := cloudGuardFromEnv(testEnv(), "eth1", nil); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestARPProbeFrame(t *testing.T) {
	src := net.HardwareAddr{0, 0x0c, 0x29, 0x5c, 0x59, 0x5e}
	ip := netip.MustParseAddr("10.70.38.200")
	f := arpProbeFrame(src, ip)
	if len(f) != 42 {
		t.Fatalf("len %d", len(f))
	}
	if string(f[0:6]) != "\xff\xff\xff\xff\xff\xff" || string(f[6:12]) != string(src) ||
		f[12] != 0x08 || f[13] != 0x06 || f[21] != 1 {
		t.Fatalf("header % x", f[:22])
	}
	if string(f[28:32]) != "\x00\x00\x00\x00" || string(f[38:42]) != "\x0a\x46\x26\xc8" {
		t.Fatalf("addresses % x", f[22:])
	}
	// our own probe (sender 0.0.0.0) is not a claim; a reply from the address is
	if arpClaims(f, ip) {
		t.Fatal("own probe counted as a claim")
	}
	reply := append([]byte(nil), f...)
	copy(reply[28:32], []byte{10, 70, 38, 200})
	if !arpClaims(reply, ip) {
		t.Fatal("reply not counted")
	}
	if arpClaims(reply, netip.MustParseAddr("10.70.38.201")) {
		t.Fatal("other address counted")
	}
	reply[13] = 0x00
	if arpClaims(reply, ip) {
		t.Fatal("non-ARP frame counted")
	}
}
