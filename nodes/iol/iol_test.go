package cisco_iol

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	clabmocksmockruntime "github.com/srl-labs/containerlab/mocks/mockruntime"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabtypes "github.com/srl-labs/containerlab/types"
	"go.uber.org/mock/gomock"
)

// NTG-180: IOL reads /iol/config.txt a few seconds after the container starts. When the boot
// config was only written in PostDeploy, after the start, a node could read it empty or cut off.
func newTestIOL(t *testing.T, mgmtIP string) *iol {
	t.Helper()
	ctrl := gomock.NewController(t)
	rt := clabmocksmockruntime.NewMockContainerRuntime(ctrl)
	rt.EXPECT().Mgmt().Return(&clabtypes.MgmtNet{IPv4Subnet: "172.20.15.0/24", IPv4Gw: "172.20.15.1"}).AnyTimes()
	n := &iol{}
	n.DefaultNode = *clabnodes.NewDefaultNode(n)
	n.Cfg = &clabtypes.NodeConfig{ShortName: "router1", LabDir: t.TempDir(), MgmtIPv4Address: mgmtIP}
	n.nvramFile = "nvram_00001"
	n.WithRuntime(rt)
	return n
}

func bootConfig(t *testing.T, n *iol) string {
	t.Helper()
	b, err := os.ReadFile(path.Join(n.Cfg.LabDir, "boot_config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCreateIOLFilesWritesTheBootConfigBeforeStart(t *testing.T) {
	n := newTestIOL(t, "172.20.15.2")
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := bootConfig(t, n)
	for _, want := range []string{
		"hostname router1",
		"ip address 172.20.15.2 255.255.255.0",
		"ip route vrf clab-mgmt 0.0.0.0 0.0.0.0 Ethernet0/0 172.20.15.1",
		"ip ssh version 2",
		"\nend",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("boot config lacks %q:\n%s", want, cfg)
		}
	}
	// No IPv6 on the mgmt network: no half-written IPv6 lines.
	if strings.Contains(cfg, "ipv6 address /0") || strings.Contains(cfg, "::/0 Ethernet0/0 \n") {
		t.Errorf("boot config has empty IPv6 lines:\n%s", cfg)
	}
}

func TestPostDeployKeepsAPreDeployBootConfig(t *testing.T) {
	n := newTestIOL(t, "172.20.15.2")
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := path.Join(n.Cfg.LabDir, "boot_config.txt")
	if err := os.WriteFile(p, []byte("sentinel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.postDeployBootConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := bootConfig(t, n); got != "sentinel\n" {
		t.Errorf("PostDeploy rewrote the boot config while IOL boots: %q", got)
	}
}

func TestARestartKeepsTheExistingBootConfig(t *testing.T) {
	// A restart builds a fresh node without PreDeploy, so it has no data interfaces to render.
	n := newTestIOL(t, "172.20.15.2")
	p := path.Join(n.Cfg.LabDir, "boot_config.txt")
	if err := os.WriteFile(p, []byte("hostname router1\ninterface Ethernet0/1\nend\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.postDeployBootConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := bootConfig(t, n); !strings.Contains(got, "interface Ethernet0/1") {
		t.Errorf("restart rewrote the boot config without its data interfaces: %q", got)
	}
}

func TestWithoutAPinnedAddressPostDeployStillWritesIt(t *testing.T) {
	n := newTestIOL(t, "")
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	n.Cfg.MgmtIPv4Address = "172.20.15.9" // learned from the runtime after start
	if err := n.postDeployBootConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := bootConfig(t, n); !strings.Contains(got, "ip address 172.20.15.9") {
		t.Errorf("unpinned node got no boot config: %q", got)
	}
}
