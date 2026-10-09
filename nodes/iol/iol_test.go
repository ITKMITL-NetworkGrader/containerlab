package cisco_iol

import (
	"context"
	"errors"
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
	n.hostNvram = path.Join(n.Cfg.LabDir, "nvram")
	n.hostVlanDat = path.Join(n.Cfg.LabDir, "vlan.dat")
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

// NTG-194: response.Failed only knows a few syntax errors, so a write that IOS did not confirm
// must fail the save too. Outputs measured on dev IOL 15.7 router, 15.2 switch and 17.12 router.
func TestWriteMemoryResult(t *testing.T) {
	for _, ok := range []string{
		"Building configuration...\n\n  [OK]",
		"Building configuration...\nCompressed configuration from 1280 bytes to 855 bytes[OK]",
		"Building configuration...\n[OK]",
	} {
		if err := writeMemoryResult(ok, nil); err != nil {
			t.Errorf("writeMemoryResult(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "%Error opening nvram:startup-config (No space left on device)"} {
		if err := writeMemoryResult(bad, nil); err == nil {
			t.Errorf("writeMemoryResult(%q) = nil, want an error", bad)
		}
	}
	if err := writeMemoryResult("Building configuration...\n[OK]", errors.New("% Invalid input")); err == nil {
		t.Error("a failed response with [OK] passed")
	}
}

// NTG-194: IOL 15 only offers SHA-1 kex and ssh-rsa host keys, and scrapligo runs ssh with
// -F /dev/null, so the options must come from here rather than the host ssh_config.
func TestLegacySSHArgs(t *testing.T) {
	got := strings.Join(legacySSHArgs, " ")
	want := "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 -o HostKeyAlgorithms=+ssh-rsa"
	if got != want {
		t.Errorf("legacySSHArgs = %q, want %q", got, want)
	}
}

// NTG-207: a node recreated moments after its first create (a link added by the next apply) still
// has the empty NVRAM file clab made, so it is a first boot: no 10 s wait and no mgmt re-push.
func TestAnEmptyNvramIsAFirstBoot(t *testing.T) {
	n := newTestIOL(t, "172.20.15.2")
	if err := os.WriteFile(n.hostNvram, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !n.firstBoot {
		t.Error("an empty NVRAM was taken as a saved config")
	}
}

func TestAWrittenNvramIsNotAFirstBoot(t *testing.T) {
	n := newTestIOL(t, "172.20.15.2")
	if err := os.WriteFile(n.hostNvram, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.firstBoot {
		t.Error("a node with NVRAM content was taken as a first boot")
	}
	if info, _ := os.Stat(n.hostNvram); info.Size() != 1024 {
		t.Errorf("NVRAM was rewritten: %d bytes", info.Size())
	}
}
