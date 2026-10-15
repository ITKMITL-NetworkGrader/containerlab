package cisco_iol

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	clabexec "github.com/srl-labs/containerlab/exec"
	"go.uber.org/mock/gomock"
)

// NTG-260 (h): a console node without a full startup-config must not get the SSH day-0 template
// (admin user, vty over SSH, mgmt address on a port that is not wired).
func TestConsoleNodeBootConfigWithoutStartupConfig(t *testing.T) {
	n, _ := consoleIOL(t)
	partial := path.Join(t.TempDir(), "extra.partial.cfg")
	if err := os.WriteFile(partial, []byte("interface Ethernet0/1\n description uplink\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, startup := range []string{"", partial} {
		n.Cfg.StartupConfig = startup
		n.partialStartupCfg = ""
		if err := n.GenBootConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path.Join(n.Cfg.LabDir, "boot_config.txt"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := string(b)
		for _, bad := range []string{"username admin", "line vty", "crypto key", "vrf forwarding clab-mgmt"} {
			if strings.Contains(cfg, bad) {
				t.Errorf("startup=%q: console boot config contains %q:\n%s", startup, bad, cfg)
			}
		}
		if !strings.Contains(cfg, "hostname router1") || !strings.HasSuffix(strings.TrimSpace(cfg), "end") {
			t.Errorf("startup=%q: want hostname and end:\n%s", startup, cfg)
		}
		if startup != "" && !strings.Contains(cfg, "description uplink") {
			t.Errorf("partial config dropped:\n%s", cfg)
		}
	}
}

// NTG-260 (i): a console save that fails with empty stderr must still say why.
func TestConsoleNodeSaveErrorHasExitCode(t *testing.T) {
	n, rt := consoleIOL(t)
	res := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice(consoleSaveCmd))
	res.SetReturnCode(6)
	rt.EXPECT().Exec(gomock.Any(), "clab-lab-router1", gomock.Any()).Return(res, nil)
	_, err := n.SaveConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit 6") {
		t.Fatalf("want the exit code in the error, got %v", err)
	}
}
