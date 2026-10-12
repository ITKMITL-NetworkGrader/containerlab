package cisco_iol

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	clabexec "github.com/srl-labs/containerlab/exec"
	clabmocksmockruntime "github.com/srl-labs/containerlab/mocks/mockruntime"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabtypes "github.com/srl-labs/containerlab/types"
	"go.uber.org/mock/gomock"
)

// NTG-254: a console node's system access is its con0 console, not SSH over the mgmt port.

func consoleIOL(t *testing.T) (*iol, *clabmocksmockruntime.MockContainerRuntime) {
	t.Helper()
	ctrl := gomock.NewController(t)
	rt := clabmocksmockruntime.NewMockContainerRuntime(ctrl)
	rt.EXPECT().Mgmt().Return(&clabtypes.MgmtNet{IPv4Subnet: "172.20.15.0/24", IPv4Gw: "172.20.15.1"}).AnyTimes()
	n := &iol{}
	n.DefaultNode = *clabnodes.NewDefaultNode(n)
	n.Cfg = &clabtypes.NodeConfig{
		ShortName: "router1", LongName: "clab-lab-router1", ContainerID: "cid", LabDir: t.TempDir(),
		MgmtIPv4Address: "172.20.15.2", Env: map[string]string{envConsole: "1"},
	}
	n.WithRuntime(rt)
	return n, rt
}

func TestConsoleNodeSkipsMgmtUpdateOnReboot(t *testing.T) {
	n, _ := consoleIOL(t) // the mock has no WriteToStdinNoWait expectation: a call fails the test
	n.firstBoot = false
	if !n.consoleMode() {
		t.Fatal("env CLAB_IOL_CONSOLE=1 must turn console mode on")
	}
	if err := n.updateMgmtAfterBoot(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleNodeHasNoMgmtPortInNetmap(t *testing.T) {
	n, _ := consoleIOL(t)
	if err := n.GenInterfaceConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"NETMAP", "iouyap.ini"} {
		b, err := os.ReadFile(path.Join(n.Cfg.LabDir, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "0/0") {
			t.Errorf("%s still wires Ethernet0/0:\n%s", f, b)
		}
	}
}

func TestConsoleNodeSavesThroughConsoleCmd(t *testing.T) {
	n, rt := consoleIOL(t)
	res := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice(consoleSaveCmd))
	res.SetStdOut([]byte("Building configuration...\n[OK]\n"))
	rt.EXPECT().Exec(gomock.Any(), "clab-lab-router1", gomock.Any()).Return(res, nil)
	if _, err := n.SaveConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleNodeSaveFailsWithoutOK(t *testing.T) {
	n, rt := consoleIOL(t)
	res := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice(consoleSaveCmd))
	res.SetReturnCode(3)
	res.SetStdErr([]byte("CONSOLE_LOCKED: enable secret set\n"))
	rt.EXPECT().Exec(gomock.Any(), "clab-lab-router1", gomock.Any()).Return(res, nil)
	_, err := n.SaveConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "CONSOLE_LOCKED") {
		t.Fatalf("want CONSOLE_LOCKED error, got %v", err)
	}
}

func TestSSHNodeKeepsMgmtPort(t *testing.T) {
	n := newTestIOL(t, "172.20.15.2")
	if err := n.GenInterfaceConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path.Join(n.Cfg.LabDir, "NETMAP"))
	if !strings.Contains(string(b), "513:0/0") {
		t.Errorf("an SSH node lost its mgmt port:\n%s", b)
	}
}
