package cisco_iol

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	clabexec "github.com/srl-labs/containerlab/exec"
	clablinks "github.com/srl-labs/containerlab/links"
	clabmocksmockruntime "github.com/srl-labs/containerlab/mocks/mockruntime"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"go.uber.org/mock/gomock"
)

// NTG-333: a node booted with fixed slots maps every port in NETMAP, so a cable added or removed
// later only rewrites iouyap.ini and restarts iouyap; IOS keeps running.

func liveIOL(t *testing.T, labels map[string]string, eps ...string) (*iol, *clabmocksmockruntime.MockContainerRuntime) {
	t.Helper()
	ctrl := gomock.NewController(t)
	rt := clabmocksmockruntime.NewMockContainerRuntime(ctrl)
	rt.EXPECT().Mgmt().Return(&clabtypes.MgmtNet{IPv4Subnet: "172.20.15.0/24", IPv4Gw: "172.20.15.1"}).AnyTimes()
	if labels != nil {
		rt.EXPECT().InspectImage(gomock.Any(), "iol:test").
			Return(&clabruntime.ImageInspect{Config: clabruntime.ImageConfig{Labels: labels}}, nil).AnyTimes()
	}
	n := &iol{}
	n.DefaultNode = *clabnodes.NewDefaultNode(n)
	n.Cfg = &clabtypes.NodeConfig{
		ShortName: "router1", LongName: "clab-lab-router1", LabDir: t.TempDir(),
		MgmtIPv4Address: "172.20.15.11", Image: "iol:test",
	}
	n.Pid = "524"
	n.hostNvram = path.Join(n.Cfg.LabDir, "nvram")
	n.hostVlanDat = path.Join(n.Cfg.LabDir, "vlan.dat")
	n.WithRuntime(rt)
	for _, ep := range eps {
		n.Endpoints = append(n.Endpoints, clablinks.NewRuntimeEndpoint(n, ep))
	}
	return n, rt
}

func labFile(t *testing.T, n *iol, name string) string {
	t.Helper()
	b, err := os.ReadFile(path.Join(n.Cfg.LabDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// execReturns answers Exec calls whose command starts with prefix.
func execReturns(rt *clabmocksmockruntime.MockContainerRuntime, prefix, stdout string, rc int) *gomock.Call {
	return rt.EXPECT().Exec(gomock.Any(), "clab-lab-router1", gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, cmd *clabexec.ExecCmd) (*clabexec.ExecResult, error) {
			if !strings.HasPrefix(cmd.GetCmdString(), prefix) {
				return nil, os.ErrInvalid
			}
			res := clabexec.NewExecResult(cmd)
			res.SetStdOut([]byte(stdout))
			res.SetReturnCode(rc)
			return res, nil
		})
}

func TestFixedSlotsImageMapsEveryPortInNETMAP(t *testing.T) {
	n, _ := liveIOL(t, map[string]string{fixedSlotsLabel: "4"}, "eth1", "eth5")
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.Cfg.Env[envNumSlots] != "4" {
		t.Fatalf("env %s = %q, want 4", envNumSlots, n.Cfg.Env[envNumSlots])
	}
	netmap := labFile(t, n, "NETMAP")
	if lines := strings.Count(netmap, "\n"); lines != 16 {
		t.Fatalf("NETMAP has %d ports, want 16:\n%s", lines, netmap)
	}
	for _, p := range []string{"524:0/0 513:0/0\n", "524:0/1 513:0/1\n", "524:3/3 513:3/3\n"} {
		if strings.Count(netmap, p) != 1 {
			t.Fatalf("NETMAP lists %q %d times:\n%s", p, strings.Count(netmap, p), netmap)
		}
	}
	want := "[default]\nbase_port = 49000\nnetmap = /iol/NETMAP\n[513:0/0]\neth_dev = eth0\n" +
		"[513:0/1]\neth_dev = eth1\n[513:1/1]\neth_dev = eth5\n"
	if got := labFile(t, n, "iouyap.ini"); got != want {
		t.Fatalf("iouyap.ini %q, want only the cabled ports %q", got, want)
	}
}

func TestFixedSlotsKeepsATopologySlotCountAndSkipsConsoleMgmtPort(t *testing.T) {
	n, _ := liveIOL(t, map[string]string{fixedSlotsLabel: "4"}, "eth1")
	n.Cfg.Env = map[string]string{envNumSlots: "2", envConsole: "1"}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	netmap := labFile(t, n, "NETMAP")
	if n.Cfg.Env[envNumSlots] != "2" || strings.Count(netmap, "\n") != 7 || strings.Contains(netmap, ":0/0") {
		t.Fatalf("env %q, NETMAP:\n%s", n.Cfg.Env[envNumSlots], netmap)
	}
}

func TestImageWithoutFixedSlotsMapsOnlyCabledPorts(t *testing.T) {
	n, _ := liveIOL(t, map[string]string{}, "eth1", "eth20")
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, set := n.Cfg.Env[envNumSlots]; set {
		t.Fatalf("%s set without the image label", envNumSlots)
	}
	if got, want := labFile(t, n, "NETMAP"), "524:0/0 513:0/0\n524:0/1 513:0/1\n524:5/0 513:5/0\n"; got != want {
		t.Fatalf("NETMAP %q, want %q", got, want)
	}
}

func TestGenInterfaceConfigDoesNotDuplicateBootInterfaces(t *testing.T) {
	n, _ := liveIOL(t, nil, "eth1")
	for range 2 {
		if err := n.GenInterfaceConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.interfaces) != 1 {
		t.Fatalf("interfaces = %d, want 1", len(n.interfaces))
	}
}

func TestLinkApplyModeIsLiveOnlyForAContainerStartedWithFixedSlots(t *testing.T) {
	ctx := context.Background()

	n, rt := liveIOL(t, map[string]string{}, "eth1", "eth15")
	execReturns(rt, "printenv "+envNumSlots, "4\n", 0)
	if got := n.LinkApplyMode(ctx); got != clabnodes.LinkApplyModeLive {
		t.Fatalf("container env 4: mode %q, want live", got)
	}

	n, rt = liveIOL(t, map[string]string{fixedSlotsLabel: "4"}, "eth1")
	execReturns(rt, "printenv "+envNumSlots, "", 1) // started by an older image or fork
	if got := n.LinkApplyMode(ctx); got != clabnodes.LinkApplyModeRecreate {
		t.Fatalf("no container env: mode %q, want recreate", got)
	}

	n, rt = liveIOL(t, map[string]string{}, "eth1", "eth16") // eth16 is slot 4, past the 4 slots
	execReturns(rt, "printenv "+envNumSlots, "4\n", 0)
	if got := n.LinkApplyMode(ctx); got != clabnodes.LinkApplyModeRecreate {
		t.Fatalf("cable past the slots: mode %q, want recreate", got)
	}
}

func TestPostDeployEndpointsRewritesIouyapIniAndRestartsIouyap(t *testing.T) {
	n, rt := liveIOL(t, nil, "eth1", "eth2")
	if err := n.GenInterfaceConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	netmap := labFile(t, n, "NETMAP")
	n.Endpoints = n.Endpoints[:1] // apply removed the eth2 cable
	gomock.InOrder(
		execReturns(rt, "printenv "+envNumSlots, "4\n", 0),
		execReturns(rt, "sh -c for p in /proc/", "", 0),
	)
	if err := n.PostDeployEndpoints(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ini := labFile(t, n, "iouyap.ini"); strings.Contains(ini, "eth2") || !strings.Contains(ini, "eth1") {
		t.Fatalf("iouyap.ini after removing eth2:\n%s", ini)
	}
	if labFile(t, n, "NETMAP") != netmap {
		t.Fatal("PostDeployEndpoints rewrote NETMAP; IOL reads it only at boot")
	}
}

func TestPostDeployEndpointsSkipsAContainerCreatedInThisRun(t *testing.T) {
	n, _ := liveIOL(t, nil, "eth1") // the mock has no Exec expectation: a call fails the test
	n.created = true
	if err := n.PostDeployEndpoints(context.Background()); err != nil {
		t.Fatal(err)
	}
}
