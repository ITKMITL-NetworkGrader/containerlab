package cisco_iol

// NTG-233: IOL keeps VLANs (and the VTP domain, mode and revision) in /iol/vlan.dat-<PID>, not in
// NVRAM. Only nvram was bound from the host, so a recreated switch lost its VLANs while its ports
// still pointed at them.

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path"
	"testing"

	clabmocksmockruntime "github.com/srl-labs/containerlab/mocks/mockruntime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"go.uber.org/mock/gomock"
)

func initL2(t *testing.T, labDir, mgmtIP string, index int, env map[string]string) (*iol, error) {
	t.Helper()
	ctrl := gomock.NewController(t)
	rt := clabmocksmockruntime.NewMockContainerRuntime(ctrl)
	rt.EXPECT().Mgmt().Return(&clabtypes.MgmtNet{IPv4Subnet: "172.20.15.0/24", IPv4Gw: "172.20.15.1"}).AnyTimes()
	n := &iol{}
	err := n.Init(&clabtypes.NodeConfig{
		ShortName: "sw1", NodeType: "l2", LabDir: labDir, MgmtIPv4Address: mgmtIP, Index: index, Env: env,
	})
	n.WithRuntime(rt)
	return n, err
}

func TestEveryIOLNodeBindsVlanDatAtItsPid(t *testing.T) {
	cases := []struct {
		name   string
		init   func(*testing.T, string, string, int, map[string]string) (*iol, error)
		mgmtIP string
		index  int
		env    map[string]string
		pid    string
		target string
	}{
		{"l3 pinned", initIOL, "172.20.15.2", 4, nil, "515", "/iol/vlan.dat-00515"},
		{"l2 pinned", initL2, "172.20.15.2", 4, nil, "515", "/iol/vlan.dat-00515"},
		{"l2 index fallback", initL2, "", 2, nil, "3", "/iol/vlan.dat-00003"},
		{"l2 env override", initL2, "172.20.15.2", 0, map[string]string{"IOL_PID": "9"}, "515", "/iol/vlan.dat-00515"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			n, err := c.init(t, dir, c.mgmtIP, c.index, c.env)
			if err != nil {
				t.Fatal(err)
			}
			if n.Cfg.Env["IOL_PID"] != c.pid {
				t.Fatalf("IOL_PID %s, want %s", n.Cfg.Env["IOL_PID"], c.pid)
			}
			want := path.Join(dir, "vlan.dat") + ":" + c.target
			found := false
			for _, b := range n.Cfg.Binds {
				found = found || b == want
			}
			if !found {
				t.Errorf("binds %v lack %q", n.Cfg.Binds, want)
			}
		})
	}
}

func TestCreateIOLFilesMakesTheVlanDatPlaceholderOnce(t *testing.T) {
	dir := t.TempDir()
	n, err := initL2(t, dir, "172.20.15.2", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Empty, not clab's one-byte "\n": IOS logs %SW_VLAN-4-IFS_FAILURE at boot on a one-byte file.
	info, err := os.Stat(path.Join(dir, "vlan.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("want an empty regular vlan.dat placeholder, got mode %v, %d bytes", info.Mode(), info.Size())
	}

	saved := make([]byte, 676)
	rand.New(rand.NewSource(233)).Read(saved)
	if err := os.WriteFile(path.Join(dir, "vlan.dat"), saved, 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err = initL2(t, dir, "172.20.15.2", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path.Join(dir, "vlan.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, saved) {
		t.Errorf("saved vlan.dat changed: %d bytes, want the same 676", len(got))
	}
}
