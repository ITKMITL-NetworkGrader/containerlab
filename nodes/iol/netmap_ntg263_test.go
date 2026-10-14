package cisco_iol

import (
	"context"
	"os"
	"path"
	"testing"

	clablinks "github.com/srl-labs/containerlab/links"
)

func netmap(t *testing.T, n *iol) string {
	t.Helper()
	b, err := os.ReadFile(path.Join(n.Cfg.LabDir, "NETMAP"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// NTG-263: apply parks a running node's links, which releases them from the node, then the
// recreated IOL writes NETMAP before the links come back. IOL and iouyap read NETMAP only at
// boot, so a NETMAP without the parked links leaves every port dead.
func TestRecreatedIOLKeepsParkedLinksInNETMAP(t *testing.T) {
	n := newTestIOL(t, "172.20.15.11")
	n.Cfg.Env = map[string]string{envConsole: "1"}
	n.Pid = "524"
	parked := clablinks.NewRuntimeEndpoint(n, "eth1")
	added := clablinks.NewRuntimeEndpoint(n, "eth2") // a cable added by the same apply
	n.Endpoints = []clablinks.Endpoint{parked}

	n.rememberParkedEndpoints()
	n.Endpoints = []clablinks.Endpoint{added} // parking released eth1; resolve added eth2

	if err := n.GenInterfaceConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "524:0/1 513:0/1\n524:0/2 513:0/2\n"
	if got := netmap(t, n); got != want {
		t.Fatalf("NETMAP %q, want %q", got, want)
	}
}

func TestIOLNETMAPListsAnInterfaceOnce(t *testing.T) {
	n := newTestIOL(t, "172.20.15.11")
	n.Cfg.Env = map[string]string{envConsole: "1"}
	n.Pid = "524"
	n.Endpoints = []clablinks.Endpoint{clablinks.NewRuntimeEndpoint(n, "eth1")}
	n.rememberParkedEndpoints()
	// restore adopted the same interface back before a second config run
	n.Endpoints = []clablinks.Endpoint{clablinks.NewRuntimeEndpoint(n, "eth1")}

	if err := n.GenInterfaceConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := netmap(t, n); got != "524:0/1 513:0/1\n" {
		t.Fatalf("NETMAP %q", got)
	}
}
