package core

import (
	"testing"

	clablinks "github.com/srl-labs/containerlab/links"
)

// NTG-249: apply matched endpoints by node and interface name only. A Cloud (macvlan) put on the
// port a cable (veth) used in the same apply looked live, so it was never deployed, while the
// cable's peer was deleted and took the port with it.
func TestCloudOnThePortOfARemovedCableIsDeployed(t *testing.T) {
	t.Parallel()
	n1 := &applyFakeLinkNode{name: "n1"}
	mv := &clablinks.LinkMacVlan{}
	mv.NodeEndpoint = clablinks.NewEndpointMacVlan(clablinks.NewEndpointGeneric(n1, "eth1", mv))
	key := applyEndpointKey{node: "n1", iface: "eth1"}

	plan := newApplyPlan(nil, nil)
	plan.liveEndpointSet = map[applyEndpointKey]struct{}{key: {}}
	if !plan.linkNeedsDeploy(mv) {
		t.Fatal("a cable's port counted as the Cloud")
	}

	plan.liveMacvlanSet = map[applyEndpointKey]struct{}{key: {}}
	if plan.linkNeedsDeploy(mv) {
		t.Fatal("a live Cloud is redeployed")
	}
}

func TestCableOnThePortOfARemovedCloudIsDeployed(t *testing.T) {
	t.Parallel()
	n1 := &applyFakeLinkNode{name: "n1"}
	n2 := &applyFakeLinkNode{name: "n2"}
	veth := clablinks.NewLinkVEth()
	veth.Endpoints = []clablinks.Endpoint{
		clablinks.NewEndpointVeth(clablinks.NewEndpointGeneric(n1, "eth1", veth)),
		clablinks.NewEndpointVeth(clablinks.NewEndpointGeneric(n2, "eth1", veth)),
	}
	plan := newApplyPlan(nil, nil)
	plan.liveEndpointSet = map[applyEndpointKey]struct{}{
		{node: "n1", iface: "eth1"}: {},
		{node: "n2", iface: "eth1"}: {},
	}
	plan.liveMacvlanSet = map[applyEndpointKey]struct{}{{node: "n1", iface: "eth1"}: {}}
	if !plan.linkNeedsDeploy(veth) {
		t.Fatal("a Cloud's port counted as the cable")
	}
}
