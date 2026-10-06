package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	clabmocksmocknodes "github.com/srl-labs/containerlab/mocks/mocknodes"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabtypes "github.com/srl-labs/containerlab/types"
	"go.uber.org/mock/gomock"
)

func saveNode(ctrl *gomock.Controller, name string, err error) clabnodes.Node {
	n := clabmocksmocknodes.NewMockNode(ctrl)
	n.EXPECT().GetShortName().Return(name).AnyTimes()
	n.EXPECT().SaveConfig(gomock.Any()).Return(nil, err)
	return n
}

// NTG-194: a node whose save fails must fail the whole save, so callers stop treating its older
// startup config as current.
func TestSaveReturnsEveryNodeFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	c := &CLab{
		Config: &Config{Mgmt: &clabtypes.MgmtNet{}},
		Nodes: map[string]clabnodes.Node{
			"r1": saveNode(ctrl, "r1", nil),
			"r2": saveNode(ctrl, "r2", errors.New("write memory did not report [OK]")),
			"r3": saveNode(ctrl, "r3", errors.New("failed to open driver")),
		},
	}

	err := c.Save(context.Background())
	if err == nil {
		t.Fatal("Save returned nil with two failed nodes")
	}
	for _, want := range []string{`"r2"`, "[OK]", `"r3"`, "open driver"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
	if strings.Contains(err.Error(), `"r1"`) {
		t.Errorf("error %q names r1, which saved", err)
	}
}

func TestSaveSucceedsWhenEveryNodeSaves(t *testing.T) {
	ctrl := gomock.NewController(t)
	c := &CLab{
		Config: &Config{Mgmt: &clabtypes.MgmtNet{}},
		Nodes:  map[string]clabnodes.Node{"r1": saveNode(ctrl, "r1", nil)},
	}
	if err := c.Save(context.Background()); err != nil {
		t.Fatalf("Save: %v", err)
	}
}
