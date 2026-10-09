package cisco_iol

// NTG-231: the IOL PID was Index+1, the node's place among all node names sorted. A node added
// with an earlier name shifted it, so a recreated node opened another nvram_<PID> (its saved
// config looked lost) and could share its PID, and so its MACs, with a node that kept running.
// The PID now comes from the pinned mgmt address and the saved config lives in one file, nvram,
// whatever the PID is.

import (
	"context"
	"os"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	clabmocksmockruntime "github.com/srl-labs/containerlab/mocks/mockruntime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"go.uber.org/mock/gomock"
)

func initIOL(t *testing.T, labDir, mgmtIP string, index int, env map[string]string) (*iol, error) {
	t.Helper()
	ctrl := gomock.NewController(t)
	rt := clabmocksmockruntime.NewMockContainerRuntime(ctrl)
	rt.EXPECT().Mgmt().Return(&clabtypes.MgmtNet{IPv4Subnet: "172.20.15.0/24", IPv4Gw: "172.20.15.1"}).AnyTimes()
	n := &iol{}
	err := n.Init(&clabtypes.NodeConfig{ShortName: "router1", LabDir: labDir, MgmtIPv4Address: mgmtIP, Index: index, Env: env})
	n.WithRuntime(rt)
	return n, err
}

func writeFile(t *testing.T, p string, size int, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func readSize(t *testing.T, p string) int64 {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestPidComesFromTheMgmtAddressNotTheSortOrder(t *testing.T) {
	dir := t.TempDir()
	for _, index := range []int{0, 4} {
		n, err := initIOL(t, dir, "172.20.15.2", index, nil)
		if err != nil {
			t.Fatal(err)
		}
		if n.Pid != "515" || n.Cfg.Env["IOL_PID"] != "515" {
			t.Errorf("index %d: Pid %s, IOL_PID %s; want 515", index, n.Pid, n.Cfg.Env["IOL_PID"])
		}
		want := path.Join(dir, "nvram") + ":/iol/nvram_00515"
		found := false
		for _, b := range n.Cfg.Binds {
			found = found || b == want
		}
		if !found {
			t.Errorf("index %d: binds %v lack %q", index, n.Cfg.Binds, want)
		}
	}
}

func TestPidFallsBackToIndexWithoutAUsableMgmtAddress(t *testing.T) {
	for _, ip := range []string{"", "172.20.15.0", "172.20.15.255", "not-an-ip"} {
		n, err := initIOL(t, t.TempDir(), ip, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		if n.Pid != "3" {
			t.Errorf("mgmt %q: Pid %s, want 3", ip, n.Pid)
		}
	}
}

func TestTopologyEnvCannotOverrideThePid(t *testing.T) {
	n, err := initIOL(t, t.TempDir(), "172.20.15.2", 0, map[string]string{"IOL_PID": "7"})
	if err != nil {
		t.Fatal(err)
	}
	if n.Cfg.Env["IOL_PID"] != "515" {
		t.Errorf("IOL_PID %s, want 515", n.Cfg.Env["IOL_PID"])
	}
}

func TestAPidIouyapUsesOrOutOfRangeIsRefused(t *testing.T) {
	for _, index := range []int{512, 1023} {
		if _, err := initIOL(t, t.TempDir(), "", index, nil); err == nil {
			t.Errorf("index %d: no error for PID %d", index, index+1)
		}
	}
}

func TestNetmapUsesThePid(t *testing.T) {
	n, err := initIOL(t, t.TempDir(), "172.20.15.2", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	netmap, err := os.ReadFile(path.Join(n.Cfg.LabDir, "NETMAP"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(netmap), "515:0/0 513:0/0") {
		t.Errorf("NETMAP %q", netmap)
	}
}

// A lab deployed before the fix keeps its config in nvram_<old PID>. The first deploy after the
// fix copies the file the old binary opened, nvram_<Index+1>, into nvram and leaves it in place.
func TestFirstDeployAfterTheFixCopiesTheFileTheOldBinaryOpened(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFile(t, path.Join(dir, "nvram_00002"), 1<<20, now.Add(-time.Hour))
	writeFile(t, path.Join(dir, "nvram_00003"), 2048, now) // newer, but not the old binary's file
	n, err := initIOL(t, dir, "172.20.15.2", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readSize(t, path.Join(dir, "nvram")); got != 1<<20 {
		t.Errorf("nvram has %d bytes, want the 1 MiB nvram_00002", got)
	}
	if readSize(t, path.Join(dir, "nvram_00002")) != 1<<20 {
		t.Error("the original was changed")
	}
	if n.firstBoot {
		t.Error("a copied saved config was taken as a first boot")
	}
}

func TestWithoutTheOldBinarysFileTheNewestWrittenOneIsCopied(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFile(t, path.Join(dir, "nvram_00002"), 1, now) // Index+1, but only clab's placeholder
	writeFile(t, path.Join(dir, "nvram_00001"), 1000, now.Add(-time.Hour))
	writeFile(t, path.Join(dir, "nvram_00004"), 3000, now.Add(-time.Minute))
	n, _ := initIOL(t, dir, "172.20.15.2", 1, nil)
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readSize(t, path.Join(dir, "nvram")); got != 3000 {
		t.Errorf("nvram has %d bytes, want nvram_00004's 3000", got)
	}

	// equal mtimes: the larger name wins, so the choice does not depend on directory order
	dir = t.TempDir()
	writeFile(t, path.Join(dir, "nvram_00001"), 1000, now)
	writeFile(t, path.Join(dir, "nvram_00004"), 3000, now)
	n, _ = initIOL(t, dir, "172.20.15.2", 1, nil)
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readSize(t, path.Join(dir, "nvram")); got != 3000 {
		t.Errorf("tie: nvram has %d bytes, want nvram_00004's 3000", got)
	}
}

func TestOnlyNvramFilesClabNamedAreSources(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for _, name := range []string{"nvram_00001.bak", "nvram_1", "nvram_00000", ".nvram.tmp-x"} {
		writeFile(t, path.Join(dir, name), 1000, now)
	}
	if err := os.Mkdir(path.Join(dir, "nvram_00004"), 0o755); err != nil {
		t.Fatal(err)
	}
	n, _ := initIOL(t, dir, "172.20.15.2", 1, nil)
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readSize(t, path.Join(dir, "nvram")); got > 1 {
		t.Errorf("nvram was copied from a file clab did not name (%d bytes)", got)
	}
	if !n.firstBoot {
		t.Error("no saved config, yet not a first boot")
	}
}

func TestAWrittenNvramIsNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFile(t, path.Join(dir, "nvram"), 5000, now.Add(-time.Hour))
	writeFile(t, path.Join(dir, "nvram_00002"), 1<<20, now)
	n, _ := initIOL(t, dir, "172.20.15.2", 1, nil)
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readSize(t, path.Join(dir, "nvram")); got != 5000 {
		t.Errorf("nvram has %d bytes, want its own 5000", got)
	}
}

// clab's own placeholder is one byte ("\n", utils.CreateFile), not empty, so NTG-207's size == 0
// check never fired. A node recreated before IOL wrote its NVRAM is still a first boot.
func TestClabsPlaceholderIsAFirstBootEveryTime(t *testing.T) {
	dir := t.TempDir()
	for round := 0; round < 2; round++ {
		n, _ := initIOL(t, dir, "172.20.15.2", 0, nil)
		if err := n.CreateIOLFiles(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !n.firstBoot {
			t.Errorf("round %d: placeholder of %d bytes was not a first boot", round, readSize(t, path.Join(dir, "nvram")))
		}
	}
}

func TestTheCopyKeepsTheOriginalsOwnerAndMode(t *testing.T) {
	dir := t.TempDir()
	src := path.Join(dir, "nvram_00002")
	writeFile(t, src, 4096, time.Now())
	if err := os.Chmod(src, 0o644); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	n, _ := initIOL(t, dir, "172.20.15.2", 1, nil)
	if err := n.CreateIOLFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(src)
	b, err := os.Stat(path.Join(dir, "nvram"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode().Perm() != b.Mode().Perm() {
		t.Errorf("mode %v, want %v", b.Mode().Perm(), a.Mode().Perm())
	}
	sa, sb := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	if sa.Uid != sb.Uid || sa.Gid != sb.Gid {
		t.Errorf("owner %d:%d, want %d:%d", sb.Uid, sb.Gid, sa.Uid, sa.Gid)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".nvram.tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestAnUnreadableSourceStopsTheDeploy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	dir := t.TempDir()
	src := path.Join(dir, "nvram_00002")
	writeFile(t, src, 4096, time.Now())
	if err := os.Chmod(src, 0); err != nil {
		t.Fatal(err)
	}
	n, _ := initIOL(t, dir, "172.20.15.2", 1, nil)
	if err := n.CreateIOLFiles(context.Background()); err == nil {
		t.Error("no error; the node would boot without its saved config")
	}
}
