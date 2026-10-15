package cisco_iol

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scrapli/scrapligo/logging"
	"github.com/scrapli/scrapligo/transport"
)

// zombieChildren lists this test process's children that have exited but were never waited for.
func zombieChildren(t *testing.T) []int {
	t.Helper()
	files, _ := filepath.Glob("/proc/self/task/*/children")
	var zombies []int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, s := range strings.Fields(string(b)) {
			pid, _ := strconv.Atoi(s)
			stat, err := os.ReadFile("/proc/" + s + "/stat")
			if err != nil {
				continue
			}
			// The state follows the ")" that closes the command name.
			if i := strings.LastIndexByte(string(stat), ')'); i >= 0 && strings.HasPrefix(string(stat[i+1:]), " Z") {
				zombies = append(zombies, pid)
			}
		}
	}
	return zombies
}

// NTG-255: scrapligo's system transport Close kills ssh but never waits for it, so every save
// over SSH left one zombie under clab-api-server.
func TestReapSystemTransportLeavesNoZombie(t *testing.T) {
	if _, err := os.Stat("/proc/self/task"); err != nil {
		t.Skip("needs /proc")
	}
	l, err := logging.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	tr, err := transport.NewTransport(l, "localhost", transport.SystemTransport)
	if err != nil {
		t.Fatal(err)
	}
	sys := tr.Impl.(*transport.System)
	sys.OpenBin, sys.OpenArgs = "sleep", []string{"60"}
	if err := tr.Open(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(false); err != nil {
		t.Fatal(err)
	}
	// Close sent SIGKILL without waiting; give the child a moment to die.
	for i := 0; i < 100 && len(zombieChildren(t)) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(zombieChildren(t)) == 0 {
		t.Fatal("setup: scrapligo's Close left no zombie; the bug this test covers is gone")
	}

	reapSSH(tr)

	if z := zombieChildren(t); len(z) != 0 {
		t.Fatalf("zombie children left after reapSSH: %v", z)
	}
	reapSSH(tr) // a second call (or one after an Open that never spawned) must not block or panic
}
