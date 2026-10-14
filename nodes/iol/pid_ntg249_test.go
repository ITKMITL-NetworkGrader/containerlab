package cisco_iol

import "testing"

func TestCloudRouterTakesItsPIDFromEnv(t *testing.T) {
	pid, err := iolPid(map[string]string{"NG_IOL_PID": "200"}, "172.20.5.11", 0)
	if err != nil || pid != 200 {
		t.Fatalf("pid %d, err %v", pid, err)
	}
	pid, err = iolPid(nil, "172.20.5.11", 0)
	if err != nil || pid != 524 {
		t.Fatalf("without env: pid %d, err %v", pid, err)
	}
}

func TestCloudRouterPIDOutOfRange(t *testing.T) {
	for _, v := range []string{"0", "255", "513", "-1", "x", ""} {
		if pid, err := iolPid(map[string]string{"NG_IOL_PID": v}, "172.20.5.11", 0); err == nil {
			t.Errorf("NG_IOL_PID %q accepted as %d", v, pid)
		}
	}
}
