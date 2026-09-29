package conformance

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const etcdTestsModule = "go.etcd.io/etcd/tests/v3@v3.7.2"

var (
	robustnessRuns  = flag.Int("runs", 100, "robustness runs per store, each on a fresh data directory and validated alone")
	robustnessKills = flag.Int("kills", 1, "SIGKILL and restart per robustness run")
)

// The harness's own tests run first: they pin the filter that keeps each check's
// history small. etcd is the control: the harness and patched model must pass it.
func TestRobustness(t *testing.T) {
	work := cacheDir(t, "robustness")
	harness, err := filepath.Abs("robustness")
	if err != nil {
		t.Fatal(err)
	}
	tests := filepath.Join(work, "etcd-tests")
	module(t, harness, etcdTestsModule, tests)
	run(t, tests, nil, "git", "apply", "-p1", filepath.Join(harness, "tests-v3.patch"))
	gowork := filepath.Join(work, "go.work")
	path, version, _ := strings.Cut(etcdTestsModule, "@")
	if err := os.WriteFile(gowork, fmt.Appendf(nil, "go 1.26\n\nuse %s\n\nreplace %s %s => %s\n", harness, path, version, tests), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"GOWORK=" + gowork}
	bin := filepath.Join(work, "robustness")
	t.Log(strings.TrimSpace(run(t, harness, env, "go", "test", "-count=1", ".")))
	run(t, harness, env, "go", "build", "-o", bin, ".")

	for _, arm := range []struct {
		name string
		bin  func(*testing.T) string
	}{{"edge-state", edgeState}, {"etcd", etcd}} {
		t.Run(arm.name, func(t *testing.T) {
			dir := storeDir(t)
			pki := makePKI(t, filepath.Join(dir, "pki"))
			cmd := capped(bin, "-bin", arm.bin(t), "-store", arm.name, "-pki", pki, "-work", dir,
				"-runs", strconv.Itoa(*robustnessRuns), "-kills", strconv.Itoa(*robustnessKills))
			validator, err := os.Create(filepath.Join(dir, "validator.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer validator.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = validator
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for s := bufio.NewScanner(stdout); s.Scan(); {
				t.Log(s.Text())
			}
			if err := cmd.Wait(); err != nil {
				t.Errorf("%v: failed runs, their history.html and %s are kept", err, validator.Name())
			}
		})
	}
}
