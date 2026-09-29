package conformance

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const apiserverModule = "k8s.io/apiserver@v0.37.1"

// TestAPIServer follows kine's recipe: testdata/test_server.go replaces the
// package that embeds etcd with a spawned store. Each arm's leaf failures must
// equal its lines in testdata/expected-failures.txt, so a new failure and a newly
// passing one both fail the gate.
func TestAPIServer(t *testing.T) {
	work := cacheDir(t, "apiserver")
	src := filepath.Join(work, "src")
	module(t, ".", apiserverModule, src)
	server, err := os.ReadFile("testdata/test_server.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "pkg/storage/etcd3/testserver/test_server.go"), server, 0o644); err != nil {
		t.Fatal(err)
	}
	packages := []string{"etcd3", "cacher"}
	for _, pkg := range packages {
		run(t, src, nil, "go", "test", "-c", "-o", filepath.Join(work, pkg+".test"), "./pkg/storage/"+pkg)
	}
	expected := expectedFailures(t)

	for _, arm := range []struct {
		name string
		bin  func(*testing.T) string
	}{{"edge-state", edgeState}, {"etcd", etcd}} {
		t.Run(arm.name, func(t *testing.T) {
			bin := arm.bin(t)
			var failed []string
			for _, pkg := range packages {
				failed = append(failed, runSuite(t, work, src, pkg, arm.name, bin)...)
			}
			want := expected[arm.name]
			for _, name := range failed {
				if !slices.Contains(want, name) {
					t.Errorf("new failure: %s", name)
				}
			}
			for _, name := range want {
				if !slices.Contains(failed, name) {
					t.Errorf("expected failure now passes (remove it from expected-failures.txt): %s", name)
				}
			}
		})
	}
}

func runSuite(t *testing.T, work, src, pkg, arm, bin string) []string {
	t.Helper()
	log := filepath.Join(work, arm+"-"+pkg+".log")
	out, err := os.Create(log)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd := capped(filepath.Join(work, pkg+".test"), "-test.v", "-test.timeout=30m")
	cmd.Dir = filepath.Join(src, "pkg/storage", pkg)
	cmd.Env = append(os.Environ(), "STORE_BIN="+bin, "TMPDIR="+storeDir(t))
	cmd.Stdout, cmd.Stderr = out, out
	status := cmd.Run()

	passed, failed := results(t, log)
	t.Logf("%s: %d passed, %d failed (leaf), exit %v; log %s", pkg, passed, len(failed), status, log)
	if status != nil && len(failed) == 0 {
		t.Errorf("%s failed without a failing test (panic or timeout): %v", pkg, status)
	}
	return failed
}

func expectedFailures(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile("testdata/expected-failures.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{}
	for line := range strings.Lines(string(b)) {
		line, _, _ = strings.Cut(line, "#")
		if f := strings.Fields(line); len(f) >= 2 {
			want[f[0]] = append(want[f[0]], f[1])
		}
	}
	return want
}

var resultLine = regexp.MustCompile(`--- (PASS|FAIL): (\S+)`)

// results names only failed leaves: a parent fails whenever a child does.
func results(t *testing.T, log string) (int, []string) {
	t.Helper()
	f, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	passed, fails := 0, []string{}
	s := bufio.NewScanner(f)
	s.Buffer(nil, 16<<20)
	for s.Scan() {
		if m := resultLine.FindStringSubmatch(s.Text()); m != nil {
			if m[1] == "PASS" {
				passed++
			} else if !slices.Contains(fails, m[2]) {
				fails = append(fails, m[2])
			}
		}
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	var leaves []string
	for _, name := range fails {
		if !slices.ContainsFunc(fails, func(o string) bool { return strings.HasPrefix(o, name+"/") }) {
			leaves = append(leaves, name)
		}
	}
	return passed, leaves
}
