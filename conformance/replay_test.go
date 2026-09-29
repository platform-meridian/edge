package conformance

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var corpora = flag.String("corpora", "../replay/corpora/*.jsonl*", "captures TestReplay replays (a glob)")

// Every difference between edge-state's and etcd's normalised answers must be
// listed in ../replay/known.tsv.
func TestReplay(t *testing.T) {
	captures, err := filepath.Glob(*corpora)
	if err != nil || len(captures) == 0 {
		t.Fatalf("no captures match %s: %v", *corpora, err)
	}
	tool := filepath.Join(cacheDir(t, "replay"), "edge-replay")
	run(t, "../replay", nil, "go", "build", "-o", tool, "./cmd/edge-replay")
	stores := map[string]string{"edge-state": edgeState(t), "etcd": etcd(t)}

	for _, capture := range captures {
		capture, err := filepath.Abs(capture)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(strings.SplitN(filepath.Base(capture), ".", 2)[0], func(t *testing.T) {
			dir := storeDir(t)
			pki := makePKI(t, filepath.Join(dir, "pki"))
			for name, bin := range stores {
				data := filepath.Join(dir, name)
				if err := os.Mkdir(data, 0o700); err != nil {
					t.Fatal(err)
				}
				extra := []string{"--watch-progress-notify-interval=5s"}
				if name == "etcd" {
					extra = append(extra, "--unsafe-no-fsync")
				}
				addr := startStore(t, bin, data, pki, extra...)
				run(t, dir, nil, tool, "run", "-capture", capture, "-target", addr,
					"-ca", filepath.Join(pki, "ca.crt"), "-cert", filepath.Join(pki, "client.crt"), "-key", filepath.Join(pki, "client.key"),
					"-out", filepath.Join(dir, name+".jsonl"))
			}
			known, err := filepath.Abs("../replay/known.tsv")
			if err != nil {
				t.Fatal(err)
			}
			diff := exec.Command(tool, "diff", "-known", known, "edge-state.jsonl", "etcd.jsonl")
			diff.Dir = dir
			out, err := diff.CombinedOutput()
			t.Logf("%s", out)
			if err != nil {
				t.Errorf("edge-state and etcd diverge: %v", err)
			}
		})
	}
}
