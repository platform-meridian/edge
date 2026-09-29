// Package conformance runs the release gates against edge-state: k8s.io/apiserver's
// etcd3 storage tests, etcd's robustness traffic across SIGKILLs, and the captured
// client traffic in ../replay/corpora, each beside a pinned etcd.
//
//	go test -timeout 0 -run TestAPIServer .
//	go test -timeout 0 -run TestRobustness/edge-state .
//	go test -timeout 0 -run TestReplay .
//
// Downloads and builds persist in the user cache directory, so after one run the
// gates also run offline with GOPROXY=off.
package conformance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	etcdVersion = "v3.7.2"
	etcdSHA256  = "3a3679bc51a4ee9d30bccea1da7cd4fe62c6fc1d2ca1255068d2c53bf3026135"
)

var edgeStateFlag = flag.String("edge-state", "", "edge-state binary (default: a release build of this checkout)")

func cacheDir(t *testing.T, name string) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(base, "meridian-edge-conformance", name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Stderr = dir, os.Stderr
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}

var (
	edgeStateMu   sync.Mutex
	edgeStatePath string
)

func edgeState(t *testing.T) string {
	t.Helper()
	edgeStateMu.Lock()
	defer edgeStateMu.Unlock()
	if edgeStatePath != "" {
		return edgeStatePath
	}
	if *edgeStateFlag != "" {
		p, err := filepath.Abs(*edgeStateFlag)
		if err != nil {
			t.Fatal(err)
		}
		edgeStatePath = p
		return p
	}
	run(t, "..", nil, "cargo", "build", "--release", "--locked", "-p", "edge-state")
	var meta struct {
		TargetDirectory string `json:"target_directory"`
	}
	if err := json.Unmarshal([]byte(run(t, "..", nil, "cargo", "metadata", "--format-version=1", "--no-deps")), &meta); err != nil {
		t.Fatal(err)
	}
	edgeStatePath = filepath.Join(meta.TargetDirectory, "release", "edge-state")
	return edgeStatePath
}

func etcd(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(cacheDir(t, "etcd-"+etcdVersion), "etcd")
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	name := fmt.Sprintf("etcd-%s-linux-amd64", etcdVersion)
	resp, err := http.Get(fmt.Sprintf("https://github.com/etcd-io/etcd/releases/download/%s/%s.tar.gz", etcdVersion, name))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != etcdSHA256 {
		t.Fatalf("%s.tar.gz: sha256 %x, want %s", name, sum, etcdSHA256)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("no %s/etcd in the tarball: %v", name, err)
		}
		if h.Name == name+"/etcd" {
			f, err := os.CreateTemp(filepath.Dir(bin), "etcd.")
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(f, tr)
			if err = errors.Join(err, f.Chmod(0o755), f.Close()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(f.Name(), bin); err != nil {
				t.Fatal(err)
			}
			return bin
		}
	}
}

func module(t *testing.T, dir, mod, dst string) {
	t.Helper()
	var dl struct{ Dir, Error string }
	if err := json.Unmarshal([]byte(run(t, dir, nil, "go", "mod", "download", "-json", mod)), &dl); err != nil || dl.Error != "" {
		t.Fatalf("go mod download %s: %v %s", mod, err, dl.Error)
	}
	if err := os.RemoveAll(dst); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(dst, os.DirFS(dl.Dir)); err != nil {
		t.Fatal(err)
	}
}

// storeDir is on tmpfs: the stock suites run etcd without fsync and edge-state has
// no such switch. Kept when the test fails.
func storeDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = "/dev/shm"
	}
	d, err := os.MkdirTemp(base, "meridian-conformance.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("kept %s", d)
			return
		}
		os.RemoveAll(d)
	})
	return d
}

var scope = []string{"--user", "--scope", "-q", "-p", "MemoryMax=8G", "-p", "MemorySwapMax=0", "--"}

var haveScope = sync.OnceValue(func() bool {
	return exec.Command("systemd-run", append(scope, "true")...).Run() == nil
})

// capped runs a heavy step under an 8 GB cap where there is a systemd user
// manager: porcupine's search can outgrow the machine.
func capped(name string, args ...string) *exec.Cmd {
	if haveScope() {
		return exec.Command("systemd-run", append(append(scope, name), args...)...)
	}
	return exec.Command(name, args...)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startStore(t *testing.T, bin, dir, pki string, extra ...string) string {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	peer := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	args := append([]string{
		"--name=default",
		"--data-dir=" + filepath.Join(dir, "data"),
		"--listen-client-urls=https://" + addr,
		"--advertise-client-urls=https://" + addr,
		"--listen-peer-urls=" + peer,
		"--initial-advertise-peer-urls=" + peer,
		"--initial-cluster=default=" + peer,
		"--cert-file=" + filepath.Join(pki, "server.crt"),
		"--key-file=" + filepath.Join(pki, "server.key"),
		"--trusted-ca-file=" + filepath.Join(pki, "ca.crt"),
		"--client-cert-auth=true",
	}, extra...)
	log, err := os.Create(filepath.Join(dir, "store.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		log.Close()
	})
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not listen on %s: see %s", bin, addr, log.Name())
		}
	}
}
