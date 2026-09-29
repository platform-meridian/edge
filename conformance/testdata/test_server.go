// Drop-in for k8s.io/apiserver/pkg/storage/etcd3/testserver (kine's recipe): the
// same API, but each RunEtcd spawns $STORE_BIN (edge-state or a real etcd) with the
// etcd command line, so the storage tests run against an external store.
package testserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/kubernetes"
	"go.etcd.io/etcd/server/v3/embed"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
)

func freePorts(n int) ([]int, error) {
	var ports []int
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer l.Close()
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// NewTestConfig keeps the stock signature; only WatchProgressNotifyInterval is honoured.
func NewTestConfig(t testing.TB) *embed.Config {
	return embed.NewConfig()
}

var portLock sync.Mutex

func RunEtcd(t testing.TB, cfg *embed.Config) *kubernetes.Client {
	t.Helper()
	bin := os.Getenv("STORE_BIN")
	if bin == "" {
		t.Fatal("STORE_BIN is not set")
	}
	if cfg == nil {
		cfg = NewTestConfig(t)
	}
	dir := t.TempDir()

	portLock.Lock()
	ports, err := freePorts(2)
	if err != nil {
		portLock.Unlock()
		t.Fatal(err)
	}
	client := fmt.Sprintf("http://127.0.0.1:%d", ports[0])
	peer := fmt.Sprintf("http://127.0.0.1:%d", ports[1])
	args := []string{
		"--name=default",
		"--data-dir=" + filepath.Join(dir, "data"),
		"--listen-client-urls=" + client,
		"--advertise-client-urls=" + client,
		"--listen-peer-urls=" + peer,
		"--initial-advertise-peer-urls=" + peer,
		"--initial-cluster=default=" + peer,
		"--unsafe-no-fsync",
		"--log-level=error",
	}
	if d := cfg.WatchProgressNotifyInterval; d > 0 {
		args = append(args, "--watch-progress-notify-interval="+d.String())
	}
	cmd := exec.Command(bin, args...)
	if logDir := os.Getenv("STORE_LOG_DIR"); logDir != "" {
		name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
		if f, err := os.Create(filepath.Join(logDir, name+".log")); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
			t.Cleanup(func() { f.Close() })
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		portLock.Unlock()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	c, err := kubernetes.New(clientv3.Config{
		Endpoints:   []string{client},
		DialTimeout: 10 * time.Second,
		Logger:      zaptest.NewLogger(t, zaptest.Level(zapcore.ErrorLevel)).Named("etcd-client"),
	})
	if err != nil {
		portLock.Unlock()
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = c.KV.Get(ctx, "/readiness-probe")
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			portLock.Unlock()
			t.Fatalf("store at %s not ready: %v", client, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	portLock.Unlock()
	t.Cleanup(func() { c.Close() })

	recorder := storagetesting.NewKubernetesRecorder(c.Kubernetes)
	c.KV = storagetesting.NewKVRecorder(c.KV, recorder)
	c.Kubernetes = recorder
	return c
}
