// Command robustness runs etcd's robustness traffic and validators (patched by
// tests-v3.patch) against one external store, SIGKILLing and restarting it on
// the same data directory while traffic runs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/tests/v3/robustness/client"
	"go.etcd.io/etcd/tests/v3/robustness/identity"
	"go.etcd.io/etcd/tests/v3/robustness/model"
	"go.etcd.io/etcd/tests/v3/robustness/report"
	"go.etcd.io/etcd/tests/v3/robustness/traffic"
	"go.etcd.io/etcd/tests/v3/robustness/validate"
)

type store struct {
	bin, kind, dir string
	clientPort     int
	peerPort       int
	pki            *pki
	cmd            *exec.Cmd
	log            *os.File
}

func (s *store) endpoint() string { return fmt.Sprintf("127.0.0.1:%d", s.clientPort) }

func (s *store) args() []string {
	scheme := "http"
	if s.pki != nil {
		scheme = "https"
	}
	c := fmt.Sprintf("%s://%s", scheme, s.endpoint())
	p := fmt.Sprintf("http://127.0.0.1:%d", s.peerPort)
	a := []string{
		"--name=default",
		"--data-dir=" + filepath.Join(s.dir, "data"),
		"--listen-client-urls=" + c,
		"--advertise-client-urls=" + c,
		"--listen-peer-urls=" + p,
		"--initial-advertise-peer-urls=" + p,
		"--initial-cluster=default=" + p,
	}
	if s.pki != nil {
		a = append(a,
			"--cert-file="+s.pki.serverCert, "--key-file="+s.pki.serverKey,
			"--trusted-ca-file="+s.pki.ca, "--client-cert-auth=true")
	}
	return a
}

func (s *store) start(ctx context.Context) error {
	s.cmd = exec.Command(s.bin, s.args()...)
	s.cmd.Stdout, s.cmd.Stderr = s.log, s.log
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := s.cmd.Start(); err != nil {
		return err
	}
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{s.endpoint()}, TLS: client.TLS, DialTimeout: time.Second, Logger: zap.NewNop()})
	if err != nil {
		return err
	}
	defer c.Close()
	deadline := time.Now().Add(30 * time.Second)
	for {
		rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, err := c.Get(rctx, "readiness-probe")
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not ready: %w", s.kind, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *store) kill() {
	_ = s.cmd.Process.Signal(syscall.SIGKILL)
	_ = s.cmd.Wait()
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type outcome struct {
	ops, checked, watchEvents, persisted, kills int
	check                                       time.Duration
	err                                         error
}

// mutexLoop drives a Talos-shaped concurrency.Mutex. Unlock and revoke are not
// unique writes, so like etcd's traffic they share its in-flight limiter and back
// off on failure: each write of unknown outcome widens the search.
func mutexLoop(ctx context.Context, c *client.RecordingClient, limiter *rate.Limiter, nonUnique traffic.ConcurrencyLimiter, finish <-chan struct{}) {
	const pfx = "mutex/"
	backoff := func() { time.Sleep(200 * time.Millisecond) }
	nonUniqueWrite := func(write func(context.Context) error) error {
		if !nonUnique.Take() {
			return errors.New("too many non-unique writes in flight")
		}
		defer nonUnique.Return()
		wctx, cancel := context.WithTimeout(ctx, traffic.RequestTimeout)
		defer cancel()
		return write(wctx)
	}
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-finish:
			return
		default:
		}
		if limiter.Wait(ctx) != nil {
			return
		}
		gctx, cancel := context.WithTimeout(ctx, traffic.RequestTimeout)
		lease, err := c.LeaseGrant(gctx, 60)
		cancel()
		if err != nil {
			backoff()
			continue
		}
		myKey := fmt.Sprintf("%s%x", pfx, int64(lease.ID))
		for cycle := 0; cycle < 3; cycle++ {
			if limiter.Wait(ctx) != nil {
				return
			}
			actx, cancel := context.WithTimeout(ctx, traffic.RequestTimeout)
			resp, err := c.MutexAcquire(actx, pfx, myKey, fmt.Sprintf("c%d-%d-%d", c.ID, n, cycle), int64(lease.ID))
			cancel()
			if err != nil {
				backoff()
				break
			}
			myRev := resp.Header.Revision
			if !resp.Succeeded {
				if kvs := resp.Responses[0].GetResponseRange().Kvs; len(kvs) > 0 {
					myRev = kvs[0].CreateRevision
				}
			}
			if owner := resp.Responses[1].GetResponseRange().Kvs; len(owner) == 0 || owner[0].CreateRevision != myRev {
				wctx, cancel := context.WithTimeout(ctx, traffic.RequestTimeout)
				_, _ = c.MutexWaiters(wctx, pfx, myRev-1)
				cancel()
			}
			if err := nonUniqueWrite(func(wctx context.Context) error {
				_, err := c.Delete(wctx, myKey)
				return err
			}); err != nil {
				backoff()
				break
			}
		}
		if err := nonUniqueWrite(func(wctx context.Context) error {
			_, err := c.LeaseRevoke(wctx, int64(lease.ID))
			return err
		}); err != nil {
			backoff()
		}
	}
}

// Porcupine's search grows exponentially with concurrent operations of unknown
// outcome, which every crash leaves: histories stay at etcd's scale, unknowns the
// log rules out are dropped (dropUnpersisted), and each check has a deadline.
const (
	maxOpsPerCheck = 5000
	checkTimeout   = time.Minute
)

func runOnce(lg *zap.Logger, s *store, tf traffic.Traffic, kills int, rng *rand.Rand, outDir string) (o outcome) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.start(ctx); err != nil {
		o.err = err
		return o
	}
	defer s.kill()

	baseTime := time.Now()
	ids := identity.NewIDProvider()
	trafficSet := client.NewSet(ids, baseTime)
	watchSet := client.NewSet(ids, baseTime)
	defer trafficSet.Close()
	defer watchSet.Close()
	endpoints := []string{s.endpoint()}

	if err := traffic.CheckEmptyDatabaseAtStart(ctx, lg, endpoints, trafficSet); err != nil {
		o.err = err
		return o
	}
	profile := traffic.KeyValueMedium
	limiter := rate.NewLimiter(rate.Limit(profile.MaximalQPS), profile.BurstableQPS)
	finish := make(chan struct{})
	keyStore := traffic.NewKeyStore(10, "key")
	storage := traffic.NewKubernetesStorage()
	nonUnique := traffic.NewConcurrencyLimiter(profile.MaxNonUniqueRequestConcurrency)
	var wg sync.WaitGroup
	err := errors.Join(
		traffic.SimulateKeyValueTraffic(ctx, &wg, &profile, endpoints, trafficSet, tf, traffic.RunTrafficLoopParam{
			QPSLimiter:                         limiter,
			IDs:                                ids,
			LeaseIDStorage:                     identity.NewLeaseIDStorage(),
			NonUniqueRequestConcurrencyLimiter: nonUnique,
			KeyStore:                           keyStore,
			Storage:                            storage,
			Finish:                             finish,
		}),
		traffic.SimulateWatchTraffic(ctx, &wg, &traffic.WatchDefault, endpoints, trafficSet, tf, traffic.RunWatchLoopParam{
			Config: traffic.WatchDefault, QPSLimiter: limiter, KeyStore: keyStore, Storage: storage, Finish: finish, Logger: lg,
		}),
		traffic.SimulateCompactionTraffic(ctx, &wg, &traffic.CompactionDefault, endpoints, trafficSet, tf, traffic.RunCompactLoopParam{
			Period: traffic.CompactionDefault.Period, Finish: finish,
		}),
	)
	for range 2 {
		c, cerr := trafficSet.NewClient(endpoints)
		if cerr != nil {
			err = errors.Join(err, cerr)
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			mutexLoop(ctx, c, limiter, nonUnique, finish)
		}()
	}
	if err != nil {
		o.err = err
		return o
	}

	maxRevision := make(chan int64, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- client.CollectClusterWatchEvents(ctx, client.CollectClusterWatchEventsParam{
			Lg: lg, Endpoints: endpoints, MaxRevisionChan: maxRevision, ClientSet: watchSet,
		})
	}()

	for range kills {
		time.Sleep(time.Duration(300+rng.Intn(1200)) * time.Millisecond)
		s.kill()
		o.kills++
		if err := s.start(ctx); err != nil {
			o.err = fmt.Errorf("restart after kill %d: %w", o.kills, err)
			close(finish)
			close(maxRevision)
			wg.Wait()
			return o
		}
	}
	time.Sleep(time.Second)
	close(finish)
	wg.Wait()

	c, err := trafficSet.NewClient(endpoints)
	if err != nil {
		o.err = err
		return o
	}
	pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = c.Put(pctx, "tombstone", "true")
	pcancel()
	c.Close()
	if err != nil {
		o.err = fmt.Errorf("the last operation must succeed: %w", err)
		return o
	}
	reports := trafficSet.Reports()
	maxRevision <- report.OperationsMaxRevision(reports)
	select {
	case err = <-watchDone:
	case <-time.After(time.Minute):
		err = errors.New("watchers did not reach the last revision within a minute")
	}
	if err != nil {
		o.err = fmt.Errorf("collecting watch events: %w", err)
		return o
	}
	reports = slices.Concat(reports, watchSet.Reports())
	s.kill()

	persisted, err := readPersisted(lg, s)
	if err != nil {
		o.err = fmt.Errorf("reading what the store persisted: %w", err)
		return o
	}
	o.persisted = len(persisted)
	for _, r := range reports {
		o.ops += len(r.KeyValue)
		o.watchEvents += r.WatchEventCount()
	}
	checked := dropUnpersisted(reports, persisted)
	for _, r := range checked {
		o.checked += len(r.KeyValue)
	}
	if o.checked > maxOpsPerCheck {
		o.err = fmt.Errorf("%d operations exceed the %d one check may take: shorten the run", o.checked, maxOpsPerCheck)
		return o
	}
	checkStart := time.Now()
	result := validate.ValidateAndReturnVisualize(lg, validate.Config{ExpectRevisionUnique: tf.ExpectUniqueRevision()}, checked, persisted, checkTimeout)
	o.check = time.Since(checkStart)
	if o.err = result.Error(); o.err != nil && outDir != "" {
		_ = result.Linearization.Visualize(lg, filepath.Join(outDir, "history.html"))
		_ = report.PersistClientReports(lg, filepath.Join(outDir, "reports"), reports)
	}
	return o
}

func main() {
	bin := flag.String("bin", "", "store binary: edge-state, or etcd")
	kind := flag.String("store", "edge-state", "edge-state or etcd: selects how persisted requests are read")
	runs := flag.Int("runs", 100, "independent runs, each on a fresh data directory and validated alone")
	kills := flag.Int("kills", 1, "SIGKILL+restart per run, between its traffic phases")
	pkiDir := flag.String("pki", "", "ca.crt, server.{crt,key} and client.{crt,key}: serve and dial with TLS and client certificates")
	work := flag.String("work", "", "directory for data directories, logs and failure reports")
	seed := flag.Int64("seed", time.Now().UnixNano(), "random seed for kill timing")
	flag.Parse()
	if *bin == "" || *work == "" {
		fmt.Fprintln(os.Stderr, "usage: robustness -bin <store> -store edge-state|etcd -work <dir> [-pki <dir>]")
		os.Exit(2)
	}
	lg, _ := zap.NewProduction(zap.IncreaseLevel(zap.WarnLevel))
	rng := rand.New(rand.NewSource(*seed))
	fmt.Printf("seed %d, %s, %d runs x %d kills, tls=%v\n", *seed, *kind, *runs, *kills, *pkiDir != "")

	var p *pki
	if *pkiDir != "" {
		p = loadPKI(*pkiDir)
		cfg, err := p.clientTLS()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		client.TLS = cfg
	}

	traffics := []struct {
		name string
		t    traffic.Traffic
	}{{"etcd", traffic.EtcdPutDeleteLease}, {"kubernetes", traffic.Kubernetes}}
	failed, crashPoints, ops, checked := 0, 0, 0, 0
	var slowest time.Duration
	for run := range *runs {
		tf := traffics[run%len(traffics)]
		dir := filepath.Join(*work, fmt.Sprintf("run-%03d", run))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			panic(err)
		}
		logf, err := os.Create(filepath.Join(dir, "store.log"))
		if err != nil {
			panic(err)
		}
		s := &store{bin: *bin, kind: *kind, dir: dir, clientPort: freePort(), peerPort: freePort(), pki: p, log: logf}
		start := time.Now()
		o := runOnce(lg, s, tf.t, *kills, rng, dir)
		logf.Close()
		crashPoints += o.kills
		ops += o.ops
		checked += o.checked
		slowest = max(slowest, o.check)
		status := "PASS"
		if o.err != nil {
			status = "FAIL"
			failed++
		}
		fmt.Printf("%s run %d (%s traffic): %d kills, %d ops (%d checked in %v), %d watch events, %d persisted requests, %v",
			status, run, tf.name, o.kills, o.ops, o.checked, o.check.Round(time.Millisecond), o.watchEvents, o.persisted, time.Since(start).Round(time.Second))
		if o.err != nil {
			fmt.Printf(": %v (kept %s)\n", o.err, dir)
			continue
		}
		fmt.Println()
		_ = os.RemoveAll(dir)
	}
	fmt.Printf("robustness: %d/%d runs passed, %d crash points, %d operations (%d checked), slowest check %v\n",
		*runs-failed, *runs, crashPoints, ops, checked, slowest.Round(time.Millisecond))
	if failed > 0 {
		os.Exit(1)
	}
}

func readPersisted(lg *zap.Logger, s *store) ([]model.EtcdRequest, error) {
	data := filepath.Join(s.dir, "data")
	if s.kind == "etcd" {
		return report.PersistedRequests(lg, []string{data})
	}
	return persistedRequests(filepath.Join(data, "state.log"))
}
