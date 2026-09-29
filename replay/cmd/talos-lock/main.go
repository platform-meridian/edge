// talos-lock makes the store traffic machined makes around a manifest apply,
// with the real etcd client. -contenders above 1 exercises the mutex Txn's else
// branch (someone else holds it).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// Talos's constants.EtcdTalosManifestApplyMutex.
const mutexKey = "talos:v1:manifestApplyMutex"

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:2379", "")
	ca := flag.String("ca", "", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	rounds := flag.Int("rounds", 3, "")
	contenders := flag.Int("contenders", 2, "")
	flag.Parse()

	cfg := clientv3.Config{Endpoints: []string{*endpoint}, DialTimeout: 10 * time.Second}
	if *cert != "" {
		kp, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		cfg.TLS = &tls.Config{Certificates: []tls.Certificate{kp}, RootCAs: pool}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for r := 0; r < *rounds; r++ {
		var wg sync.WaitGroup
		for c := 0; c < *contenders; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := applyUnderLock(ctx, cfg, fmt.Sprintf("r%d-c%d", r, c)); err != nil {
					log.Fatalf("round %d contender %d: %v", r, c, err)
				}
			}()
		}
		wg.Wait()
	}
	log.Printf("talos-lock: %d rounds x %d contenders done", *rounds, *contenders)
}

func applyUnderLock(ctx context.Context, cfg clientv3.Config, who string) error {
	cli, err := clientv3.New(cfg)
	if err != nil {
		return err
	}
	defer cli.Close()
	if _, err := cli.MemberList(ctx); err != nil {
		return fmt.Errorf("member list: %w", err)
	}
	if _, err := cli.Status(ctx, cfg.Endpoints[0]); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if _, err := cli.AlarmList(ctx); err != nil {
		return fmt.Errorf("alarm list: %w", err)
	}
	sess, err := concurrency.NewSession(cli)
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	defer sess.Close()
	mu := concurrency.NewMutex(sess, mutexKey)
	if err := mu.Lock(ctx); err != nil {
		return fmt.Errorf("error acquiring mutex: %w", err)
	}
	if _, err := cli.Put(ctx, "/talos-lock/applied/"+who, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := cli.Get(ctx, "/talos-lock/applied/", clientv3.WithPrefix()); err != nil {
		return err
	}
	return mu.Unlock(ctx)
}
