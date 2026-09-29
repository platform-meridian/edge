package main

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	innerAddr = "127.0.0.1:12379"
	innerBin  = "/edge-state"
)

// wrap runs as Talos's etcd, tapping the configured client address in front of
// edge-state. The capture goes under <data-dir>/tap/, which survives the boot.
func wrap(args []string) {
	flags := map[string]string{}
	var inner []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		k, v, joined := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		if !joined && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			i++
			v = args[i]
		}
		flags[k] = v
		if k == "listen-client-urls" {
			a = "--listen-client-urls=https://" + innerAddr
		} else if !joined && v != "" {
			a = "--" + k + "=" + v
		}
		inner = append(inner, a)
	}
	listen := flags["listen-client-urls"]
	if listen == "" {
		log.Fatal("edge-tap wrap: no --listen-client-urls")
	}
	var addrs []string
	for _, u := range strings.Split(listen, ",") {
		_, hostport, _ := strings.Cut(u, "://")
		addrs = append(addrs, strings.TrimSuffix(hostport, "/"))
	}
	dataDir := flags["data-dir"]
	if dataDir == "" {
		dataDir = "/var/lib/etcd"
	}
	secrets := filepath.Dir(flags["cert-file"])
	clientCert, clientKey := "", ""
	for _, n := range []string{"admin", "peer", "server"} {
		if _, err := os.Stat(filepath.Join(secrets, n+".crt")); err == nil {
			clientCert, clientKey = filepath.Join(secrets, n+".crt"), filepath.Join(secrets, n+".key")
			break
		}
	}

	child := exec.Command(innerBin, inner...)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		log.Fatalf("edge-tap wrap: %v", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sig
		child.Process.Signal(s)
	}()
	go func() {
		err := child.Wait()
		log.Printf("edge-tap wrap: edge-state exited: %v", err)
		code := 1
		if child.ProcessState != nil && child.ProcessState.ExitCode() >= 0 {
			code = child.ProcessState.ExitCode()
		}
		if r := active.Load(); r != nil {
			r.flush()
		}
		os.Exit(code)
	}()
	out := filepath.Join(dataDir, "tap", "capture-"+time.Now().UTC().Format("20060102T150405Z")+".jsonl")
	err := run(config{
		listen: strings.Join(addrs, ","), upstream: innerAddr, out: out,
		cert: flags["cert-file"], key: flags["key-file"], ca: flags["trusted-ca-file"],
		clientCert: clientCert, clientKey: clientKey, serverSNI: "localhost",
	})
	log.Printf("edge-tap wrap: tap stopped: %v", err)
	child.Process.Signal(syscall.SIGTERM)
	select {}
}
