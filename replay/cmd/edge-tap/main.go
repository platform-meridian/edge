// edge-tap: a byte-exact gRPC tap between etcd clients and a store.
//
//	edge-tap -listen 127.0.0.1:2379 -upstream 127.0.0.1:12379 -out capture.jsonl \
//	  -cert server.crt -key server.key -ca ca.crt \
//	  -client-cert admin.crt -client-key admin.key
//
// Every method is forwarded as an opaque bidirectional stream. Without -cert it
// serves plaintext; without -client-cert it dials plaintext. Invoked as `etcd`
// (Talos's /usr/local/bin/etcd), it wraps edge-state.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type frame []byte

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	return *(v.(*frame)), nil
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	*(v.(*frame)) = append([]byte(nil), data...)
	return nil
}

// record is one line of a capture. Dir is c2s, s2c, or end (the stream's status).
type record struct {
	Seq    uint64 `json:"seq"`
	T      int64  `json:"t"`
	Conn   string `json:"conn"`
	Stream uint64 `json:"stream"`
	Method string `json:"method"`
	Dir    string `json:"dir"`
	B64    []byte `json:"b64,omitempty"`
	Code   uint32 `json:"code,omitempty"`
	Msg    string `json:"msg,omitempty"`
}

type recorder struct {
	mu  sync.Mutex
	w   *bufio.Writer
	f   *os.File
	seq uint64
}

// write assigns seq under the lock, so the file's line order is the seq order.
func (r *recorder) write(rec record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	rec.Seq, rec.T = r.seq, time.Now().UnixNano()
	b, _ := json.Marshal(rec)
	r.w.Write(append(b, '\n'))
}

func (r *recorder) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.w.Flush()
	r.f.Sync()
}

// flushEvery bounds what a power cut can lose to one period.
func (r *recorder) flushEvery(d time.Duration) {
	for range time.Tick(d) {
		r.mu.Lock()
		r.w.Flush()
		r.mu.Unlock()
	}
}

// active is the running recorder, flushed when the wrapped store exits.
var active atomic.Pointer[recorder]

type tap struct {
	rec      *recorder
	upstream *grpc.ClientConn
	streams  atomic.Uint64
}

func (t *tap) handle(_ any, ss grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(ss)
	ctx := ss.Context()
	conn := ""
	if p, ok := peer.FromContext(ctx); ok {
		conn = p.Addr.String()
	}
	id := t.streams.Add(1)
	log := func(dir string, b []byte) {
		t.rec.write(record{Conn: conn, Stream: id, Method: method, Dir: dir, B64: b})
	}
	md, _ := metadata.FromIncomingContext(ctx)
	out := metadata.MD{}
	for k, v := range md {
		if !strings.HasPrefix(k, ":") {
			out[k] = v
		}
	}
	ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(ctx, out))
	defer cancel()
	cs, err := t.upstream.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, method)
	if err != nil {
		return t.end(conn, id, method, err)
	}
	go func() {
		for {
			var f frame
			if err := ss.RecvMsg(&f); err != nil {
				if errors.Is(err, io.EOF) {
					cs.CloseSend()
				} else {
					cancel()
				}
				return
			}
			log("c2s", f)
			if cs.SendMsg(&f) != nil {
				return
			}
		}
	}()
	if h, err := cs.Header(); err == nil {
		ss.SendHeader(h)
	}
	for {
		var f frame
		err := cs.RecvMsg(&f)
		if err != nil {
			ss.SetTrailer(cs.Trailer())
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return t.end(conn, id, method, err)
		}
		log("s2c", f)
		if err := ss.SendMsg(&f); err != nil {
			return t.end(conn, id, method, err)
		}
	}
}

func (t *tap) end(conn string, id uint64, method string, err error) error {
	s := status.Convert(err)
	t.rec.write(record{Conn: conn, Stream: id, Method: method, Dir: "end", Code: uint32(s.Code()), Msg: s.Message()})
	return err
}

func loadPool(ca string) *x509.CertPool {
	pem, err := os.ReadFile(ca)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatalf("ca: no certificates in %s", ca)
	}
	return pool
}

type config struct {
	listen, upstream, out            string
	cert, key, ca                    string
	clientCert, clientKey, serverSNI string
}

func run(c config) error {
	var srvCreds, cliCreds credentials.TransportCredentials
	if c.cert != "" {
		kp, err := tls.LoadX509KeyPair(c.cert, c.key)
		if err != nil {
			return fmt.Errorf("server certificate: %w", err)
		}
		srvCreds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{kp},
			ClientCAs:    loadPool(c.ca),
			ClientAuth:   tls.RequireAndVerifyClientCert,
		})
	} else {
		srvCreds = insecure.NewCredentials()
	}
	if c.clientCert != "" {
		kp, err := tls.LoadX509KeyPair(c.clientCert, c.clientKey)
		if err != nil {
			return fmt.Errorf("client certificate: %w", err)
		}
		cliCreds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{kp},
			RootCAs:      loadPool(c.ca),
			ServerName:   c.serverSNI,
		})
	} else {
		cliCreds = insecure.NewCredentials()
	}
	up, err := grpc.NewClient(c.upstream, grpc.WithTransportCredentials(cliCreds),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{}), grpc.MaxCallRecvMsgSize(1<<30), grpc.MaxCallSendMsgSize(1<<30)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.out), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(c.out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	rec := &recorder{w: bufio.NewWriterSize(f, 1<<20), f: f}
	active.Store(rec)
	go rec.flushEvery(200 * time.Millisecond)
	t := &tap{rec: rec, upstream: up}
	srv := grpc.NewServer(grpc.Creds(srvCreds), grpc.UnknownServiceHandler(t.handle),
		grpc.ForceServerCodec(rawCodec{}), grpc.MaxRecvMsgSize(1<<30), grpc.MaxSendMsgSize(1<<30))
	errs := make(chan error)
	for _, addr := range strings.Split(c.listen, ",") {
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errs <- srv.Serve(lis) }()
	}
	log.Printf("edge-tap: %s -> %s, capturing to %s", c.listen, c.upstream, c.out)
	return <-errs
}

func main() {
	if filepath.Base(os.Args[0]) == "etcd" {
		wrap(os.Args[1:])
		return
	}
	var c config
	flag.StringVar(&c.listen, "listen", "127.0.0.1:2379", "addresses clients dial, comma-separated")
	flag.StringVar(&c.upstream, "upstream", "127.0.0.1:12379", "the store's address")
	flag.StringVar(&c.out, "out", "capture.jsonl", "capture file (appended)")
	flag.StringVar(&c.cert, "cert", "", "server certificate presented to clients")
	flag.StringVar(&c.key, "key", "", "its key")
	flag.StringVar(&c.ca, "ca", "", "CA that signs client certificates and the store's certificate")
	flag.StringVar(&c.clientCert, "client-cert", "", "client certificate presented to the store")
	flag.StringVar(&c.clientKey, "client-key", "", "its key")
	flag.StringVar(&c.serverSNI, "upstream-name", "localhost", "name checked against the store's certificate")
	flag.Parse()
	if err := run(c); err != nil {
		log.Fatal(err)
	}
}
