// edge-replay: replays an edge-tap capture against a store, normalises what it
// answers, and diffs two stores' answers; also measures watch delivery latency
// from a capture.
//
//	edge-replay run -capture c.jsonl.gz -target 127.0.0.1:2379 [-ca -cert -key] -out a.jsonl
//	edge-replay reference -capture c.jsonl.gz -out cap.jsonl   the captured store's own answers
//	edge-replay diff a.jsonl b.jsonl
//	edge-replay latency c.jsonl.gz
//	edge-replay trim c.jsonl out.jsonl.gz                      only what a replay needs
//	edge-replay show c.jsonl <seq|s:stream>...                 decoded records, with their bytes
package main

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: edge-replay run|reference|diff|latency|trim ...")
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(args)
	case "reference":
		err = cmdReference(args)
	case "diff":
		var n int
		n, err = cmdDiff(args)
		if err == nil && n > 0 {
			os.Exit(1)
		}
	case "latency":
		err = cmdLatency(args)
	case "trim":
		err = cmdTrim(args)
	case "show":
		err = cmdShow(args)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func dial(target, ca, cert, key string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if cert != "" {
		kp, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		creds = credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}, RootCAs: pool, ServerName: "localhost"})
	}
	return grpc.NewClient(target, grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true), grpc.MaxCallRecvMsgSize(1<<30), grpc.MaxCallSendMsgSize(1<<30)))
}

func writeResults(path string, rs []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	capture := fs.String("capture", "", "")
	target := fs.String("target", "127.0.0.1:2379", "")
	ca, cert, key := fs.String("ca", "", ""), fs.String("cert", "", ""), fs.String("key", "", "")
	out := fs.String("out", "replay.jsonl", "")
	fs.Parse(args)
	recs, err := readCapture(*capture)
	if err != nil {
		return err
	}
	conn, err := dial(*target, *ca, *cert, *key)
	if err != nil {
		return err
	}
	r := &replayer{conn: conn, capLeases: map[int64]int64{}, streams: map[uint64]*liveStream{}, norm: newNormaliser()}
	if err := r.run(recs); err != nil {
		return err
	}
	log.Printf("replayed %d records: %d results", len(recs), len(r.out))
	return writeResults(*out, r.out)
}

// cmdReference normalises the captured store's own answers, so a replay can be
// checked against what the clients really saw.
func cmdReference(args []string) error {
	fs := flag.NewFlagSet("reference", flag.ExitOnError)
	capture := fs.String("capture", "", "")
	out := fs.String("out", "reference.jsonl", "")
	fs.Parse(args)
	recs, err := readCapture(*capture)
	if err != nil {
		return err
	}
	byStream := map[uint64][]record{}
	var order []uint64
	for _, rec := range recs {
		if _, ok := byStream[rec.Stream]; !ok {
			order = append(order, rec.Stream)
		}
		byStream[rec.Stream] = append(byStream[rec.Stream], rec)
	}
	n := newNormaliser()
	var rs, streams []result
	var streamRecs [][]record
	for _, id := range order {
		recs := byStream[id]
		mi, err := lookup(recs[0].Method)
		if err != nil {
			return err
		}
		var resps []proto.Message
		code, msg, first := "OK", "", uint64(0)
		for _, rec := range recs {
			switch rec.Dir {
			case "c2s":
				if first == 0 {
					first = rec.Seq
				}
			case "s2c":
				m := newMsg(mi.desc.Output())
				if err := proto.Unmarshal(rec.B64, m); err != nil {
					return err
				}
				resps = append(resps, m)
			case "end":
				code, msg = codeName(rec.Code), rec.Msg
			}
		}
		if mi.bidi {
			if code == "Canceled" {
				code, msg = "OK", ""
			}
			streams = append(streams, result{Key: fmt.Sprintf("s:%d", id), Method: recs[0].Method, Code: code, Msg: msg})
			streamRecs = append(streamRecs, recs)
			continue
		}
		res := result{Key: fmt.Sprintf("u:%d", first), Method: recs[0].Method, Code: code, Msg: msg}
		if mi.server {
			var a []any
			for _, m := range resps {
				a = append(a, n.msg(m.ProtoReflect()))
			}
			res.Resp = a
		} else if len(resps) > 0 {
			res.Resp = n.msg(resps[0].ProtoReflect())
		}
		rs = append(rs, res)
	}
	// Unary results in request order, then streams, as run emits them.
	sortByKeySeq(rs)
	for i := range streams {
		mi, _ := lookup(streams[i].Method)
		var resps []proto.Message
		for _, rec := range streamRecs[i] {
			if rec.Dir == "s2c" {
				m := newMsg(mi.desc.Output())
				proto.Unmarshal(rec.B64, m)
				resps = append(resps, m)
			}
		}
		streams[i].Stream = normStream(n, streams[i].Method, resps)
	}
	return writeResults(*out, append(rs, streams...))
}

func sortByKeySeq(rs []result) {
	seq := func(r result) uint64 {
		s, _ := strconv.ParseUint(strings.TrimPrefix(r.Key, "u:"), 10, 64)
		return s
	}
	sort.SliceStable(rs, func(i, j int) bool { return seq(rs[i]) < seq(rs[j]) })
}

func codeName(c uint32) string { return codes.Code(c).String() }

func cmdTrim(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("trim <capture> <out.jsonl.gz>")
	}
	recs, err := readCapture(args[0])
	if err != nil {
		return err
	}
	f, err := os.Create(args[1])
	if err != nil {
		return err
	}
	defer f.Close()
	z, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	enc := json.NewEncoder(z)
	kept := 0
	for _, r := range recs {
		if r.Dir == "s2c" && !strings.HasSuffix(r.Method, "/LeaseGrant") {
			continue
		}
		kept++
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	log.Printf("kept %d of %d records", kept, len(recs))
	return z.Close()
}

func cmdShow(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("show <capture> <seq|s:stream>...")
	}
	recs, err := readCapture(args[0])
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, a := range args[1:] {
		want[a] = true
	}
	for _, r := range recs {
		if !want[fmt.Sprint(r.Seq)] && !want[fmt.Sprintf("s:%d", r.Stream)] {
			continue
		}
		mi, err := lookup(r.Method)
		if err != nil {
			return err
		}
		body := ""
		switch r.Dir {
		case "c2s", "s2c":
			d := mi.desc.Input()
			if r.Dir == "s2c" {
				d = mi.desc.Output()
			}
			m := newMsg(d)
			if err := proto.Unmarshal(r.B64, m); err != nil {
				return err
			}
			body = prototext.MarshalOptions{}.Format(m)
		case "end":
			body = codeName(r.Code) + " " + r.Msg
		}
		fmt.Printf("seq=%d stream=%d %s %s\n  %s\n  hex=%x\n", r.Seq, r.Stream, r.Method, r.Dir, body, r.B64)
	}
	return nil
}
