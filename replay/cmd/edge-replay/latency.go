package main

import (
	"fmt"
	"sort"
	"strings"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"google.golang.org/protobuf/proto"
)

func pcts(xs []float64) string {
	if len(xs) == 0 {
		return "n=0"
	}
	sort.Float64s(xs)
	p := func(q float64) float64 { return xs[min(len(xs)-1, int(float64(len(xs))*q))] }
	return fmt.Sprintf("n=%-6d p50=%7.1f p90=%7.1f p99=%7.1f max=%7.1f ms", len(xs), p(.5), p(.9), p(.99), xs[len(xs)-1])
}

func committed(method string, b []byte) int64 {
	switch {
	case strings.HasSuffix(method, ".KV/Put"):
		var r pb.PutResponse
		if proto.Unmarshal(b, &r) == nil {
			return r.GetHeader().GetRevision()
		}
	case strings.HasSuffix(method, ".KV/DeleteRange"):
		var r pb.DeleteRangeResponse
		if proto.Unmarshal(b, &r) == nil && r.Deleted > 0 {
			return r.GetHeader().GetRevision()
		}
	case strings.HasSuffix(method, ".KV/Txn"):
		var r pb.TxnResponse
		if proto.Unmarshal(b, &r) != nil {
			return 0
		}
		for _, op := range r.Responses {
			if op.GetResponsePut() != nil || op.GetResponseDeleteRange().GetDeleted() > 0 {
				return r.GetHeader().GetRevision()
			}
		}
	}
	return 0
}

func isWrite(method string) bool {
	for _, m := range []string{".KV/Put", ".KV/DeleteRange", ".KV/Txn"} {
		if strings.HasSuffix(method, m) {
			return true
		}
	}
	return false
}

type write struct {
	req, resp int64
	inflight  int
}

// cmdLatency times each committed write to its answer and to the watch response
// carrying its event, all on the tap's clock. A store that notifies watchers
// before answering the writer shows negative answer-to-event values.
func cmdLatency(args []string) error {
	recs, err := readCapture(args[0])
	if err != nil {
		return err
	}
	reqT := map[uint64]int64{}
	inflightAt := map[uint64]int{}
	inflight := 0
	writes := map[int64]write{}
	service := map[string][]float64{}
	bucket := func(n int) string {
		switch {
		case n <= 1:
			return "1 write in flight"
		case n <= 3:
			return "2-3 writes in flight"
		case n <= 7:
			return "4-7 writes in flight"
		}
		return "8+ writes in flight"
	}
	for _, r := range recs {
		if !isWrite(r.Method) {
			continue
		}
		switch r.Dir {
		case "c2s":
			inflight++
			reqT[r.Stream], inflightAt[r.Stream] = r.T, inflight
		case "s2c":
			t0, ok := reqT[r.Stream]
			if !ok {
				continue
			}
			inflight--
			n := inflightAt[r.Stream]
			ms := float64(r.T-t0) / 1e6
			service["all"] = append(service["all"], ms)
			service[bucket(n)] = append(service[bucket(n)], ms)
			if rev := committed(r.Method, r.B64); rev > 0 {
				writes[rev] = write{req: t0, resp: r.T, inflight: n}
			}
		}
	}
	fromReq, fromResp := map[string][]float64{}, map[string][]float64{}
	type delivery struct {
		rev, t int64
		stream uint64
	}
	var ds []delivery
	for _, r := range recs {
		if r.Dir != "s2c" || !strings.HasSuffix(r.Method, "/Watch") {
			continue
		}
		var w pb.WatchResponse
		if proto.Unmarshal(r.B64, &w) != nil {
			continue
		}
		seen := map[int64]bool{}
		for _, e := range w.Events {
			rev := e.GetKv().GetModRevision()
			wr, ok := writes[rev]
			if !ok || seen[rev] {
				continue
			}
			seen[rev] = true
			ds = append(ds, delivery{rev, r.T, r.Stream})
			for _, b := range []string{"all", bucket(wr.inflight)} {
				fromReq[b] = append(fromReq[b], float64(r.T-wr.req)/1e6)
				fromResp[b] = append(fromResp[b], float64(r.T-wr.resp)/1e6)
			}
		}
	}
	show := func(title string, m map[string][]float64) {
		fmt.Printf("%s: %s\n", title, pcts(m["all"]))
		for _, b := range sortedKeys(m) {
			if b != "all" {
				fmt.Printf("  %-22s %s\n", b, pcts(m[b]))
			}
		}
	}
	show("write service (request in -> answer out)", service)
	show("write request in -> watch event out", fromReq)
	show("write answer out -> watch event out", fromResp)

	// Clients correlate resources watched on different streams: an event delivered
	// before one of an older revision on another stream is a window where they
	// disagree.
	sort.Slice(ds, func(i, j int) bool { return ds[i].rev < ds[j].rev })
	var skew []float64
	var latest delivery
	for _, d := range ds {
		if d.t < latest.t && d.stream != latest.stream {
			skew = append(skew, float64(latest.t-d.t)/1e6)
		}
		if d.t > latest.t {
			latest = d
		}
	}
	fmt.Printf("events delivered before an older revision's (on another stream): %d of %d; by %s\n", len(skew), len(ds), pcts(skew))
	return nil
}

func sortedKeys(m map[string][]float64) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
