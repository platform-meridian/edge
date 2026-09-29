package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// minReplayTTL keeps every replayed lease alive for the whole replay: expiry is
// wall-clock, and an expiry racing the serial requests would renumber every later
// revision differently on each store.
const minReplayTTL = 3600

type methodInfo struct {
	desc         protoreflect.MethodDescriptor
	bidi, server bool
}

func lookup(method string) (methodInfo, error) {
	name := protoreflect.FullName(strings.ReplaceAll(strings.TrimPrefix(method, "/"), "/", "."))
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
	if err != nil {
		return methodInfo{}, fmt.Errorf("%s: %w", method, err)
	}
	md := d.(protoreflect.MethodDescriptor)
	return methodInfo{desc: md, bidi: md.IsStreamingClient(), server: md.IsStreamingServer()}, nil
}

func newMsg(d protoreflect.MessageDescriptor) proto.Message {
	t, err := protoregistry.GlobalTypes.FindMessageByName(d.FullName())
	if err != nil {
		panic(err)
	}
	return t.New().Interface()
}

// result keys are u:<seq> for a unary call and s:<stream> for a stream.
type result struct {
	Key    string `json:"k"`
	Method string `json:"method"`
	Code   string `json:"code"`
	Msg    string `json:"msg,omitempty"`
	Resp   any    `json:"resp,omitempty"`
	Stream any    `json:"stream,omitempty"`
}

type liveStream struct {
	key    string
	method string
	cs     grpc.ClientStream
	cancel context.CancelFunc
	mu     sync.Mutex
	cond   *sync.Cond
	resps  []proto.Message
	err    error
	done   bool
}

type replayer struct {
	conn      *grpc.ClientConn
	capLeases map[int64]int64 // captured lease id -> this store's
	streams   map[uint64]*liveStream
	order     []uint64
	lastRecv  atomic.Int64
	rev       int64 // the newest revision any answer has carried
	out       []result
	norm      *normaliser
}

func (r *replayer) rewrite(m protoreflect.Message) {
	name := m.Descriptor().FullName()
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.Kind() == protoreflect.MessageKind && fd.IsList():
			for i := 0; i < v.List().Len(); i++ {
				r.rewrite(v.List().Get(i).Message())
			}
		case fd.Kind() == protoreflect.MessageKind && !fd.IsMap():
			r.rewrite(v.Message())
		case name == "etcdserverpb.LeaseGrantRequest" && fd.Name() == "TTL" && v.Int() < minReplayTTL:
			m.Set(fd, protoreflect.ValueOfInt64(minReplayTTL))
		case fd.Kind() == protoreflect.Int64Kind && (fd.Name() == "lease" ||
			(fd.Name() == "ID" && name != "etcdserverpb.LeaseGrantRequest")):
			if id, ok := r.capLeases[v.Int()]; ok {
				m.Set(fd, protoreflect.ValueOfInt64(id))
			}
		}
		return true
	})
}

func codeOf(err error) (string, string) {
	s := status.Convert(err)
	return s.Code().String(), s.Message()
}

func (r *replayer) run(recs []record) error {
	grantResp := map[uint64][]byte{} // stream -> captured LeaseGrant response
	for _, rec := range recs {
		if rec.Dir == "s2c" && strings.HasSuffix(rec.Method, "/LeaseGrant") {
			if _, ok := grantResp[rec.Stream]; !ok {
				grantResp[rec.Stream] = rec.B64
			}
		}
	}
	for _, rec := range recs {
		switch rec.Dir {
		case "c2s":
			mi, err := lookup(rec.Method)
			if err != nil {
				return err
			}
			req := newMsg(mi.desc.Input())
			if err := proto.Unmarshal(rec.B64, req); err != nil {
				return fmt.Errorf("seq %d: %w", rec.Seq, err)
			}
			r.rewrite(req.ProtoReflect())
			switch {
			case mi.bidi:
				r.sendStream(rec, mi, req)
			case mi.server:
				r.serverStream(rec, mi, req)
			default:
				r.unary(rec, mi, req, grantResp[rec.Stream])
			}
		case "end":
			if s := r.streams[rec.Stream]; s != nil {
				r.sync(s)
				s.cancel()
			}
		}
	}
	r.settle()
	for _, id := range r.order {
		s := r.streams[id]
		r.sync(s)
		s.cancel()
		s.mu.Lock()
		for !s.done {
			s.cond.Wait()
		}
		s.mu.Unlock()
		r.out = append(r.out, r.streamResult(s))
	}
	return nil
}

func (r *replayer) unary(rec record, mi methodInfo, req proto.Message, capturedGrant []byte) {
	resp := newMsg(mi.desc.Output())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := r.conn.Invoke(ctx, rec.Method, req, resp)
	res := result{Key: fmt.Sprintf("u:%d", rec.Seq), Method: rec.Method}
	res.Code, res.Msg = codeOf(err)
	if err == nil {
		if h, ok := resp.(interface{ GetHeader() *pb.ResponseHeader }); ok {
			r.rev = max(r.rev, h.GetHeader().GetRevision())
		}
		if g, ok := resp.(*pb.LeaseGrantResponse); ok && capturedGrant != nil {
			var cg pb.LeaseGrantResponse
			if proto.Unmarshal(capturedGrant, &cg) == nil {
				r.capLeases[cg.ID] = g.ID
			}
		}
		res.Resp = r.norm.msg(resp.ProtoReflect())
	}
	r.out = append(r.out, res)
}

func (r *replayer) serverStream(rec record, mi methodInfo, req proto.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := result{Key: fmt.Sprintf("u:%d", rec.Seq), Method: rec.Method}
	cs, err := r.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, rec.Method)
	var resps []any
	if err == nil {
		if err = cs.SendMsg(req); err == nil {
			cs.CloseSend()
			for {
				m := newMsg(mi.desc.Output())
				if err = cs.RecvMsg(m); err != nil {
					break
				}
				resps = append(resps, r.norm.msg(m.ProtoReflect()))
			}
		}
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	res.Code, res.Msg = codeOf(err)
	res.Resp = resps
	r.out = append(r.out, res)
}

func (r *replayer) sendStream(rec record, mi methodInfo, req proto.Message) {
	s := r.streams[rec.Stream]
	if s == nil {
		ctx, cancel := context.WithCancel(context.Background())
		s = &liveStream{key: fmt.Sprintf("s:%d", rec.Stream), method: rec.Method, cancel: cancel}
		s.cond = sync.NewCond(&s.mu)
		r.streams[rec.Stream] = s
		r.order = append(r.order, rec.Stream)
		cs, err := r.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, rec.Method)
		if err != nil {
			s.err, s.done = err, true
			return
		}
		s.cs = cs
		go func() {
			for {
				m := newMsg(mi.desc.Output())
				err := cs.RecvMsg(m)
				s.mu.Lock()
				if err != nil {
					s.err, s.done = err, true
					s.cond.Broadcast()
					s.mu.Unlock()
					return
				}
				s.resps = append(s.resps, m)
				r.lastRecv.Store(time.Now().UnixNano())
				s.cond.Broadcast()
				s.mu.Unlock()
			}
		}()
	}
	if s.cs == nil {
		return
	}
	// What a watch request is answered with depends on what is already delivered.
	wr, isWatch := req.(*pb.WatchRequest)
	if isWatch {
		r.settle()
		if wr.GetCancelRequest() != nil {
			r.sync(s)
		}
	}
	s.mu.Lock()
	before := len(s.resps)
	s.mu.Unlock()
	if s.cs.SendMsg(req) != nil {
		return
	}
	switch {
	case !isWatch: // a keepalive is answered once
		r.waitFor(s, 5*time.Second, func(ms []proto.Message) bool { return len(ms) > before })
	case wr.GetCreateRequest() != nil:
		r.waitFor(s, 5*time.Second, func(ms []proto.Message) bool {
			for _, m := range ms[before:] {
				if m.(*pb.WatchResponse).Created {
					return true
				}
			}
			return false
		})
	case wr.GetCancelRequest() != nil:
		r.waitFor(s, 2*time.Second, func(ms []proto.Message) bool {
			for _, m := range ms[before:] {
				if m.(*pb.WatchResponse).Canceled {
					return true
				}
			}
			return false
		})
	default: // progress: etcd may stay silent until the stream is synced
		r.waitFor(s, time.Second, func(ms []proto.Message) bool {
			for _, m := range ms[before:] {
				if w := m.(*pb.WatchResponse); w.WatchId == -1 {
					return true
				}
			}
			return false
		})
	}
}

func (r *replayer) waitFor(s *liveStream, d time.Duration, ok func([]proto.Message) bool) {
	deadline := time.Now().Add(d)
	t := time.AfterFunc(d, func() { s.mu.Lock(); s.cond.Broadcast(); s.mu.Unlock() })
	defer t.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.done && !ok(s.resps) && time.Now().Before(deadline) {
		s.cond.Wait()
	}
}

// sync waits for a progress response (watch id -1) at the newest revision, which
// both stores send once every event before it is delivered. Without it, a cancel
// or close in the capture would race delivery and the stores differ by timing.
func (r *replayer) sync(s *liveStream) {
	if s.cs == nil || !strings.HasSuffix(s.method, "/Watch") {
		return
	}
	progress := &pb.WatchRequest{RequestUnion: &pb.WatchRequest_ProgressRequest{ProgressRequest: &pb.WatchProgressRequest{}}}
	for range 50 {
		s.mu.Lock()
		before, done := len(s.resps), s.done
		s.mu.Unlock()
		if done || s.cs.SendMsg(progress) != nil {
			return
		}
		synced := false
		r.waitFor(s, 200*time.Millisecond, func(ms []proto.Message) bool {
			for _, m := range ms[before:] {
				if w := m.(*pb.WatchResponse); w.WatchId == -1 && len(w.Events) == 0 && w.GetHeader().GetRevision() >= r.rev {
					synced = true
				}
			}
			return synced
		})
		if synced {
			return
		}
	}
	log.Printf("%s: never reported progress at revision %d", s.key, r.rev)
}

func (r *replayer) settle() {
	const quiet, most = 30 * time.Millisecond, 3 * time.Second
	start := time.Now()
	for time.Since(start) < most {
		if time.Since(time.Unix(0, r.lastRecv.Load())) >= quiet {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *replayer) streamResult(s *liveStream) result {
	res := result{Key: s.key, Method: s.method}
	if s.err != nil && status.Code(s.err).String() != "Canceled" && !errors.Is(s.err, io.EOF) {
		res.Code, res.Msg = codeOf(s.err)
	} else {
		res.Code = "OK"
	}
	res.Stream = normStream(r.norm, s.method, s.resps)
	return res
}

// normStream flattens a stream's responses: watch events per watch (numbered by
// first appearance) and their delivery order are compared exactly; how events
// were batched into responses is not; progress notifications are time-driven and
// only counted.
func normStream(n *normaliser, method string, resps []proto.Message) any {
	if !strings.HasSuffix(method, "/Watch") {
		var out []any
		for _, m := range resps {
			out = append(out, n.msg(m.ProtoReflect()))
		}
		return out
	}
	ids := map[int64]string{}
	wid := func(id int64) string {
		if s, ok := ids[id]; ok {
			return s
		}
		s := fmt.Sprintf("W%d", len(ids)+1)
		ids[id] = s
		return s
	}
	events := map[string][]any{}
	var control, order []any
	progress := 0
	for _, m := range resps {
		w := m.(*pb.WatchResponse)
		switch {
		case w.Created || w.Canceled:
			c := map[string]any{"w": wid(w.WatchId), "created": w.Created, "canceled": w.Canceled,
				"rev": w.GetHeader().GetRevision()}
			if w.CompactRevision != 0 {
				c["compact"] = w.CompactRevision
			}
			if w.CancelReason != "" {
				c["reason"] = w.CancelReason
			}
			control = append(control, c)
		case len(w.Events) == 0:
			progress++
		}
		for _, e := range w.Events {
			id := wid(w.WatchId)
			events[id] = append(events[id], n.msg(e.ProtoReflect()))
			order = append(order, fmt.Sprintf("%s@%d", id, e.GetKv().GetModRevision()))
		}
	}
	return map[string]any{"control": control, "events": events, "order": order, "progress": progress}
}
