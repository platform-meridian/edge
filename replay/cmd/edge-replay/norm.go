package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// masked are fields that legitimately differ between two stores, or between two
// runs of one: identity, raft bookkeeping, sizes, versions, TTL remainders and
// hashes of implementation-defined state. Keyed by message name, then field.
var masked = map[protoreflect.FullName]map[protoreflect.Name]bool{
	"etcdserverpb.StatusResponse": set("version", "dbSize", "leader", "raftIndex", "raftTerm",
		"raftAppliedIndex", "dbSizeInUse", "isLearner", "storageVersion", "dbSizeQuota", "downgradeInfo"),
	"etcdserverpb.Member":                  set("ID", "name", "peerURLs", "clientURLs"),
	"etcdserverpb.LeaseKeepAliveResponse":  set("TTL"),
	"etcdserverpb.LeaseTimeToLiveResponse": set("TTL"),
	"etcdserverpb.HashResponse":            set("hash"),
	"etcdserverpb.HashKVResponse":          set("hash", "hash_revision"),
	"etcdserverpb.SnapshotResponse":        set("blob", "remaining_bytes", "version"),
	"etcdserverpb.MemberUpdateResponse":    set("members"),
	"etcdserverpb.DowngradeResponse":       set("version"),
	"etcdserverpb.AuthenticateResponse":    set("token"),
	"etcdserverpb.ResponseHeader":          set("cluster_id", "member_id", "raft_term"),
	"etcdserverpb.MemberPromoteResponse":   set("members"),
	"etcdserverpb.MemberAddResponse":       set("members", "member"),
	"etcdserverpb.MemberRemoveResponse":    set("members"),
	"etcdserverpb.AlarmMember":             set("memberID"),
}

func set(names ...protoreflect.Name) map[protoreflect.Name]bool {
	m := map[protoreflect.Name]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// leaseField names the fields that carry a lease id, which differ per store and
// are compared by order of first appearance instead.
func leaseField(msg protoreflect.FullName, f protoreflect.Name) bool {
	switch {
	case f == "lease":
		return true
	case f == "ID":
		switch msg {
		case "etcdserverpb.LeaseGrantResponse", "etcdserverpb.LeaseKeepAliveResponse",
			"etcdserverpb.LeaseTimeToLiveResponse", "etcdserverpb.LeaseStatus":
			return true
		}
	}
	return false
}

type normaliser struct {
	leases map[int64]string
}

func newNormaliser() *normaliser { return &normaliser{leases: map[int64]string{}} }

func (n *normaliser) lease(id int64) string {
	if id == 0 {
		return "0"
	}
	if s, ok := n.leases[id]; ok {
		return s
	}
	s := fmt.Sprintf("L%d", len(n.leases)+1)
	n.leases[id] = s
	return s
}

func (n *normaliser) msg(m protoreflect.Message) map[string]any {
	out := map[string]any{}
	name := m.Descriptor().FullName()
	mask := masked[name]
	// Present or not: one store may send a zero value the other leaves out.
	for f := range mask {
		if m.Descriptor().Fields().ByName(f) != nil {
			out[string(f)] = "*"
		}
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		f := fd.Name()
		if mask[f] {
			return true
		}
		switch {
		case fd.IsList():
			l := v.List()
			a := make([]any, l.Len())
			for i := range a {
				a[i] = n.value(name, fd, l.Get(i))
			}
			out[string(f)] = a
		case fd.IsMap():
			out[string(f)] = fmt.Sprintf("map[%d]", v.Map().Len())
		default:
			out[string(f)] = n.value(name, fd, v)
		}
		return true
	})
	return out
}

func (n *normaliser) value(msg protoreflect.FullName, fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return n.msg(v.Message())
	case protoreflect.EnumKind:
		if ev := fd.Enum().Values().ByNumber(v.Enum()); ev != nil {
			return string(ev.Name())
		}
		return int32(v.Enum())
	case protoreflect.BytesKind:
		b := v.Bytes()
		if fd.Name() == "value" || !utf8.Valid(b) {
			h := sha256.Sum256(b)
			return fmt.Sprintf("sha:%s/%d", hex.EncodeToString(h[:6]), len(b))
		}
		return string(b)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		if leaseField(msg, fd.Name()) {
			return n.lease(v.Int())
		}
		return v.Int()
	}
	return v.Interface()
}
