package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"

	"go.etcd.io/etcd/tests/v3/robustness/model"
)

// An independent reader of edge-state's log (crates/edge-state/src/record.rs and
// entry.rs): frames of [len u32 LE][crc32 u32 LE][payload], read up to the first
// frame that does not verify, as recovery does.

// Entry tags and txn write kinds, as in crates/edge-state/src/entry.rs.
const (
	tagPut byte = iota
	tagDelete
	tagCompaction
	tagLeaseGrant
	tagLeaseRevoke
	tagTxn
	tagRevoke
	tagBase
	tagPutAbs
)

const (
	writePut byte = iota
	writeDelete
)

type logEntry struct {
	request model.EtcdRequest
	// revision the entry commits at; 0 when it consumes none.
	revision int64
}

type entryReader struct{ b []byte }

var errShort = errors.New("entry truncated")

func (r *entryReader) take(n int) ([]byte, error) {
	if n < 0 || len(r.b) < n {
		return nil, errShort
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

func (r *entryReader) u8() (byte, error) {
	v, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return v[0], nil
}

func (r *entryReader) u32() (uint32, error) {
	v, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(v), nil
}

func (r *entryReader) u64() (int64, error) {
	v, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(v)), nil
}

func (r *entryReader) bytes() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	v, err := r.take(int(n))
	return string(v), err
}

func txnOf(ops ...model.EtcdOperation) model.EtcdRequest {
	return model.EtcdRequest{Type: model.Txn, Txn: &model.TxnRequest{OperationsOnSuccess: ops}}
}

func putOp(key, value string, lease int64) model.EtcdOperation {
	return model.EtcdOperation{Type: model.PutOperation, Put: model.PutOptions{Key: key, Value: model.ToValueOrHash(value), LeaseID: lease}}
}

func deleteOp(key string) model.EtcdOperation {
	return model.EtcdOperation{Type: model.DeleteOperation, Delete: model.DeleteOptions{Key: key}}
}

func decodeEntry(p []byte) (logEntry, error) {
	if len(p) == 0 {
		return logEntry{}, errors.New("empty entry")
	}
	r := &entryReader{p[1:]}
	var e logEntry
	var err error
	switch p[0] {
	case tagPut:
		var lease int64
		var key string
		if e.revision, err = r.u64(); err == nil {
			if lease, err = r.u64(); err == nil {
				key, err = r.bytes()
			}
		}
		e.request = txnOf(putOp(key, string(r.b), lease))
		r.b = nil
	case tagDelete:
		e.revision, err = r.u64()
		e.request = txnOf(deleteOp(string(r.b)))
		r.b = nil
	case tagCompaction:
		var c int64
		c, err = r.u64()
		e.request = model.EtcdRequest{Type: model.Compact, Compact: &model.CompactRequest{Revision: c}}
	case tagLeaseGrant:
		var id int64
		if id, err = r.u64(); err == nil {
			_, err = r.u64()
		}
		e.request = model.EtcdRequest{Type: model.LeaseGrant, LeaseGrant: &model.LeaseGrantRequest{LeaseID: id}}
	case tagLeaseRevoke:
		var id int64
		id, err = r.u64()
		e.request = model.EtcdRequest{Type: model.LeaseRevoke, LeaseRevoke: &model.LeaseRevokeRequest{LeaseID: id}}
	case tagTxn:
		var n uint32
		if e.revision, err = r.u64(); err == nil {
			n, err = r.u32()
		}
		var ops []model.EtcdOperation
		for i := uint32(0); err == nil && i < n; i++ {
			var kind byte
			if kind, err = r.u8(); err != nil {
				break
			}
			switch kind {
			case writePut:
				var lease int64
				var key, value string
				if lease, err = r.u64(); err == nil {
					if key, err = r.bytes(); err == nil {
						value, err = r.bytes()
					}
				}
				ops = append(ops, putOp(key, value, lease))
			case writeDelete:
				var key string
				key, err = r.bytes()
				ops = append(ops, deleteOp(key))
			default:
				err = fmt.Errorf("unknown txn write kind %d", kind)
			}
		}
		e.request = txnOf(ops...)
	case tagRevoke: // the lease and its keys under one revision
		var id int64
		var n uint32
		if id, err = r.u64(); err == nil {
			if e.revision, err = r.u64(); err == nil {
				n, err = r.u32()
			}
		}
		for i := uint32(0); err == nil && i < n; i++ {
			_, err = r.bytes()
		}
		e.request = model.EtcdRequest{Type: model.LeaseRevoke, LeaseRevoke: &model.LeaseRevokeRequest{LeaseID: id}}
	case tagBase, tagPutAbs:
		return e, errors.New("the log was rotated: history before it is gone, so it cannot be replayed")
	default:
		return e, fmt.Errorf("unknown entry tag %d", p[0])
	}
	if err == nil && len(r.b) != 0 {
		err = fmt.Errorf("%d trailing bytes", len(r.b))
	}
	return e, err
}

func readEdgeLog(path string) ([]logEntry, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var out []logEntry
	for len(b) >= 8 {
		n := int(binary.LittleEndian.Uint32(b[0:4]))
		crc := binary.LittleEndian.Uint32(b[4:8])
		if n == 0 || 8+n > len(b) || crc32.ChecksumIEEE(b[8:8+n]) != crc {
			break
		}
		e, err := decodeEntry(b[8 : 8+n])
		if err != nil {
			return nil, 0, fmt.Errorf("entry %d: %w", len(out), err)
		}
		out = append(out, e)
		b = b[8+n:]
	}
	return out, len(b), nil
}

// persistedRequests replays the log through the etcd model and requires every
// entry's revision to be the one the model assigns: the store and the model must
// agree on which requests consumed a revision.
func persistedRequests(path string) ([]model.EtcdRequest, error) {
	entries, _, err := readEdgeLog(path)
	if err != nil {
		return nil, err
	}
	keySet := map[string]bool{}
	for _, e := range entries {
		if e.request.Txn != nil {
			for _, op := range e.request.Txn.OperationsOnSuccess {
				keySet[op.Put.Key+op.Delete.Key] = true
			}
		}
	}
	var keys []string
	for k := range keySet {
		keys = append(keys, k)
	}
	state := model.NewState(keys)
	var requests []model.EtcdRequest
	for i, e := range entries {
		next, resp := state.Step(e.request)
		if resp.Error != "" || resp.ClientError != "" {
			return nil, fmt.Errorf("log entry %d (%s) fails in the model: %s%s", i, e.request.Type, resp.Error, resp.ClientError)
		}
		want := state.Revision
		if e.revision != 0 {
			want = e.revision
		}
		if e.request.Type != model.Compact && next.Revision != want {
			return nil, fmt.Errorf("log entry %d (%s) is at revision %d, the model puts it at %d", i, e.request.Type, e.revision, next.Revision)
		}
		state = next
		requests = append(requests, e.request)
	}
	return requests, nil
}
