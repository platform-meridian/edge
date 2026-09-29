package main

import (
	"github.com/anishathalye/porcupine"

	"go.etcd.io/etcd/tests/v3/robustness/model"
	"go.etcd.io/etcd/tests/v3/robustness/report"
)

// dropUnpersisted removes failed writes that never took effect: those whose
// branch did not write in a replay of the store's log (etcd's log also holds txns
// whose compare failed), and failed lease grants, which nothing can observe.
//
// The checker tries every failed write both ways, multiplying its search.
// Dropping one asserts it did not take effect, which only narrows what passes:
// if the log lost a write that did take effect, a later read the history no
// longer explains fails the check.
func dropUnpersisted(reports []report.ClientReport, persisted []model.EtcdRequest) []report.ClientReport {
	puts := map[model.PutOptions]bool{}
	deletes := map[string]bool{}
	revokes := map[int64]bool{}
	compacts := map[int64]bool{}
	var logged []porcupine.Operation
	for _, r := range persisted {
		logged = append(logged, porcupine.Operation{Input: r})
	}
	state := model.NewState(model.ModelKeys(logged))
	for _, r := range persisted {
		next, resp := state.Step(r)
		switch r.Type {
		case model.Txn:
			ops := r.Txn.OperationsOnSuccess
			if resp.Txn != nil && resp.Txn.Failure {
				ops = r.Txn.OperationsOnFailure
			}
			for _, op := range ops {
				switch op.Type {
				case model.PutOperation:
					puts[model.PutOptions{Key: op.Put.Key, Value: op.Put.Value}] = true
				case model.DeleteOperation:
					deletes[op.Delete.Key] = true
				}
			}
		case model.LeaseRevoke:
			revokes[r.LeaseRevoke.LeaseID] = true
		case model.Compact:
			compacts[r.Compact.Revision] = true
		}
		state = next
	}
	persistedWrite := func(req model.EtcdRequest) bool {
		switch req.Type {
		case model.Txn:
			for _, op := range req.Txn.AllOperations() {
				switch op.Type {
				case model.PutOperation:
					if puts[model.PutOptions{Key: op.Put.Key, Value: op.Put.Value}] {
						return true
					}
				case model.DeleteOperation:
					if deletes[op.Delete.Key] {
						return true
					}
				}
			}
			return false
		case model.LeaseGrant:
			// Whether or not it took effect, no client learned its lease ID, so nothing
			// in the history can use or observe that lease.
			return false
		case model.LeaseRevoke:
			return revokes[req.LeaseRevoke.LeaseID]
		case model.Compact:
			return compacts[req.Compact.Revision]
		}
		return true
	}

	out := make([]report.ClientReport, len(reports))
	for i, r := range reports {
		out[i] = r
		out[i].KeyValue = nil
		for _, op := range r.KeyValue {
			req := op.Input.(model.EtcdRequest)
			if op.Output.(model.MaybeEtcdResponse).Error != "" && !req.IsRead() && !persistedWrite(req) {
				continue
			}
			out[i].KeyValue = append(out[i].KeyValue, op)
		}
	}
	return out
}
