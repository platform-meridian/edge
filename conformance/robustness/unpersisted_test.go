package main

import (
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"go.uber.org/zap"

	"go.etcd.io/etcd/tests/v3/robustness/model"
	"go.etcd.io/etcd/tests/v3/robustness/report"
	"go.etcd.io/etcd/tests/v3/robustness/validate"
)

func putKV(key, value string) model.EtcdRequest {
	return model.EtcdRequest{Type: model.Txn, Txn: &model.TxnRequest{OperationsOnSuccess: []model.EtcdOperation{
		{Type: model.PutOperation, Put: model.PutOptions{Key: key, Value: model.ToValueOrHash(value)}},
	}}}
}

func get(key string) model.EtcdRequest {
	return model.EtcdRequest{Type: model.Range, Range: &model.RangeRequest{RangeOptions: model.RangeOptions{Start: key}}}
}

func got(revision int64, kvs ...model.KeyValue) model.MaybeEtcdResponse {
	return model.MaybeEtcdResponse{EtcdResponse: model.EtcdResponse{
		Range: &model.RangeResponse{KVs: append([]model.KeyValue{}, kvs...), Count: int64(len(kvs))}, Revision: revision,
	}}
}

var failed = model.MaybeEtcdResponse{Error: "context deadline exceeded"}

func op(client int, call, ret int64, req model.EtcdRequest, resp model.MaybeEtcdResponse) porcupine.Operation {
	return porcupine.Operation{ClientId: client, Input: req, Call: call, Output: resp, Return: ret}
}

func sawAFailedPut() []report.ClientReport {
	seen := model.KeyValue{Key: "k", ValueRevision: model.ValueRevision{
		Value: model.ToValueOrHash("v"), ModRevision: 2, Version: 1, CreateRevision: 2,
	}}
	return []report.ClientReport{
		{ClientID: 0, KeyValue: []porcupine.Operation{
			op(0, 1, 2, get("k"), got(1)),
			op(0, 3, 4, putKV("k", "v"), failed),
		}},
		{ClientID: 1, KeyValue: []porcupine.Operation{op(1, 10, 11, get("k"), got(2, seen))}},
	}
}

func linearizable(t *testing.T, reports []report.ClientReport) bool {
	t.Helper()
	res := validate.ValidateAndReturnVisualize(zap.NewNop(), validate.Config{}, reports, nil, 10*time.Second)
	return res.Linearization.Error() == nil
}

func kept(reports []report.ClientReport) int {
	n := 0
	for _, r := range reports {
		n += len(r.KeyValue)
	}
	return n
}

func TestDroppedLostWriteFailsCheck(t *testing.T) {
	history := sawAFailedPut()
	if !linearizable(t, history) {
		t.Fatal("with the failed put kept, the read is explained by it")
	}
	dropped := dropUnpersisted(history, nil)
	if kept(dropped) != 2 {
		t.Fatalf("kept %d of 3 operations, want the failed put dropped", kept(dropped))
	}
	if linearizable(t, dropped) {
		t.Fatal("a read of a write the log does not hold passed")
	}
}

func TestUntakenBranchPutDropped(t *testing.T) {
	guarded := putKV("k", "v")
	guarded.Txn.Conditions = []model.EtcdCondition{{Key: "k", ExpectedVersion: 4}}
	history := []report.ClientReport{{KeyValue: []porcupine.Operation{op(0, 1, 2, guarded, failed)}}}
	if n := kept(dropUnpersisted(history, []model.EtcdRequest{guarded})); n != 0 {
		t.Fatalf("kept %d: the logged txn's compare failed", n)
	}
	if n := kept(dropUnpersisted(history, []model.EtcdRequest{putKV("k", "w"), putKV("k", "x"), putKV("k", "y"), putKV("k", "z"), guarded})); n != 1 {
		t.Fatalf("kept %d: at version 4 the logged txn's compare held", n)
	}
}

func TestLoggedFailedWriteKept(t *testing.T) {
	history := sawAFailedPut()
	dropped := dropUnpersisted(history, []model.EtcdRequest{putKV("k", "v")})
	if kept(dropped) != 3 {
		t.Fatalf("kept %d of 3 operations", kept(dropped))
	}
	if !linearizable(t, dropped) {
		t.Fatal("the persisted put explains the read")
	}
}

func TestFailedWriteDroppedOnlyWhenLogRulesOut(t *testing.T) {
	grant := func(id int64) model.EtcdRequest {
		return model.EtcdRequest{Type: model.LeaseGrant, LeaseGrant: &model.LeaseGrantRequest{LeaseID: id}}
	}
	revoke := model.EtcdRequest{Type: model.LeaseRevoke, LeaseRevoke: &model.LeaseRevokeRequest{LeaseID: 7}}
	del := model.EtcdRequest{Type: model.Txn, Txn: &model.TxnRequest{OperationsOnSuccess: []model.EtcdOperation{
		{Type: model.DeleteOperation, Delete: model.DeleteOptions{Key: "d"}},
	}}}
	compact := model.EtcdRequest{Type: model.Compact, Compact: &model.CompactRequest{Revision: 5}}
	answered := model.MaybeEtcdResponse{EtcdResponse: model.EtcdResponse{LeaseGrant: &model.LeaseGrantResponse{}, Revision: 1}}
	history := []report.ClientReport{{KeyValue: []porcupine.Operation{
		op(0, 1, 2, grant(7), answered),
		op(0, 3, 4, grant(0), failed),
		op(0, 5, 6, revoke, failed),
		op(0, 7, 8, del, failed),
		op(0, 9, 10, compact, failed),
		op(0, 11, 12, putKV("k", "v"), failed),
	}}}
	for _, c := range []struct {
		name      string
		persisted []model.EtcdRequest
		want      int
	}{
		{"nothing persisted but the answered grant", []model.EtcdRequest{grant(7)}, 1},
		{"an unanswered grant persisted", []model.EtcdRequest{grant(7), grant(8)}, 1},
		{"the revoke persisted", []model.EtcdRequest{grant(7), revoke}, 2},
		{"the delete persisted", []model.EtcdRequest{grant(7), del}, 2},
		{"the compaction persisted", []model.EtcdRequest{grant(7), compact}, 2},
		{"the put persisted", []model.EtcdRequest{grant(7), putKV("k", "v")}, 2},
		{"another value persisted", []model.EtcdRequest{grant(7), putKV("k", "w")}, 1},
	} {
		if n := kept(dropUnpersisted(history, c.persisted)); n != c.want {
			t.Errorf("%s: kept %d, want %d", c.name, n, c.want)
		}
	}
}
