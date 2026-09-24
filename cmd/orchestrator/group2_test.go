package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/TrafficWrapper/orchestrator/internal/protocol"
	bolt "go.etcd.io/bbolt"
)

func lastTxID(t *testing.T, s *server) int {
	t.Helper()
	var id int
	_ = s.store.db.View(func(tx *bolt.Tx) error { id = tx.ID(); return nil })
	return id
}

func TestHeartbeatSkipsRedundantWrites(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "hb-worker")
	rec, _ := s.store.worker(w.ID)
	if err := s.store.updateWorkerHeartbeat(w.ID, rec.DesiredSeq, rec.SelfDescribe); err != nil {
		t.Fatal(err)
	}
	before := lastTxID(t, s)
	if err := s.store.updateWorkerHeartbeat(w.ID, rec.DesiredSeq, rec.SelfDescribe); err != nil {
		t.Fatal(err)
	}
	if after := lastTxID(t, s); after != before {
		t.Fatalf("unchanged heartbeat wrote to the DB (tx %d -> %d)", before, after)
	}
	changed := map[string]any{"label": "renamed"}
	if err := s.store.updateWorkerHeartbeat(w.ID, rec.DesiredSeq, changed); err != nil {
		t.Fatal(err)
	}
	got, _ := s.store.worker(w.ID)
	if got.SelfDescribe["label"] != "renamed" {
		t.Fatal("heartbeat with a new self-description must be stored")
	}
}

func TestRecordAckReturnsSeqAfterQuotaBump(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "ack-worker")
	putQuotaDevice(t, s, deviceRecord{ID: "q-dev", Status: "approved", AWGPublicKey: "k", RealityUUID: "u", InternalIP: "10.13.13.10/32", Limits: deviceLimits{TrafficQuotaBytes: 10}, CreatedAt: time.Now().UTC(), ConfigSeq: 1})
	rec, _ := s.store.worker(w.ID)
	now := time.Now().UTC()
	if _, _, err := s.store.recordAck(w.ID, rec.DesiredSeq, "", nil, nil, []deviceUsage{{DeviceID: "q-dev"}}, now); err != nil {
		t.Fatal(err)
	}
	desired, blocked, err := s.store.recordAck(w.ID, rec.DesiredSeq, "", nil, nil, []deviceUsage{{DeviceID: "q-dev", RxBytes: 20}}, now)
	if err != nil || blocked != 1 {
		t.Fatalf("blocked=%d err=%v", blocked, err)
	}
	if desired <= rec.DesiredSeq {
		t.Fatalf("ack must report the bumped seq: got %d, before %d", desired, rec.DesiredSeq)
	}
	stored, _ := s.store.worker(w.ID)
	if stored.DesiredSeq != desired || stored.AppliedSeq != rec.DesiredSeq {
		t.Fatalf("stored=%+v desired=%d", stored, desired)
	}
}

func TestIdleJanitorDoesNotWrite(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "idle-worker")
	rec, _ := s.store.worker(w.ID)
	_ = s.store.updateWorkerHeartbeat(w.ID, rec.DesiredSeq, rec.SelfDescribe)
	putQuotaDevice(t, s, deviceRecord{ID: "idle-dev", Status: "approved", CreatedAt: time.Now().UTC()})
	before := lastTxID(t, s)
	now := time.Now().UTC()
	if n, err := s.store.markStaleWorkersInactive(now.Add(-workerFreshTTL)); err != nil || n != 0 {
		t.Fatalf("stale=%d err=%v", n, err)
	}
	if n, err := s.store.pruneDeadTokens(now); err != nil || n != 0 {
		t.Fatalf("pruned=%d err=%v", n, err)
	}
	if n, err := s.store.applyDeviceUsageAndBlocks("", nil, now); err != nil || n != 0 {
		t.Fatalf("blocked=%d err=%v", n, err)
	}
	if after := lastTxID(t, s); after != before {
		t.Fatalf("idle janitor wrote to the DB (tx %d -> %d)", before, after)
	}
}

func TestNudgeWakesOnSeqBump(t *testing.T) {
	s := newTestServer(t)
	kp, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer := kp.Public
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(peer))
	rec, _ := s.store.worker(w.ID)
	raw, _ := json.Marshal(nudgeRequest{WorkerID: w.ID, HaveSeq: rec.DesiredSeq})
	done := make(chan nudgeResponse, 1)
	go func() {
		resp, _ := s.handleNudge(context.Background(), peer, raw)
		done <- resp.(nudgeResponse)
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := s.store.db.Update(s.store.bumpWorkerSeqsTx); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-done:
		if !resp.OK || resp.DesiredSeq <= rec.DesiredSeq {
			t.Fatalf("resp=%+v", resp)
		}
		if waited := time.Since(start); waited > 500*time.Millisecond {
			t.Fatalf("nudge woke after %s", waited)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nudge did not wake on seq bump")
	}
}

func TestUpdateKeyCacheReloadsOnFileChange(t *testing.T) {
	s := newTestServer(t)
	s.cfg.UpdatePublicKey = ""
	if _, err := loadOrCreateUpdateSigningKey(&s.cfg); err != nil {
		t.Fatal(err)
	}
	s.cfg.UpdatePublicKey = ""
	_, first, err := s.loadServerUpdateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, again, _ := s.loadServerUpdateSigningKey()
	if again != first {
		t.Fatal("cached key changed without a file change")
	}
	path := filepath.Join(s.cfg.StateDir, "update.key")
	_, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := priv.MarshalText()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, future, future)
	_, second, err := s.loadServerUpdateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("replaced update.key was not reloaded")
	}
}
