package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func noiseWorker(t *testing.T, s *server) ([]byte, workerRecord) {
	t.Helper()
	kp, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(kp.Public))
	rec, _ := s.store.worker(w.ID)
	if _, _, err := s.store.recordAck(w.ID, rec.DesiredSeq, "ok", "", nil, nil, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	return kp.Public, rec
}

func workerDesiredState(t *testing.T, bundle signedConfig) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &doc); err != nil {
		t.Fatal(err)
	}
	return doc["desired_state"].(map[string]any)
}

func pullAs(t *testing.T, s *server, peer []byte, req pullRequest) any {
	t.Helper()
	raw, _ := json.Marshal(req)
	resp, err := s.handlePull(peer, raw)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// ORC-H2: an old worker first receives an empty config, then is refused.
func TestRevokeOldWorkerIsTwoPhase(t *testing.T) {
	s := newTestServer(t)
	enrollTestDevice(t, s)
	peer, rec := noiseWorker(t, s)
	if err := s.store.revokeWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	revoked, _ := s.store.worker(rec.ID)
	if revoked.Status != "revoked" || revoked.RevokeSeq != rec.DesiredSeq+1 {
		t.Fatalf("revoke state: %+v", revoked)
	}
	resp, ok := pullAs(t, s, peer, pullRequest{WorkerID: rec.ID, HaveSeq: rec.DesiredSeq}).(pullResponse)
	if !ok || !resp.OK {
		t.Fatalf("phase one must serve a config: %+v", resp)
	}
	state := workerDesiredState(t, resp.WorkerBundle)
	if devices := state["approved_devices"].([]any); len(devices) != 0 {
		t.Fatalf("revoked worker got %d devices", len(devices))
	}
	if state["reality"].(map[string]any)["enabled"] != false || state["awg"].(map[string]any)["enabled"] != false {
		t.Fatal("revoked worker must get every protocol off")
	}
	ackRaw, _ := json.Marshal(ackRequest{WorkerID: rec.ID, AppliedVersion: revoked.RevokeSeq})
	ack, err := s.handleAck(peer, ackRaw)
	if err != nil {
		t.Fatal(err)
	}
	if refusal, ok := ack.(workerRefusal); !ok || refusal.Code != workerCodeRevoked {
		t.Fatalf("ack after phase one: %+v", ack)
	}
	if refusal, ok := pullAs(t, s, peer, pullRequest{WorkerID: rec.ID, HaveSeq: revoked.RevokeSeq}).(workerRefusal); !ok || refusal.Status != "revoked" || refusal.Error != "worker revoked" {
		t.Fatalf("pull after ack must be refused: %+v", refusal)
	}
}

func TestRevokeIsImmediateWithCapabilityOrAfterGrace(t *testing.T) {
	s := newTestServer(t)
	peer, rec := noiseWorker(t, s)
	if err := s.store.revokeWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := pullAs(t, s, peer, pullRequest{WorkerID: rec.ID, WorkerCapabilities: []string{workerCapRevokedStatus}}).(workerRefusal); !ok {
		t.Fatal("worker declaring revoked_status must be refused at once")
	}
	if err := s.store.updateWorker(rec.ID, func(w *workerRecord) error {
		past := time.Now().UTC().Add(-workerRevokeGrace - time.Minute)
		w.RevokedAt = &past
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := pullAs(t, s, peer, pullRequest{WorkerID: rec.ID}).(workerRefusal); !ok {
		t.Fatal("old worker must be refused after the grace period")
	}
	raw, _ := json.Marshal(nudgeRequest{WorkerID: rec.ID, HaveSeq: 0})
	if resp, _ := s.handleNudge(context.Background(), peer, raw); resp.(workerRefusal).Code != workerCodeRevoked {
		t.Fatalf("nudge=%+v", resp)
	}
}

func TestRevokedKeyCannotReEnrollAndKeepsToken(t *testing.T) {
	s := newTestServer(t)
	peer, rec := noiseWorker(t, s)
	if err := s.store.revokeWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.store.createToken("tok-id", "tok-secret", time.Hour, 1, ""); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(enrollRequest{Token: "tok-secret", SelfDescribe: map[string]any{"hostname": "x"}})
	resp, err := s.handleEnroll(peer, raw)
	if err != nil {
		t.Fatal(err)
	}
	if enroll := resp.(enrollResponse); enroll.OK || enroll.Code != workerCodeRevoked {
		t.Fatalf("enroll=%+v", enroll)
	}
	if id, err := s.store.findTokenID("tok-secret", "", time.Now().UTC()); err != nil || id == "" {
		t.Fatal("refused enroll must not spend the token")
	}
	if err := s.store.approveWorker(rec.ID); err == nil {
		t.Fatal("revoked is terminal: approve must fail")
	}
}

func TestPendingWorkerCallsCarryCode(t *testing.T) {
	s := newTestServer(t)
	kp, _ := protocol.GenerateKeypair()
	rec, err := s.store.upsertPendingWorker(protocol.KeyToBase64(kp.Public), map[string]any{"hostname": "p"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(nudgeRequest{WorkerID: rec.ID})
	if resp, _ := s.handleNudge(context.Background(), kp.Public, raw); resp.(workerRefusal).Code != workerCodePending {
		t.Fatalf("nudge=%+v", resp)
	}
	raw, _ = json.Marshal(ackRequest{WorkerID: rec.ID})
	if resp, _ := s.handleAck(kp.Public, raw); resp.(workerRefusal).Code != workerCodePending {
		t.Fatalf("ack=%+v", resp)
	}
	raw, _ = json.Marshal(workerTelemetryRequest{WorkerID: rec.ID})
	if resp, _ := s.handleWorkerTelemetry(kp.Public, raw); resp.(workerRefusal).Code != workerCodePending {
		t.Fatalf("telemetry=%+v", resp)
	}
	// Pull keeps its old answer: old pending workers only ever pull.
	if resp := pullAs(t, s, kp.Public, pullRequest{WorkerID: rec.ID}).(pullResponse); resp.OK || resp.Status != "pending" {
		t.Fatalf("pull=%+v", resp)
	}
}

// X-M3: a disabled worker gets no devices and only transition bumps.
func TestDisabledWorkerGetsNoDevicesOrDeviceBumps(t *testing.T) {
	s := newTestServer(t)
	device := enrollTestDevice(t, s)
	peer, rec := noiseWorker(t, s)
	disabled := false
	if err := s.store.updateWorkerPolicy(rec.ID, workerPolicyPatch{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	afterDisable, _ := s.store.worker(rec.ID)
	if afterDisable.DesiredSeq <= rec.DesiredSeq {
		t.Fatal("disable must bump the worker once")
	}
	resp := pullAs(t, s, peer, pullRequest{WorkerID: rec.ID, HaveSeq: rec.DesiredSeq}).(pullResponse)
	if devices := workerDesiredState(t, resp.WorkerBundle)["approved_devices"].([]any); len(devices) != 0 {
		t.Fatalf("disabled worker got %d devices", len(devices))
	}
	if _, err := s.store.updateDevice(device, true, func(*deviceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.store.worker(rec.ID); again.DesiredSeq != afterDisable.DesiredSeq {
		t.Fatal("device changes must not bump a disabled worker")
	}
	usage := []deviceUsage{{DeviceID: device, Source: "reality", RxBytes: 100}}
	if _, _, err := s.store.recordAck(rec.ID, afterDisable.DesiredSeq, "ok", "", nil, nil, usage, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if dev, _ := s.store.device(device); len(dev.UsageCounters) != 0 {
		t.Fatal("usage from a disabled worker must be ignored")
	}
}

// ORC-L32: last_seen follows the orchestrator clock, not the worker's.
func TestTelemetryReceivedAtUsesOrchestratorClock(t *testing.T) {
	snapshot, err := summarizeTelemetryPayload("d1", "w1", []byte(`{"did":"d1"}`), "2000-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(snapshot.ReceivedAt) > time.Minute {
		t.Fatalf("received_at=%s taken from the worker", snapshot.ReceivedAt)
	}
	if snapshot.Fields["worker_received_at"] != "2000-01-01T00:00:00Z" {
		t.Fatal("worker time must stay as a diagnostic")
	}
}

func TestAdminWorkerRevokeRequiresStepUp(t *testing.T) {
	s := newTestServer(t)
	_, rec := noiseWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	call := func(body map[string]string) int {
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		s.handleAdminWorkerRevoke(w, httptest.NewRequest(http.MethodPost, "/admin/v1/workers/revoke", bytes.NewReader(raw)))
		return w.Code
	}
	if code := call(map[string]string{"id": rec.ID}); code != http.StatusForbidden {
		t.Fatalf("revoke without step-up: status=%d", code)
	}
	if got, _ := s.store.worker(rec.ID); got.Status == "revoked" {
		t.Fatal("worker revoked without step-up")
	}
	if code := call(map[string]string{"id": rec.ID, "current_secret": "owner-secret-value"}); code != http.StatusOK {
		t.Fatalf("revoke with step-up: status=%d", code)
	}
	if got, _ := s.store.worker(rec.ID); got.Status != "revoked" {
		t.Fatal("worker not revoked")
	}
}

func enrollTestDevice(t *testing.T, s *server) string {
	t.Helper()
	putQuotaDevice(t, s, deviceRecord{ID: "rev-dev", Status: "approved", AWGPublicKey: "k", RealityUUID: "u", InternalIP: "10.13.13.10/32", CreatedAt: time.Now().UTC(), ConfigSeq: 1})
	return "rev-dev"
}
