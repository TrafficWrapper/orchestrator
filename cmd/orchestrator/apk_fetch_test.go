package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// seededAPKServer publishes a seed APK and adds one approved worker whose
// static key is peer.
func seededAPKServer(t *testing.T, apk []byte) (*server, workerRecord, []byte) {
	t.Helper()
	s := newTestServer(t)
	seed := filepath.Join(s.cfg.StateDir, "seed-app.apk")
	if err := os.WriteFile(seed, apk, 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.SeedAPKPath, s.cfg.SeedVersionCode, s.cfg.SeedVersionName, s.cfg.UpdatePublicKey = seed, 7, "seed", ""
	priv, err := loadOrCreateUpdateSigningKey(&s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.seedUpdateAPKIfPresent(priv); err != nil {
		t.Fatal(err)
	}
	peer := bytes.Repeat([]byte{7}, 32)
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(peer))
	return s, w, peer
}

func deliveryForTest(t *testing.T, s *server, id string, haveSeq int64, caps []string) apkDelivery {
	t.Helper()
	rec, err := s.store.worker(id)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.apkDeliveryForPull(rec, haveSeq, caps)
	if err != nil {
		t.Fatal(err)
	}
	if d.release != nil {
		d.release()
	}
	return d
}

// ORC-M8: a worker declaring apk_fetch_v1 in its pull gets update_ref and no
// inline APK; a declaration only in the stored self_describe does not count.
func TestPullSendsUpdateRefOnlyForDeclaredFetch(t *testing.T) {
	apk := []byte("apk bytes for chunked fetch")
	s, w, _ := seededAPKServer(t, apk)
	rel, _, _ := s.store.currentAPKRelease()
	d := deliveryForTest(t, s, w.ID, 1, []string{workerCapAPKFetch})
	if d.update != nil || d.ref == nil {
		t.Fatalf("update=%v ref=%v", d.update != nil, d.ref)
	}
	if d.ref.APKSeq != rel.Seq || d.ref.APKSize != int64(len(apk)) || d.ref.APKSHA256 != rel.APKSHA256 || d.ref.ManifestJSON == "" || d.ref.ManifestMinisig == "" {
		t.Fatalf("ref=%+v", d.ref)
	}
	raw, _ := json.Marshal(pullResponse{OK: true, UpdateRef: d.ref})
	if !bytes.Contains(raw, []byte(`"update_ref":{"apk_seq":`)) || bytes.Contains(raw, []byte(`"update":`)) {
		t.Fatalf("pull json: %s", raw)
	}
	if _, err := s.store.upsertPendingWorker(w.StaticPublicKey, map[string]any{"capabilities": []any{workerCapAPKFetch}}); err != nil {
		t.Fatal(err)
	}
	if d := deliveryForTest(t, s, w.ID, 1, nil); d.ref != nil || d.update == nil {
		t.Fatalf("stored capability must not switch to update_ref: ref=%v update=%v", d.ref != nil, d.update != nil)
	}
}

// ORC-M8: APKs over the inline limit are left out entirely for old workers.
func TestInlineAPKLimit(t *testing.T) {
	s, w, _ := seededAPKServer(t, bytes.Repeat([]byte("x"), 64))
	s.cfg.APKInlineMaxBytes = 32
	if d := deliveryForTest(t, s, w.ID, 1, nil); d.update != nil || d.ref != nil {
		t.Fatal("APK above the inline limit shipped")
	}
	if d := deliveryForTest(t, s, w.ID, 1, []string{workerCapAPKFetch}); d.ref == nil {
		t.Fatal("chunked fetch must not depend on the inline limit")
	}
	if err := validateAPKLimits(orchConfig{APKInlineMaxBytes: maxAPKInlineMaxBytes + 1}); err == nil {
		t.Fatal("inline limit above 64 MiB accepted")
	}
	if err := validateAPKLimits(orchConfig{APKInlineMaxBytes: defaultAPKInlineMaxBytes, APKMaxBytes: defaultAPKMaxBytes}); err != nil {
		t.Fatal(err)
	}
}

// ORC-M16: inline responses carry a write deadline and a worker holds at
// most one shipment slot.
func TestInlineAPKWriteDeadlineAndPerWorkerSlot(t *testing.T) {
	s, w, _ := seededAPKServer(t, []byte("apk"))
	rec, _ := s.store.worker(w.ID)
	d, err := s.apkDeliveryForPull(rec, 1, nil)
	if err != nil || d.update == nil || d.writeTimeout <= 0 {
		t.Fatalf("inline delivery: update=%v timeout=%s err=%v", d.update != nil, d.writeTimeout, err)
	}
	if (pullResponse{writeTimeout: d.writeTimeout}).responseWriteTimeout() != d.writeTimeout {
		t.Fatal("pull response must expose its write timeout")
	}
	if _, ok := s.acquireAPKShipment(w.ID, 10*time.Millisecond); ok {
		t.Fatal("a second slot for the same worker was granted")
	}
	d.release()
	if release, ok := s.acquireAPKShipment(w.ID, 10*time.Millisecond); !ok {
		t.Fatal("slot not reusable after release")
	} else {
		release()
	}
}

// ORC-M8/WRK-M9: a worker that keeps pulling with the same have_seq after an
// inline APK stops getting it (backoff) but keeps getting config; an ack
// clears the marker.
func TestInlineAPKAttemptMarker(t *testing.T) {
	s, w, _ := seededAPKServer(t, []byte("apk"))
	for i := range apkInlineMaxFailures {
		if d := deliveryForTest(t, s, w.ID, 5, nil); d.update == nil {
			t.Fatalf("attempt %d: APK not shipped", i)
		}
	}
	if d := deliveryForTest(t, s, w.ID, 5, nil); d.update != nil {
		t.Fatal("APK shipped again after repeated failed attempts")
	}
	rec, _ := s.store.worker(w.ID)
	if rec.APKInlineRetryAt == nil || rec.APKSentSeq != 0 {
		t.Fatalf("backoff not recorded: %+v", rec)
	}
	if d := deliveryForTest(t, s, w.ID, 5, nil); d.update != nil {
		t.Fatal("APK shipped during backoff")
	}
	// Once the backoff passes it is tried again; an ack clears the marker.
	past := time.Now().UTC().Add(-time.Minute)
	if err := s.store.updateWorker(w.ID, func(rec *workerRecord) error { rec.APKInlineRetryAt = &past; return nil }); err != nil {
		t.Fatal(err)
	}
	if d := deliveryForTest(t, s, w.ID, 6, nil); d.update == nil {
		t.Fatal("APK not retried after backoff")
	}
	rec, _ = s.store.worker(w.ID)
	if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	rel, _, _ := s.store.currentAPKRelease()
	if rec.APKAppliedSeq != rel.Seq || rec.APKInlinePending || rec.APKInlineFailures != 0 || rec.APKInlineRetryAt != nil {
		t.Fatalf("ack did not clear the marker: %+v", rec)
	}
}

// ORC-M15: a pull that goes out without the APK clears the sent markers so a
// later ack cannot mark the release applied.
func TestPullWithoutAPKClearsSentMarkers(t *testing.T) {
	s, w, _ := seededAPKServer(t, []byte("apk"))
	if d := deliveryForTest(t, s, w.ID, 1, nil); d.update == nil {
		t.Fatal("APK not shipped")
	}
	old := apkShipmentWait
	apkShipmentWait = 10 * time.Millisecond
	t.Cleanup(func() { apkShipmentWait = old })
	var held []func()
	for i := range maxConcurrentAPKShipments {
		release, ok := s.acquireAPKShipment("other-"+string(rune('a'+i)), time.Second)
		if !ok {
			t.Fatal("slot not granted")
		}
		held = append(held, release)
	}
	if d := deliveryForTest(t, s, w.ID, 1, nil); d.update != nil {
		t.Fatal("APK shipped with all slots busy")
	}
	for _, release := range held {
		release()
	}
	rec, _ := s.store.worker(w.ID)
	if rec.APKSentSeq != 0 || rec.APKSentAtSeq != 0 {
		t.Fatalf("sent markers kept: %+v", rec)
	}
	if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", nil); err != nil {
		t.Fatal(err)
	}
	if rec, _ := s.store.worker(w.ID); rec.APKAppliedSeq != 0 {
		t.Fatal("ack marked an unsent APK applied")
	}
}

// Workers reporting distributed_apk.seq are matched by sha256 and seq.
func TestAPKAppliedByDistributedSeq(t *testing.T) {
	rel := apkReleaseRecord{Seq: 4, APKSHA256: "ab"}
	rec := workerRecord{APKAppliedSeq: 4, SelfDescribe: map[string]any{"distributed_apk": map[string]any{"apk_sha256": "AB", "seq": float64(3)}}}
	if apkReleaseApplied(rec, rel) {
		t.Fatal("older reported seq treated as applied")
	}
	rec.SelfDescribe["distributed_apk"].(map[string]any)["seq"] = float64(4)
	if !apkReleaseApplied(rec, rel) {
		t.Fatal("matching sha and seq not applied")
	}
	if !apkReleaseApplied(workerRecord{APKAppliedSeq: 4}, rel) {
		t.Fatal("legacy marker ignored")
	}
}

// ORC-L22: a release whose files cannot be read drops only the APK.
func TestPullSurvivesUnreadableAPK(t *testing.T) {
	s, w, _ := seededAPKServer(t, []byte("apk"))
	rel, _, _ := s.store.currentAPKRelease()
	if err := os.Remove(rel.APKPath); err != nil {
		t.Fatal(err)
	}
	if d := deliveryForTest(t, s, w.ID, 1, nil); d.update != nil {
		t.Fatal("unreadable APK shipped")
	}
	if err := os.Remove(rel.ManifestPath); err != nil {
		t.Fatal(err)
	}
	if d := deliveryForTest(t, s, w.ID, 1, []string{workerCapAPKFetch}); d.ref != nil {
		t.Fatal("update_ref without a manifest")
	}
}

func chunkForTest(t *testing.T, s *server, peer []byte, req apkChunkRequest) apkChunkResponse {
	t.Helper()
	raw, _ := json.Marshal(req)
	resp, err := s.handleAPKChunk(context.Background(), peer, raw)
	if err != nil {
		t.Fatal(err)
	}
	out := resp.(apkChunkResponse)
	out.releaseAfterWrite()
	return out
}

func TestAPKChunkEndpoint(t *testing.T) {
	apk := []byte("0123456789abcdef")
	s, w, peer := seededAPKServer(t, apk)
	rel, _, _ := s.store.currentAPKRelease()
	base := apkChunkRequest{WorkerID: w.ID, APKSeq: rel.Seq, APKSHA256: rel.APKSHA256}

	req := base
	req.Offset, req.Length = 10, 100
	resp := chunkForTest(t, s, peer, req)
	data, _ := base64.StdEncoding.DecodeString(resp.DataBase64)
	if !resp.OK || resp.TotalSize != int64(len(apk)) || string(data) != "abcdef" {
		t.Fatalf("tail chunk: %+v data=%q", resp, data)
	}
	if resp.responseWriteTimeout() <= 0 {
		t.Fatal("chunk response without a write deadline")
	}
	for _, bad := range []apkChunkRequest{{Offset: -1, Length: 1}, {Offset: 16, Length: 1}, {Offset: 0, Length: 0}, {Offset: 0, Length: apkChunkMaxBytes + 1}} {
		req := base
		req.Offset, req.Length = bad.Offset, bad.Length
		if resp := chunkForTest(t, s, peer, req); resp.OK || resp.Code != apkCodeBadRange {
			t.Fatalf("range %d+%d: %+v", bad.Offset, bad.Length, resp)
		}
	}
	req = base
	req.APKSHA256, req.Length = "00", 1
	if resp := chunkForTest(t, s, peer, req); resp.OK || resp.Code != apkCodeSuperseded {
		t.Fatalf("other sha: %+v", resp)
	}
	// An older seq of the same APK (re-signed manifest) keeps downloading.
	req = base
	req.APKSeq, req.Length = rel.Seq-1, 4
	if resp := chunkForTest(t, s, peer, req); !resp.OK {
		t.Fatalf("older seq, same sha: %+v", resp)
	}
	req = base
	req.Length = 1
	if resp := chunkForTest(t, s, bytes.Repeat([]byte{9}, 32), req); resp.OK {
		t.Fatal("chunk served to another key")
	}
	if err := s.store.revokeWorker(w.ID); err != nil {
		t.Fatal(err)
	}
	if resp := chunkForTest(t, s, peer, req); resp.OK || resp.Code != workerCodeRevoked {
		t.Fatalf("revoked worker: %+v", resp)
	}
}

// ORC-L34: the orchestrator's own downtime is not worker silence.
func TestStartupGraceForWorkerLiveness(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	if s.startupGrace(now) {
		t.Fatal("no grace without a start time")
	}
	s.startedAt = now.Add(-time.Minute)
	if !s.startupGrace(now) || s.startupGrace(now.Add(workerFreshTTL)) {
		t.Fatal("grace must last workerFreshTTL after start")
	}
	old := now.Add(-time.Hour)
	rec := s.seenSinceStart(workerRecord{Status: "approved", LastAckAt: &old})
	if _, down := botWorkerProblemEntry(rec, now); down {
		t.Fatal("worker reported down during startup grace")
	}
	if !rec.LastAckAt.Equal(s.startedAt) {
		t.Fatalf("last seen=%s", rec.LastAckAt)
	}
}

// ORC-M8: publishing refuses APKs above ORCH_APK_MAX_BYTES.
func TestAPKPublishSizeLimit(t *testing.T) {
	s, ts, token := autoPublishServer(t)
	apk := buildTestAPKWithManifest(t, 1011, "0.1.11")
	s.cfg.APKMaxBytes = int64(len(apk)) - 1
	if code := publishStatus(t, ts.URL+"/admin/v1/apk/publish", token, apk, nil); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized APK: %d", code)
	}
	s.cfg.APKMaxBytes = int64(len(apk))
	if code := publishStatus(t, ts.URL+"/admin/v1/apk/publish", token, apk, nil); code != http.StatusOK {
		t.Fatalf("APK at the limit: %d", code)
	}
}

// X-I12: chunk responses carry server_time like every other Noise response,
// and stamping keeps the slot release.
func TestAPKChunkResponseCarriesServerTime(t *testing.T) {
	released := false
	stamped := stampServerTime(apkChunkResponse{OK: true, release: func() { released = true }}, time.UnixMilli(1234))
	resp, ok := stamped.(apkChunkResponse)
	if !ok || resp.ServerTime != 1234 {
		t.Fatalf("stamped=%+v", stamped)
	}
	resp.releaseAfterWrite()
	if !released {
		t.Fatal("stamping dropped the release func")
	}
}
