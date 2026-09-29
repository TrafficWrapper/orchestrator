package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func clientBundleSeq(t *testing.T, bundle signedConfig) (int64, map[string]any) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &doc); err != nil {
		t.Fatal(err)
	}
	seq := int64(doc["seq"].(float64))
	delete(doc, "seq")
	delete(doc, "issued_at")
	delete(doc, "expires_at")
	return seq, doc
}

func setWorkerSeqs(t *testing.T, s *server, id string, desired, applied int64, status string) {
	t.Helper()
	if err := s.store.updateWorker(id, func(rec *workerRecord) error {
		rec.DesiredSeq, rec.AppliedSeq = desired, applied
		if status != "" {
			rec.Status = status
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ORC-H1: the first counter lands above anything the old max(DesiredSeq)
// scheme could have issued, from any worker in any status.
func TestClientSeqMigratesAboveEveryWorkerSeq(t *testing.T) {
	s := newTestServer(t)
	a := addApprovedWorkerWithStatic(t, s, "seq-a")
	b := addApprovedWorkerWithStatic(t, s, "seq-b")
	setWorkerSeqs(t, s, a.ID, 900, 950, "inactive")
	setWorkerSeqs(t, s, b.ID, 400, 400, "")
	bundle, err := s.buildClientBundle()
	if err != nil {
		t.Fatal(err)
	}
	if seq, _ := clientBundleSeq(t, bundle); seq != 950+clientSeqMigrationGap {
		t.Fatalf("migrated seq=%d", seq)
	}
	s2 := newTestServer(t)
	s2.cfg.ClientSeqFloor = 5_000_000
	addApprovedWorkerWithStatic(t, s2, "seq-c")
	bundle, _ = s2.buildClientBundle()
	if seq, _ := clientBundleSeq(t, bundle); seq != 5_000_000 {
		t.Fatalf("floor not applied: seq=%d", seq)
	}
}

// ORC-H1/ORC-M13: content changes are published under a strictly higher seq
// after a confirming check, and one seq always carries one content.
func TestClientSeqMonotonicWithConfirmation(t *testing.T) {
	s := newTestServer(t)
	a := addApprovedWorkerWithStatic(t, s, "mono-a")
	addApprovedWorkerWithStatic(t, s, "mono-b")
	first, _ := s.buildClientBundle()
	seq1, content1 := clientBundleSeq(t, first)
	setWorkerSeqs(t, s, a.ID, 1, 1, "inactive")
	if _, err := s.refreshClientBundle(false); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.buildClientBundle()
	if seq, content := clientBundleSeq(t, pending); seq != seq1 || !jsonEqual(content, content1) {
		t.Fatal("an unconfirmed change must not alter the content under the same seq")
	}
	if _, err := s.refreshClientBundle(false); err != nil {
		t.Fatal(err)
	}
	s.clientBundleSigned = signedClientBundle{}
	published, _ := s.buildClientBundle()
	seq2, content2 := clientBundleSeq(t, published)
	if seq2 <= seq1 || jsonEqual(content2, content1) {
		t.Fatalf("confirmed change must publish under a higher seq: %d -> %d", seq1, seq2)
	}
	if strings.Contains(published.ConfigJSON, a.ID) {
		t.Fatal("inactive worker still published")
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Rollback invariant: every serving worker's DesiredSeq is at least the
// counter; disabled workers are left alone.
func TestClientSeqRaisesServingWorkers(t *testing.T) {
	s := newTestServer(t)
	a := addApprovedWorkerWithStatic(t, s, "inv-a")
	b := addApprovedWorkerWithStatic(t, s, "inv-b")
	off := false
	if err := s.store.updateWorkerPolicy(b.ID, workerPolicyPatch{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.store.worker(b.ID)
	bundle, _ := s.buildClientBundle()
	seq, _ := clientBundleSeq(t, bundle)
	if got, _ := s.store.worker(a.ID); got.DesiredSeq < seq {
		t.Fatalf("serving worker DesiredSeq=%d below counter %d", got.DesiredSeq, seq)
	}
	if got, _ := s.store.worker(b.ID); got.DesiredSeq != before.DesiredSeq {
		t.Fatal("disabled worker must not be raised")
	}
}

func TestClientSeqRepublishesBeforeExpiry(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "ttl-a")
	bundle, _ := s.buildClientBundle()
	seq1, content1 := clientBundleSeq(t, bundle)
	if err := s.store.db.Update(func(tx *bolt.Tx) error {
		st, _, _ := s.store.clientBundleState()
		st.PublishedAt = time.Now().Add(-s.clientBundleTTL() * 3 / 4)
		return s.store.putClientBundleStateTx(tx, st)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.refreshClientBundle(false); err != nil {
		t.Fatal(err)
	}
	bundle, _ = s.buildClientBundle()
	seq2, content2 := clientBundleSeq(t, bundle)
	if seq2 != seq1+1 || !jsonEqual(content1, content2) {
		t.Fatalf("aging bundle must be republished under seq+1 with the same content: %d -> %d", seq1, seq2)
	}
}

func TestClientAppliedSeqWindow(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "applied-a")
	bundle, _ := s.buildClientBundle()
	seq, _ := clientBundleSeq(t, bundle)
	rec, _ := s.store.worker(w.ID)
	s.observeClientAppliedSeq(rec, seq+clientAppliedSeqWindow+1)
	if st, _, _ := s.store.clientBundleState(); st.Seq != seq {
		t.Fatal("a report beyond the window must not move the counter")
	}
	s.observeClientAppliedSeq(rec, seq+500)
	if st, _, _ := s.store.clientBundleState(); st.Seq != seq+501 {
		t.Fatalf("counter=%d want %d", st.Seq, seq+501)
	}
}

// ORC-M2: a worker ahead of DesiredSeq (restored DB) is moved past it
// instead of freezing on NotModified.
func TestWorkerAheadOfDesiredSeqResyncs(t *testing.T) {
	s := newTestServer(t)
	kp, _ := protocol.GenerateKeypair()
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(kp.Public))
	rec, _ := s.store.worker(w.ID)
	ahead := rec.DesiredSeq + 500
	raw, _ := json.Marshal(pullRequest{WorkerID: w.ID, HaveSeq: ahead})
	resp, err := s.handlePull(kp.Public, raw)
	if err != nil {
		t.Fatal(err)
	}
	pull := resp.(pullResponse)
	if pull.NotModified || pull.DesiredSeq <= ahead {
		t.Fatalf("worker ahead must get a newer config: %+v", pull.DesiredSeq)
	}
	if _, _, err := s.store.recordAck(w.ID, pull.DesiredSeq+100, "ok", "", nil, nil, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.store.worker(w.ID); got.DesiredSeq <= pull.DesiredSeq+100 {
		t.Fatalf("ack ahead must resync: desired=%d", got.DesiredSeq)
	}
}

// ORC-L35: no workers means a retryable error before the token is spent.
func TestEnrollWithoutWorkersKeepsToken(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "stale-worker")
	if err := s.store.db.Update(func(tx *bolt.Tx) error {
		return rewriteBucket(tx.Bucket(bucketWorkers), func(k, raw []byte) ([]byte, error) {
			var rec workerRecord
			if err := s.store.openJSON(bucketWorkers, k, raw, &rec); err != nil {
				return nil, err
			}
			old := time.Now().Add(-24 * time.Hour)
			rec.ApprovedAt, rec.LastAckAt = &old, &old
			return s.store.sealJSON(bucketWorkers, k, rec)
		})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.createBootstrapToken("boot-empty", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollDeviceForTestWithVersion(t, s, "boot-empty", "0.1.31")
	if resp.OK || !strings.Contains(resp.Error, "no approved worker") {
		t.Fatalf("enroll=%+v", resp)
	}
	if id, err := s.store.findBootstrapTokenID("boot-empty", time.Now().UTC()); err != nil || id == "" {
		t.Fatal("token must not be spent")
	}
	bundle, _ := s.buildClientBundle()
	if !strings.Contains(bundle.ConfigJSON, `"workers":[]`) {
		t.Fatalf("workers must be an empty array: %s", bundle.ConfigJSON)
	}
}

func TestAutoDetectedAddressSurvivesShortEmptyReports(t *testing.T) {
	now := time.Now().UTC()
	rec := workerRecord{SelfDescribe: map[string]any{"egress_ip": "203.0.113.9", "reality": map[string]any{"address_v6": "2001:db8::9"}}}
	clean := map[string]any{"egress_ip": "", "reality": map[string]any{"address_v6": ""}}
	keepAutoDetected(&rec, clean, now)
	if clean["egress_ip"] != "203.0.113.9" || clean["reality"].(map[string]any)["address_v6"] != "2001:db8::9" {
		t.Fatalf("empty report must keep the last value: %v", clean)
	}
	later := map[string]any{"egress_ip": "", "reality": map[string]any{"address_v6": ""}}
	keepAutoDetected(&rec, later, now.Add(autoDetectEmptyGrace+time.Minute))
	if later["egress_ip"] != "" {
		t.Fatal("a persistent empty value must be accepted after the grace")
	}
}

func TestAdminClientSeqFloorRequiresStepUp(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "floor-a")
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	call := func(body map[string]any) int {
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		s.handleAdminClientSeqFloor(w, httptest.NewRequest(http.MethodPost, "/admin/v1/client-seq/floor", bytes.NewReader(raw)))
		return w.Code
	}
	if code := call(map[string]any{"floor": 9_000_000}); code != http.StatusForbidden {
		t.Fatalf("status=%d", code)
	}
	if code := call(map[string]any{"floor": 9_000_000, "current_secret": "owner-secret-value"}); code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if st, _, _ := s.store.clientBundleState(); st.Seq != 9_000_000 {
		t.Fatalf("seq=%d", st.Seq)
	}
}
