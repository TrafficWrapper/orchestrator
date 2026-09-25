package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestSanitizeWorkerCapabilities(t *testing.T) {
	in := []string{" apk_fetch_v1 ", "unknown_cap", "revoked_status", "apk_fetch_v1", "", strings.Repeat("x", 100), "reality_flow", "desired_state_enabled"}
	got := sanitizeWorkerCapabilities(in)
	want := []string{"apk_fetch_v1", "desired_state_enabled", "reality_flow", "revoked_status"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := sanitizeWorkerCapabilities(nil); got != nil {
		t.Fatalf("nil input gave %v", got)
	}
	long := make([]string, 0, 1000)
	for i := 0; i < 1000; i++ {
		long = append(long, "junk")
	}
	long = append(long, "apk_fetch_v1")
	if got := sanitizeWorkerCapabilities(long); len(got) != 0 {
		t.Fatalf("entries past the count bound were read: %v", got)
	}
}

// X-I12: self_describe.capabilities passes the sanitizer and is stored.
func TestSelfDescribeCapabilitiesAreStored(t *testing.T) {
	clean, _ := sanitizeSelfDescribe(map[string]any{"capabilities": []any{"reality_flow", "apk_fetch_v1"}})
	caps, ok := clean["capabilities"].([]any)
	if !ok || len(caps) != 2 {
		t.Fatalf("sanitized capabilities=%v", clean["capabilities"])
	}
	s := newTestServer(t)
	rec, err := s.store.upsertPendingWorker("caps-static", map[string]any{"capabilities": []any{"revoked_status"}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.store.worker(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !workerHasCapability(stored, nil, workerCapRevokedStatus) {
		t.Fatalf("stored self_describe lost capabilities: %v", stored.SelfDescribe["capabilities"])
	}
	payload := adminWorkerPayload(stored)
	if got, _ := payload["capabilities"].([]string); !slices.Equal(got, []string{"revoked_status"}) {
		t.Fatalf("admin capabilities=%v", payload["capabilities"])
	}
}

func rawWorkerRecordForTest(t *testing.T, s *server, id string) []byte {
	t.Helper()
	var out []byte
	if err := s.store.db.View(func(tx *bolt.Tx) error {
		out = bytes.Clone(tx.Bucket(bucketWorkers).Get([]byte(id)))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// X-I12: the pull's worker_capabilities is sanitized, kept on the worker
// record, shown in the admin API, and written only when it changes.
func TestPullStoresWorkerCapabilities(t *testing.T) {
	s := newTestServer(t)
	peer, rec := noiseWorker(t, s)
	req := pullRequest{WorkerID: rec.ID, HaveSeq: rec.DesiredSeq, WorkerCapabilities: []string{"revoked_status", "future_cap", "apk_fetch_v1"}}
	if resp, ok := pullAs(t, s, peer, req).(pullResponse); !ok || !resp.OK {
		t.Fatalf("pull failed: %#v", resp)
	}
	stored, err := s.store.worker(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"apk_fetch_v1", "revoked_status"}
	if !slices.Equal(stored.PullCapabilities, want) {
		t.Fatalf("pull capabilities=%v want %v", stored.PullCapabilities, want)
	}
	raw, _ := json.Marshal(adminWorkerPayload(stored))
	if !strings.Contains(string(raw), `"pull_capabilities":["apk_fetch_v1","revoked_status"]`) {
		t.Fatalf("admin worker payload misses pull capabilities: %s", raw)
	}

	before := rawWorkerRecordForTest(t, s, rec.ID)
	req.WorkerCapabilities = []string{"apk_fetch_v1", "revoked_status", "apk_fetch_v1"}
	pullAs(t, s, peer, req)
	if after := rawWorkerRecordForTest(t, s, rec.ID); !bytes.Equal(before, after) {
		t.Fatal("an unchanged capability list rewrote the worker record")
	}

	req.WorkerCapabilities = nil
	pullAs(t, s, peer, req)
	stored, _ = s.store.worker(rec.ID)
	if len(stored.PullCapabilities) != 0 {
		t.Fatalf("pull without worker_capabilities kept %v", stored.PullCapabilities)
	}
	raw, _ = json.Marshal(adminWorkerPayload(stored))
	if !strings.Contains(string(raw), `"pull_capabilities":[]`) {
		t.Fatalf("admin payload must list an empty array: %s", raw)
	}
}

// Old workers send no worker_capabilities: nothing is stored and nothing
// is written.
func TestPullWithoutCapabilitiesDoesNotWrite(t *testing.T) {
	s := newTestServer(t)
	peer, rec := noiseWorker(t, s)
	before := rawWorkerRecordForTest(t, s, rec.ID)
	pullAs(t, s, peer, pullRequest{WorkerID: rec.ID, HaveSeq: rec.DesiredSeq})
	if after := rawWorkerRecordForTest(t, s, rec.ID); !bytes.Equal(before, after) {
		t.Fatal("a pull without capabilities rewrote the worker record")
	}
}
