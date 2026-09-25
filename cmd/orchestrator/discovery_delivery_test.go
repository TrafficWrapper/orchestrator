package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// discoveryWorkerForTest adds an approved worker publishing both an AWG
// endpoint (with a preset) and REALITY with short IDs; peer is its key.
func discoveryWorkerForTest(t *testing.T, s *server) (workerRecord, []byte) {
	t.Helper()
	peer := bytes.Repeat([]byte{5}, 32)
	rec, err := s.store.upsertPendingWorker(protocol.KeyToBase64(peer), map[string]any{
		"egress_ip": "203.0.113.5",
		"reality": map[string]any{
			"address": "203.0.113.5", "port": 8444, "publicKey": testRealityPublicKey,
			"shortId": "abcd1234", "cohort_short_ids": []any{"beef0001", "beef0002"},
		},
		"awg": map[string]any{
			"endpoint": "203.0.113.5:51888", "port": 51888, "public_key": testAWGPublicKey,
			"subnet": "10.13.13.0/24", "awg_preset": map[string]any{"jc": 4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(rec.ID)
	return rec, peer
}

func discoveryEndpointsForTest(t *testing.T, jsonText string) (awg, reality []map[string]any) {
	t.Helper()
	var doc struct {
		Endpoints struct {
			AWG     []map[string]any `json:"awg"`
			Reality []map[string]any `json:"reality"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(jsonText), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Endpoints.AWG, doc.Endpoints.Reality
}

// X-M1/ORC-M20/X-M6: by default the feed carries only the AWG entry the app
// core needs, tagged with worker_id, and no REALITY material.
func TestDiscoveryReducedByDefault(t *testing.T) {
	s := newTestServer(t)
	w, _ := discoveryWorkerForTest(t, s)
	jsonText, err := s.discoveryBundleJSON(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	awg, reality := discoveryEndpointsForTest(t, jsonText)
	if reality == nil || len(reality) != 0 || !strings.Contains(jsonText, `"reality":[]`) {
		t.Fatalf("reality must be an empty list: %s", jsonText)
	}
	if len(awg) != 1 {
		t.Fatalf("awg=%v", awg)
	}
	var keys []string
	for k := range awg[0] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "awg_preset,egress_ip,endpoint,priority,server_public_key,worker_id" || awg[0]["worker_id"] != w.ID {
		t.Fatalf("awg entry: %v", awg[0])
	}
	for _, secret := range []string{"abcd1234", "beef0001", "beef0002", "shortId", "short_id"} {
		if strings.Contains(jsonText, secret) {
			t.Fatalf("reduced feed leaks %q", secret)
		}
	}
}

func TestDiscoveryFullModeTagsWorkerID(t *testing.T) {
	s := newTestServer(t)
	s.cfg.DiscoveryPublic = discoveryModeFull
	w, _ := discoveryWorkerForTest(t, s)
	jsonText, err := s.discoveryBundleJSON(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	awg, reality := discoveryEndpointsForTest(t, jsonText)
	if len(reality) != 1 || reality[0]["worker_id"] != w.ID || awg[0]["worker_id"] != w.ID {
		t.Fatalf("full feed: %s", jsonText)
	}
}

func TestParseDiscoveryMode(t *testing.T) {
	for in, want := range map[string]string{"": "reduced", "OFF": "off", " full ": "full", "reduced": "reduced"} {
		if got, err := parseDiscoveryMode(in); err != nil || got != want {
			t.Fatalf("%q: got %q err %v", in, got, err)
		}
	}
	if _, err := parseDiscoveryMode("public"); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

// X-M7: pull carries the same signed feed the public endpoint serves; in off
// mode only workers get it.
func TestPullCarriesDiscoveryBundle(t *testing.T) {
	s := newTestServer(t)
	pub := writeDiscoverySigningKeyForTest(t, s)
	w, peer := discoveryWorkerForTest(t, s)
	pull := func() pullResponse {
		t.Helper()
		raw, _ := json.Marshal(pullRequest{WorkerID: w.ID})
		resp, err := s.handlePull(peer, raw)
		if err != nil {
			t.Fatal(err)
		}
		out := resp.(pullResponse)
		out.releaseAfterWrite()
		return out
	}
	got := pull()
	if got.DiscoveryBundle == nil {
		t.Fatal("pull without discovery_bundle")
	}
	if !minisign.Verify(pub, []byte(got.DiscoveryBundle.EndpointsJSON), []byte(got.DiscoveryBundle.EndpointsJSONMinisig)) {
		t.Fatal("discovery_bundle signature does not verify")
	}
	public := discoveryJSONResponse(t, s, "198.51.100.7:1234").Body.String()
	if public != got.DiscoveryBundle.EndpointsJSON {
		t.Fatal("workers and the public endpoint must get the same feed")
	}
	raw, _ := json.Marshal(got)
	if !bytes.Contains(raw, []byte(`"discovery_bundle":{"endpoints_json":`)) {
		t.Fatalf("pull json: %s", raw)
	}

	s.cfg.DiscoveryPublic = discoveryModeOff
	for _, path := range []string{"/discovery/endpoints.json", "/discovery/endpoints.json.minisig"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if strings.HasSuffix(path, ".minisig") {
			s.handleDiscoveryEndpointsMinisig(rr, req)
		} else {
			s.handleDiscoveryEndpointsJSON(rr, req)
		}
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s in off mode: %d", path, rr.Code)
		}
	}
	if pull().DiscoveryBundle == nil {
		t.Fatal("off mode must still deliver the feed to workers")
	}
}

// X-M7: a new discovery seq bumps workers so they pull the feed; the feed is
// re-sent before it gets old.
func TestDiscoveryChangesBumpWorkers(t *testing.T) {
	s := newTestServer(t)
	writeDiscoverySigningKeyForTest(t, s)
	w, _ := discoveryWorkerForTest(t, s)
	now := time.Now().UTC()
	if bumped, err := s.publishDiscoveryToWorkers(now); err != nil || !bumped {
		t.Fatalf("first publish: bumped=%t err=%v", bumped, err)
	}
	before, _ := s.store.worker(w.ID)
	if bumped, err := s.publishDiscoveryToWorkers(now.Add(time.Minute)); err != nil || bumped {
		t.Fatalf("unchanged feed bumped workers: %t %v", bumped, err)
	}
	if _, err := s.bumpDiscoverySeq(); err != nil {
		t.Fatal(err)
	}
	if bumped, err := s.publishDiscoveryToWorkers(now.Add(2 * time.Minute)); err != nil || !bumped {
		t.Fatalf("new seq did not bump: %t %v", bumped, err)
	}
	if after, _ := s.store.worker(w.ID); after.DesiredSeq <= before.DesiredSeq {
		t.Fatal("worker seq not advanced")
	}
	if bumped, err := s.publishDiscoveryToWorkers(now.Add(2*time.Minute + discoveryReissueAfter)); err != nil || !bumped {
		t.Fatalf("aging feed not re-sent: %t %v", bumped, err)
	}
}

// ORC-L28: a snapshot built before an invalidation is never fresh, whatever
// order the build and the invalidation finish in.
func TestDiscoverySnapshotStaleAfterGenerationMoves(t *testing.T) {
	s := newTestServer(t)
	writeDiscoverySigningKeyForTest(t, s)
	discoveryWorkerForTest(t, s)
	if _, err := s.signedDiscoverySnapshot(); err != nil {
		t.Fatal(err)
	}
	revision := s.store.discoveryRevision()
	s.discoveryCacheMu.Lock()
	fresh := s.freshDiscoverySnapshotLocked(time.Now().UTC(), revision)
	s.discoveryCacheMu.Unlock()
	if fresh == nil {
		t.Fatal("fresh snapshot not served")
	}
	s.discoveryInvalidGen.Add(1)
	s.discoveryCacheMu.Lock()
	fresh = s.freshDiscoverySnapshotLocked(time.Now().UTC(), revision)
	s.discoveryCacheMu.Unlock()
	if fresh != nil {
		t.Fatal("snapshot from an older generation served as fresh")
	}
}
