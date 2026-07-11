package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aead.dev/minisign"
)

func TestDiscoveryHandlersCacheAndInvalidate(t *testing.T) {
	s := newTestServer(t)
	writeDiscoverySigningKeyForTest(t, s)
	addApprovedWorker(t, s)

	var firstJSON string
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json", nil)
		req.RemoteAddr = "198.51.100.10:1234"
		rr := httptest.NewRecorder()
		s.handleDiscoveryEndpointsJSON(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("cached discovery GET %d status=%d body=%s", i, rr.Code, rr.Body.String())
		}
		if i == 0 {
			firstJSON = rr.Body.String()
		} else if rr.Body.String() != firstJSON {
			t.Fatal("cache returned different JSON for unchanged worker set")
		}
		sigReq := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json.minisig", nil)
		sigReq.RemoteAddr = "198.51.100.10:1234"
		sigRR := httptest.NewRecorder()
		s.handleDiscoveryEndpointsMinisig(sigRR, sigReq)
		if sigRR.Code != http.StatusOK || sigRR.Body.Len() == 0 {
			t.Fatalf("cached discovery signature GET %d status=%d body=%s", i, sigRR.Code, sigRR.Body.String())
		}
	}
	if builds := s.discoveryBuilds.Load(); builds != 1 {
		t.Fatalf("discovery generations=%d want 1", builds)
	}

	if _, err := s.bumpDiscoverySeq(); err != nil {
		t.Fatal(err)
	}
	bumpedJSON := discoveryJSONViaHandler(t, s)
	if builds := s.discoveryBuilds.Load(); builds != 2 {
		t.Fatalf("discovery generations after bump=%d want 2", builds)
	}
	if discoverySeqFromText(t, bumpedJSON) <= discoverySeqFromText(t, firstJSON) {
		t.Fatal("admin bump did not advance cached discovery seq")
	}

	workers, err := s.store.workers()
	if err != nil || len(workers) != 1 {
		t.Fatalf("workers=%d err=%v", len(workers), err)
	}
	self := workers[0].SelfDescribe
	self["egress_ip"] = "203.0.113.99"
	if err := s.store.updateWorkerSelfDescribe(workers[0].ID, self); err != nil {
		t.Fatal(err)
	}
	changedJSON := discoveryJSONViaHandler(t, s)
	if builds := s.discoveryBuilds.Load(); builds != 3 {
		t.Fatalf("discovery generations after worker change=%d want 3", builds)
	}
	if changedJSON == bumpedJSON {
		t.Fatal("worker endpoint change did not invalidate discovery cache")
	}

	s.discoveryCacheMu.Lock()
	s.discoveryCache.GeneratedAt = time.Now().UTC().Add(-discoveryBundleCacheTTL)
	s.discoveryCacheMu.Unlock()
	_ = discoveryJSONViaHandler(t, s)
	if builds := s.discoveryBuilds.Load(); builds != 4 {
		t.Fatalf("discovery generations after TTL=%d want 4", builds)
	}
}

func TestDiscoveryEndpointRateLimitIsBounded(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	key := rateLimitKey("198.51.100.20")
	for i := 0; i < discoveryRateLimit; i++ {
		if !s.reserveDiscoveryRequestForKey(key, discoveryRateAssetJSON, now) {
			t.Fatalf("request %d rejected before limit", i)
		}
	}
	if s.reserveDiscoveryRequestForKey(key, discoveryRateAssetJSON, now) {
		t.Fatal("request above discovery rate limit accepted")
	}
	if !s.reserveDiscoveryRequestForKey(key, discoveryRateAssetMinisig, now) {
		t.Fatal("JSON flood incorrectly exhausted the minisig bucket")
	}
	req := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json", nil)
	req.RemoteAddr = "198.51.100.20:4321"
	rr := httptest.NewRecorder()
	s.handleDiscoveryEndpointsJSON(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited handler status=%d want 429", rr.Code)
	}

	for i := 0; i < maxDiscoveryRateKeys+100; i++ {
		floodKey := rateLimitKey(fmt.Sprintf("2001:db8:%x:%x::1", i/0x10000, i%0x10000))
		if !s.reserveDiscoveryRequestForKey(floodKey, discoveryRateAssetJSON, now) {
			t.Fatalf("new discovery key rejected at cap: %s", floodKey)
		}
	}
	s.discoveryRateMu.Lock()
	got := len(s.discoveryRates)
	s.discoveryRateMu.Unlock()
	if got != maxDiscoveryRateKeys {
		t.Fatalf("discovery rate keys=%d want cap %d", got, maxDiscoveryRateKeys)
	}
}

func TestDiscoveryRateLimitAllowsCGNATBootstrapPairs(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	key := rateLimitKey("198.51.100.21")
	const clients = 1000
	for i := 0; i < clients; i++ {
		if !s.reserveDiscoveryRequestForKey(key, discoveryRateAssetJSON, now) {
			t.Fatalf("CGNAT client %d JSON fetch rejected", i)
		}
		if !s.reserveDiscoveryRequestForKey(key, discoveryRateAssetMinisig, now) {
			t.Fatalf("CGNAT client %d minisig fetch rejected", i)
		}
	}
	for i := clients; i < discoveryRateLimit; i++ {
		if !s.reserveDiscoveryRequestForKey(key, discoveryRateAssetJSON, now) ||
			!s.reserveDiscoveryRequestForKey(key, discoveryRateAssetMinisig, now) {
			t.Fatalf("bootstrap pair %d rejected before logical limit", i)
		}
	}
	if s.reserveDiscoveryRequestForKey(key, discoveryRateAssetJSON, now) {
		t.Fatal("extreme JSON flood above logical limit accepted")
	}
	if s.reserveDiscoveryRequestForKey(key, discoveryRateAssetMinisig, now) {
		t.Fatal("extreme minisig flood above logical limit accepted")
	}
	s.discoveryRateMu.Lock()
	got := len(s.discoveryRates)
	s.discoveryRateMu.Unlock()
	if got != 1 {
		t.Fatalf("JSON+minisig pair used %d source-map entries want 1", got)
	}
}

func TestSignedDiscoveryBundleUsesUpdateKey(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.cfg.UpdatePublicKey = mustText(pub)
	privText, err := priv.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.StateDir, "update.key"), privText, 0o600); err != nil {
		t.Fatal(err)
	}
	addApprovedWorker(t, s)

	jsonText, minisigText, pubText, err := s.signedDiscoveryBundle()
	if err != nil {
		t.Fatal(err)
	}
	if pubText != mustText(pub) {
		t.Fatalf("pubkey=%q want %q", pubText, mustText(pub))
	}
	if !minisign.Verify(pub, []byte(jsonText), []byte(minisigText)) {
		t.Fatal("discovery bundle minisign verification failed")
	}
	if err := rejectForbiddenKeys([]byte(jsonText)); err != nil {
		t.Fatalf("discovery bundle contains forbidden keys: %v", err)
	}
	var root struct {
		Schema    int    `json:"schema"`
		Namespace string `json:"ns"`
		Endpoints struct {
			Reality []map[string]any `json:"reality"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	if root.Schema != 2 || root.Namespace != "rendezvous-v1" {
		t.Fatalf("bad discovery root: %+v", root)
	}
	if len(root.Endpoints.Reality) != 1 {
		t.Fatalf("reality endpoints=%d want 1", len(root.Endpoints.Reality))
	}

	bundle, err := s.buildClientBundleForClient(0, "0.1.18")
	if err != nil {
		t.Fatal(err)
	}
	var clientRoot struct {
		DiscoveryPubkey string `json:"discovery_pubkey"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &clientRoot); err != nil {
		t.Fatal(err)
	}
	if clientRoot.DiscoveryPubkey != mustText(pub) {
		t.Fatalf("discovery_pubkey=%q want %q", clientRoot.DiscoveryPubkey, mustText(pub))
	}
}

func TestDiscoveryBundleNextSinksAndClientRescuePointersAreOptional(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	s.cfg.DiscoveryNextSinks = []string{"https://operator.example/discovery", "https://operator.example/discovery", ""}
	s.cfg.DiscoveryRescuePointers = []string{"https://operator.example/rescue-pointer.json"}

	jsonText, err := s.discoveryBundleJSON(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		NextSinks []string `json:"next_sinks"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	if len(root.NextSinks) != 1 || root.NextSinks[0] != "https://operator.example/discovery" {
		t.Fatalf("next_sinks=%v", root.NextSinks)
	}

	bundle, err := s.buildClientBundleForClient(0, "0.1.25")
	if err != nil {
		t.Fatal(err)
	}
	var clientRoot struct {
		RescuePointers []string `json:"discovery_rescue_pointers"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &clientRoot); err != nil {
		t.Fatal(err)
	}
	if len(clientRoot.RescuePointers) != 1 || clientRoot.RescuePointers[0] != "https://operator.example/rescue-pointer.json" {
		t.Fatalf("rescue pointers=%v", clientRoot.RescuePointers)
	}
}

func TestDiscoveryAWGEndpointCarriesEgressIP(t *testing.T) {
	route, ok := discoveryAWGEndpoint(workerRecord{
		SelfDescribe: map[string]any{
			"egress_ip": "198.51.100.44",
			"awg": map[string]any{
				"endpoint":   "worker.example:51821",
				"public_key": "awg-server-pub",
				"awg_preset": map[string]any{"jc": 4},
			},
		},
	})
	if !ok {
		t.Fatal("awg discovery route was not built")
	}
	if route["endpoint"] != "worker.example:51821" {
		t.Fatalf("endpoint=%#v", route["endpoint"])
	}
	if route["egress_ip"] != "198.51.100.44" {
		t.Fatalf("egress_ip=%#v", route["egress_ip"])
	}

	route, ok = discoveryAWGEndpoint(workerRecord{
		EgressIPObserved: "198.51.100.45",
		SelfDescribe: map[string]any{
			"awg": map[string]any{
				"endpoint":   "worker.example:51821",
				"public_key": "awg-server-pub",
				"awg_preset": map[string]any{"jc": 4},
			},
		},
	})
	if !ok {
		t.Fatal("awg discovery route with observed egress was not built")
	}
	if route["egress_ip"] != "198.51.100.45" {
		t.Fatalf("observed egress_ip=%#v", route["egress_ip"])
	}
}

func TestDiscoverySeqBumpPersistsAboveWorkerFloor(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)

	seq, err := s.bumpDiscoverySeq()
	if err != nil {
		t.Fatal(err)
	}
	if seq < 2 {
		t.Fatalf("bumped seq=%d want >=2", seq)
	}
	jsonText, err := s.discoveryBundleJSON(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	if root.Seq != seq {
		t.Fatalf("bundle seq=%d want bumped seq=%d", root.Seq, seq)
	}
}

func TestDiscoverySeqIsMonotonicAcrossEndpointChangesAndRestart(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "worker-static-a")
	now := time.Now().UTC()

	seq1 := discoverySeqFromJSON(t, s, now)
	seqAgain := discoverySeqFromJSON(t, s, now.Add(time.Minute))
	if seqAgain != seq1 {
		t.Fatalf("stable endpoints changed seq: first=%d second=%d", seq1, seqAgain)
	}

	addApprovedDiscoveryWorker(t, s, "worker-static-b", "203.0.113.6")
	seq2 := discoverySeqFromJSON(t, s, now.Add(2*time.Minute))
	if seq2 <= seq1 {
		t.Fatalf("endpoint add did not advance seq: before=%d after=%d", seq1, seq2)
	}

	if n, err := s.store.markStaleWorkersInactive(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("expected workers to be marked inactive")
	}
	seq3 := discoverySeqFromJSON(t, s, now.Add(3*time.Minute))
	if seq3 <= seq2 {
		t.Fatalf("endpoint removal did not advance seq monotonically: before=%d after=%d", seq2, seq3)
	}

	restarted := &server{cfg: s.cfg, store: s.store}
	seq4 := discoverySeqFromJSON(t, restarted, now.Add(4*time.Minute))
	if seq4 != seq3 {
		t.Fatalf("restart changed stable discovery seq: before=%d after=%d", seq3, seq4)
	}
}

func discoverySeqFromJSON(t *testing.T, s *server, now time.Time) int64 {
	t.Helper()
	jsonText, err := s.discoveryBundleJSON(now)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	return root.Seq
}

func addApprovedDiscoveryWorker(t *testing.T, s *server, staticPub string, address string) {
	t.Helper()
	rec, err := s.store.upsertPendingWorker(staticPub, map[string]any{
		"label":     "Worker " + address,
		"egress_ip": address,
		"reality": map[string]any{
			"address":   address,
			"port":      8444,
			"publicKey": "pub-" + address,
			"shortId":   "sid",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
}

func writeDiscoverySigningKeyForTest(t *testing.T, s *server) minisign.PublicKey {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.UpdatePublicKey = mustText(pub)
	privText, err := priv.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.StateDir, "update.key"), privText, 0o600); err != nil {
		t.Fatal(err)
	}
	return pub
}

func discoveryJSONViaHandler(t *testing.T, s *server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json", nil)
	req.RemoteAddr = "198.51.100.30:1234"
	rr := httptest.NewRecorder()
	s.handleDiscoveryEndpointsJSON(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("discovery status=%d body=%s", rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

func discoverySeqFromText(t *testing.T, jsonText string) int64 {
	t.Helper()
	var root struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	return root.Seq
}
