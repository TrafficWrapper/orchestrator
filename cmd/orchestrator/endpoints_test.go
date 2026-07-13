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
	s.discoveryCache.Current.GeneratedAt = time.Now().UTC().Add(-discoveryBundleCacheTTL)
	s.discoveryCacheMu.Unlock()
	_ = discoveryJSONViaHandler(t, s)
	if builds := s.discoveryBuilds.Load(); builds != 4 {
		t.Fatalf("discovery generations after TTL=%d want 4", builds)
	}
}

func TestDiscoveryPairRemainsVerifiableAcrossCacheRebuild(t *testing.T) {
	for _, test := range []struct {
		name       string
		invalidate func(*testing.T, *server)
	}{
		{
			name: "ttl",
			invalidate: func(t *testing.T, s *server) {
				t.Helper()
				s.discoveryCacheMu.Lock()
				s.discoveryCache.Current.GeneratedAt = time.Now().UTC().Add(-discoveryBundleCacheTTL)
				s.discoveryCacheMu.Unlock()
				time.Sleep(1100 * time.Millisecond)
			},
		},
		{
			name: "worker_revision",
			invalidate: func(t *testing.T, s *server) {
				t.Helper()
				workers, err := s.store.workers()
				if err != nil || len(workers) != 1 {
					t.Fatalf("workers=%d err=%v", len(workers), err)
				}
				self := workers[0].SelfDescribe
				self["egress_ip"] = "203.0.113.199"
				if err := s.store.updateWorkerSelfDescribe(workers[0].ID, self); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t)
			pub := writeDiscoverySigningKeyForTest(t, s)
			addApprovedWorker(t, s)

			jsonRR := discoveryJSONResponse(t, s, "198.51.100.40:1234")
			firstJSON := jsonRR.Body.String()
			firstETag := jsonRR.Header().Get("ETag")
			if firstETag == "" {
				t.Fatal("discovery JSON did not expose an ETag revision")
			}
			test.invalidate(t, s)
			changedJSON := discoveryPairViaHandlers(t, s, "198.51.100.41:1234")
			if changedJSON == firstJSON {
				t.Fatal("cache rebuild did not produce a new discovery revision")
			}

			sigRR := discoveryMinisigResponse(t, s, "198.51.100.40:1234", "")
			if sigRR.Code != http.StatusOK {
				t.Fatalf("paired minisig status=%d body=%s", sigRR.Code, sigRR.Body.String())
			}
			if sigRR.Header().Get("ETag") != firstETag {
				t.Fatalf("paired ETag=%q want %q", sigRR.Header().Get("ETag"), firstETag)
			}
			if !minisign.Verify(pub, []byte(firstJSON), sigRR.Body.Bytes()) {
				t.Fatal("minisig after cache rebuild did not verify the original JSON")
			}

			versionedSigRR := discoveryMinisigResponse(t, s, "198.51.100.42:1234", firstETag)
			if versionedSigRR.Code != http.StatusOK ||
				!minisign.Verify(pub, []byte(firstJSON), versionedSigRR.Body.Bytes()) {
				t.Fatalf("versioned minisig status=%d body=%s", versionedSigRR.Code, versionedSigRR.Body.String())
			}
		})
	}
}

func TestDiscoveryRateLimitAllowsCGNATBootstrapPairs(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	key := discoveryRateKey("198.51.100.21")
	bundle := discoverySnapshotForRateTest("cgnat")
	for i := 0; i < discoveryRateLimit; i++ {
		served, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, now)
		if !ok || served != bundle {
			t.Fatalf("bootstrap pair %d JSON rejected", i)
		}
		served, _, ok, matches := s.reserveDiscoveryMinisigForKey(key, "", now)
		if !ok || !matches || served != bundle {
			t.Fatalf("bootstrap pair %d minisig rejected", i)
		}
	}
	if _, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, now); ok {
		t.Fatal("JSON above the 1200-pair limit accepted")
	}
	if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(key, "", now); ok {
		t.Fatal("minisig-only request above the 1200-pair limit accepted")
	}
	s.discoveryRateMu.Lock()
	got := len(s.discoveryRates)
	s.discoveryRateMu.Unlock()
	if got != 1 {
		t.Fatalf("JSON+minisig pairs used %d source-map entries want 1", got)
	}
}

func TestDiscoveryHandlerRateLimitKeepsPairAtomic(t *testing.T) {
	s := newTestServer(t)
	writeDiscoverySigningKeyForTest(t, s)
	addApprovedWorker(t, s)
	if _, err := s.signedDiscoverySnapshot(); err != nil {
		t.Fatal(err)
	}
	const remoteAddr = "198.51.100.43:1234"
	key := discoveryRateKey("198.51.100.43")
	s.discoveryRates = map[string]discoveryRequestRate{
		key: {
			WindowStart: time.Now().Add(-58 * time.Second),
			PairCount:   discoveryRateLimit - 1,
		},
	}

	jsonRR := discoveryJSONResponse(t, s, remoteAddr)
	sigRR := discoveryMinisigResponse(t, s, remoteAddr, jsonRR.Header().Get("ETag"))
	if sigRR.Code != http.StatusOK {
		t.Fatalf("minisig for accepted final pair status=%d body=%s", sigRR.Code, sigRR.Body.String())
	}

	nextJSON := httptest.NewRecorder()
	nextJSONRequest := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json", nil)
	nextJSONRequest.RemoteAddr = remoteAddr
	s.handleDiscoveryEndpointsJSON(nextJSON, nextJSONRequest)
	if nextJSON.Code != http.StatusTooManyRequests {
		t.Fatalf("JSON beyond pair limit status=%d want 429", nextJSON.Code)
	}
	nextMinisig := discoveryMinisigResponse(t, s, remoteAddr, "")
	if nextMinisig.Code != http.StatusTooManyRequests {
		t.Fatalf("minisig-only beyond pair limit status=%d want 429", nextMinisig.Code)
	}
	if retryAfter := nextJSON.Header().Get("Retry-After"); retryAfter != "1" && retryAfter != "2" {
		t.Fatalf("dynamic Retry-After=%q want remaining 1-2 seconds", retryAfter)
	}
}

func TestDiscoveryMinisigOnlyConsumesPairBudget(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	key := discoveryRateKey("198.51.100.22")
	for i := 0; i < discoveryRateLimit; i++ {
		if _, _, ok, matches := s.reserveDiscoveryMinisigForKey(key, "", now); !ok || !matches {
			t.Fatalf("minisig-only request %d rejected before limit", i)
		}
	}
	if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(key, "", now); ok {
		t.Fatal("minisig-only flood bypassed the pair limit")
	}
}

func TestDiscoveryRateLimitResetsAfterClockRollback(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	key := discoveryRateKey("198.51.100.23")
	bundle := discoverySnapshotForRateTest("clock")
	for i := 0; i < discoveryRateLimit; i++ {
		if _, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, now); !ok {
			t.Fatalf("pair %d rejected before limit", i)
		}
		if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(key, "", now); !ok {
			t.Fatalf("pair %d minisig rejected before limit", i)
		}
	}
	rolledBack := now.Add(-5 * time.Minute)
	if _, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, rolledBack); !ok {
		t.Fatal("clock rollback left the source frozen at its old limit")
	}
}

func TestDiscoveryRetryAfterUsesRemainingWindow(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	key := discoveryRateKey("198.51.100.24")
	bundle := discoverySnapshotForRateTest("retry")
	for i := 0; i < discoveryRateLimit; i++ {
		if _, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, now); !ok {
			t.Fatalf("pair %d rejected before limit", i)
		}
		if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(key, "", now); !ok {
			t.Fatalf("pair %d minisig rejected before limit", i)
		}
	}
	_, retryAfter, ok := s.reserveDiscoveryJSONForKey(
		key,
		bundle,
		now.Add(discoveryRateWindow-500*time.Millisecond),
	)
	if ok {
		t.Fatal("request above limit was accepted")
	}
	if retryAfter != 1 {
		t.Fatalf("Retry-After=%d want ceil 1", retryAfter)
	}
}

func TestDiscoveryIPv6RateKeyAggregatesWithin48(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	bundle := discoverySnapshotForRateTest("ipv6")
	firstKey := discoveryRateKey("2001:db8:1234:1::1")
	lastKey := discoveryRateKey("2001:db8:1234:ffff::1")
	if firstKey != lastKey || firstKey != "2001:db8:1234::/48" {
		t.Fatalf("IPv6 discovery keys differ: first=%q last=%q", firstKey, lastKey)
	}
	for i := 0; i < discoveryRateLimit; i++ {
		key := discoveryRateKey(fmt.Sprintf("2001:db8:1234:%x::1", i))
		if _, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, now); !ok {
			t.Fatalf("IPv6 pair %d rejected before limit", i)
		}
		if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(key, "", now); !ok {
			t.Fatalf("IPv6 pair %d minisig rejected before limit", i)
		}
	}
	if _, _, ok := s.reserveDiscoveryJSONForKey(lastKey, bundle, now); ok {
		t.Fatal("rotating /64 addresses inside one /48 bypassed the pair limit")
	}
	if got := len(s.discoveryRates); got != 1 {
		t.Fatalf("one IPv6 /48 created %d rate keys", got)
	}
}

func TestDiscoveryRateMapDoesNotEvictLiveCountersAtCapacity(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	bundle := discoverySnapshotForRateTest("capacity")
	legitimateKey := discoveryRateKey("198.51.100.25")
	for i := 0; i < discoveryRateLimit-1; i++ {
		if _, _, ok := s.reserveDiscoveryJSONForKey(legitimateKey, bundle, now); !ok {
			t.Fatalf("legitimate pair %d rejected", i)
		}
		if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(legitimateKey, "", now); !ok {
			t.Fatalf("legitimate pair %d minisig rejected", i)
		}
	}
	for i := 0; i < maxDiscoveryRateKeys-1; i++ {
		key := discoveryRateKey(fmt.Sprintf("198.18.%d.%d", i/256, i%256))
		if _, _, ok := s.reserveDiscoveryJSONForKey(key, bundle, now); !ok {
			t.Fatalf("fill key %d rejected before map capacity", i)
		}
		if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(key, "", now); !ok {
			t.Fatalf("fill key %d minisig rejected before map capacity", i)
		}
	}
	if got := len(s.discoveryRates); got != maxDiscoveryRateKeys {
		t.Fatalf("discovery rate keys=%d want cap %d", got, maxDiscoveryRateKeys)
	}
	newKey := discoveryRateKey("203.0.113.250")
	if _, _, ok := s.reserveDiscoveryJSONForKey(newKey, bundle, now); ok {
		t.Fatal("new key displaced a live rate entry at capacity")
	}
	if _, _, ok := s.reserveDiscoveryJSONForKey(legitimateKey, bundle, now); !ok {
		t.Fatal("legitimate counter was evicted while filling the map")
	}
	if _, _, ok, _ := s.reserveDiscoveryMinisigForKey(legitimateKey, "", now); !ok {
		t.Fatal("paired minisig was rejected at the exact limit")
	}
	if _, _, ok := s.reserveDiscoveryJSONForKey(legitimateKey, bundle, now); ok {
		t.Fatal("legitimate source counter was reset by map pressure")
	}
}

func TestDiscoveryRateMapPrunesExpiredEntriesAtCapacity(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	s.discoveryRates = make(map[string]discoveryRequestRate, maxDiscoveryRateKeys)
	for i := 0; i < maxDiscoveryRateKeys; i++ {
		key := discoveryRateKey(fmt.Sprintf("198.19.%d.%d", i/256, i%256))
		s.discoveryRates[key] = discoveryRequestRate{
			WindowStart: now.Add(-2 * discoveryRateWindow),
			PairCount:   discoveryRateLimit,
		}
	}
	newKey := discoveryRateKey("203.0.113.251")
	if _, _, ok := s.reserveDiscoveryJSONForKey(newKey, discoverySnapshotForRateTest("reused"), now); !ok {
		t.Fatal("expired entries prevented a new source from using bounded capacity")
	}
	if got := len(s.discoveryRates); got != 1 {
		t.Fatalf("expired rate entries were not pruned: got=%d want 1", got)
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
	return discoveryPairViaHandlers(t, s, "198.51.100.30:1234")
}

func discoveryPairViaHandlers(t *testing.T, s *server, remoteAddr string) string {
	t.Helper()
	jsonRR := discoveryJSONResponse(t, s, remoteAddr)
	sigRR := discoveryMinisigResponse(t, s, remoteAddr, jsonRR.Header().Get("ETag"))
	if sigRR.Code != http.StatusOK {
		t.Fatalf("discovery minisig status=%d body=%s", sigRR.Code, sigRR.Body.String())
	}
	if sigRR.Header().Get("ETag") != jsonRR.Header().Get("ETag") {
		t.Fatalf("discovery pair ETag mismatch: json=%q minisig=%q", jsonRR.Header().Get("ETag"), sigRR.Header().Get("ETag"))
	}
	return jsonRR.Body.String()
}

func discoveryJSONResponse(t *testing.T, s *server, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json", nil)
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	s.handleDiscoveryEndpointsJSON(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("discovery status=%d body=%s", rr.Code, rr.Body.String())
	}
	return rr
}

func discoveryMinisigResponse(
	t *testing.T,
	s *server,
	remoteAddr string,
	etag string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/discovery/endpoints.json.minisig", nil)
	req.RemoteAddr = remoteAddr
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	rr := httptest.NewRecorder()
	s.handleDiscoveryEndpointsMinisig(rr, req)
	return rr
}

func discoverySnapshotForRateTest(revision string) string {
	return revision
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
