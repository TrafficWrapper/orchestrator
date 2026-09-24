package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func enrollWithCapabilities(t *testing.T, s *server, token string, caps []string) deviceEnrollResponse {
	t.Helper()
	raw, _ := json.Marshal(deviceEnrollRequest{
		BootstrapToken: token, IdentityPubKey: "identity-pub", IdentityKeyType: "ed25519",
		ClientVersion: "0.2.0", AWGPublicKey: "awg-dev", Capabilities: caps,
	})
	resp, err := s.handleDeviceEnroll(make([]byte, 32), raw)
	if err != nil {
		t.Fatal(err)
	}
	out := resp.(deviceEnrollResponse)
	if !out.OK {
		t.Fatalf("enroll failed: %s", out.Error)
	}
	return out
}

func workerConfigForTest(t *testing.T, s *server, workerID string) map[string]any {
	t.Helper()
	rec, err := s.store.worker(workerID)
	if err != nil {
		t.Fatal(err)
	}
	wb, _, err := s.buildBundles(rec)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(wb.ConfigJSON), &doc); err != nil {
		t.Fatal(err)
	}
	return doc["desired_state"].(map[string]any)
}

func TestVisionFlowNegotiatedAtEnrollment(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "vision-worker")
	if _, err := s.store.createBootstrapToken("boot-v", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollWithCapabilities(t, s, "boot-v", []string{"reality_vision"})
	if resp.RealityFlow != realityFlowVision {
		t.Fatalf("enroll response flow=%q", resp.RealityFlow)
	}
	state := workerConfigForTest(t, s, w.ID)
	devices := state["approved_devices"].([]any)
	if len(devices) != 1 || devices[0].(map[string]any)["reality_flow"] != realityFlowVision {
		t.Fatalf("worker config must carry the device's flow: %v", devices)
	}
	// Re-enrolling without the capability (older app) must drop Vision.
	again := enrollWithCapabilities(t, s, "boot-v", nil)
	if again.RealityFlow != "" {
		t.Fatalf("re-enroll without capability kept flow %q", again.RealityFlow)
	}
	state = workerConfigForTest(t, s, w.ID)
	if flow, ok := state["approved_devices"].([]any)[0].(map[string]any)["reality_flow"]; ok {
		t.Fatalf("flow must be cleared in worker config, got %v", flow)
	}
	// The shared client bundle never carries a flow.
	bundle, err := s.buildClientBundle(0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bundle.ConfigJSON, realityFlowVision) {
		t.Fatal("client bundle must not contain a per-device flow")
	}
}

func TestShortIDRevocationKeepsCohortSlots(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "cohort-worker")
	cohorts := []any{"c0", "c1", "c2", "c3"}
	if _, err := s.store.upsertPendingWorker("cohort-worker", map[string]any{
		"egress_ip": "203.0.113.5",
		"reality":   map[string]any{"address": "203.0.113.5", "port": 8444, "publicKey": "pub", "shortId": "sid", "cohort_short_ids": cohorts},
	}); err != nil {
		t.Fatal(err)
	}
	revoked := true
	if err := s.store.updateWorkerPolicy(w.ID, workerPolicyPatch{ShortID: "c1", ShortIDRevoked: &revoked}); err != nil {
		t.Fatal(err)
	}
	state := workerConfigForTest(t, s, w.ID)
	if got := state["revoked_short_ids"].([]any); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("revoked_short_ids=%v", got)
	}
	rec, _ := s.store.worker(w.ID)
	if got := clientCohortShortIDs(rec); strings.Join(got, ",") != "c0,,c2,c3" {
		t.Fatalf("cohort slots must keep positions with revoked blanked: %v", got)
	}
	for _, id := range []string{"dev-a", "dev-b", "dev-c"} {
		if idx := realityCohortIndex(id, 16); idx < 0 || idx >= 16 || idx != realityCohortIndex(id, 16) {
			t.Fatalf("cohort index %d out of range or unstable", idx)
		}
	}
}

func TestRateMbpsDerivedFromRateLimit(t *testing.T) {
	cases := map[string]float64{"20mbit": 20, "512kbit": 0.512, "1gbit": 1000, "50mbps": 50}
	for in, want := range cases {
		if got, ok := rateMbpsFromLimit(in); !ok || got != want {
			t.Fatalf("%s -> %v %t", in, got, ok)
		}
	}
	if _, ok := rateMbpsFromLimit("fast"); ok {
		t.Fatal("unparseable rate must be skipped")
	}
	payload := deviceLimitsPayload(deviceLimits{RateLimit: "20mbit", TrafficQuotaBytes: 5})
	if payload["download_mbps"] != 20 || payload["upload_mbps"] != 20 || payload["traffic_quota_bytes"] != uint64(5) {
		t.Fatalf("limits payload=%v", payload)
	}
	// Sub-megabit limits must not round to 0, which the worker treats as unlimited.
	if got := deviceLimitsPayload(deviceLimits{RateLimit: "512kbit"})["download_mbps"]; got != 1 {
		t.Fatalf("512kbit -> %v, want 1", got)
	}
	if got := workerRateMbps(1e9); got != maxWorkerRateMbps {
		t.Fatalf("clamp -> %d", got)
	}
}

func TestAWGProfileRouteInheritsWorkerIPv6AndDNS(t *testing.T) {
	route := map[string]any{"params": map[string]any{}}
	inheritAWGWorkerFields(route, map[string]any{"endpoint_v6": "[2001:db8::1]:51888", "dns": []any{"10.13.13.1"}})
	params := route["params"].(map[string]any)
	if route["endpoint_v6"] != "[2001:db8::1]:51888" || params["endpoint_v6"] != "[2001:db8::1]:51888" {
		t.Fatalf("endpoint_v6 not inherited: %v", route)
	}
	if dns, _ := params["dns"].([]any); len(dns) != 1 {
		t.Fatalf("dns not inherited: %v", route)
	}
}

func TestAWGProfileDrainingHidesProfileFromClients(t *testing.T) {
	rec := workerRecord{SelfDescribe: map[string]any{
		"awg":          map[string]any{"endpoint": "w:51888", "public_key": "k1", "profile": "awg"},
		"awg_profiles": []any{map[string]any{"endpoint": "w:51999", "public_key": "k2", "profile": "awg-new"}},
	}}
	if len(awgProfilesForClients(rec)) != 2 {
		t.Fatal("no draining: both profiles offered")
	}
	rec.DrainingAWGProfiles = []string{"awg"}
	got := awgProfilesForClients(rec)
	if len(got) != 1 || got[0].Name != "awg-new" {
		t.Fatalf("draining profile still offered: %+v", got)
	}
	rec.DrainingAWGProfiles = []string{"awg", "awg-new"}
	if len(awgProfilesForClients(rec)) != 2 {
		t.Fatal("draining everything must fall back to all profiles")
	}
}

func TestWorkerSelfCheckStoredAndAlerted(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "health-worker")
	rec, _ := s.store.worker(w.ID)
	if _, _, err := s.store.recordAck(w.ID, rec.DesiredSeq, "degraded: camouflage,reality", "", nil, nil, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	entry, ok := botWorkerProblemEntry(rec, time.Now().UTC())
	if !ok || entry.Kind != "worker_degraded" || !strings.Contains(entry.Detail, "camouflage,reality") {
		t.Fatalf("degraded worker not alerted: %+v ok=%t", entry, ok)
	}
	if _, _, err := s.store.recordAck(w.ID, rec.DesiredSeq, "ok", "", nil, nil, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	if _, ok := botWorkerProblemEntry(rec, time.Now().UTC()); ok {
		t.Fatal("healthy worker must not be alerted")
	}
}

func TestWorkerWithSlowAckStaysFreshViaHeartbeat(t *testing.T) {
	// Workers ack every ORCH_ACK_INTERVAL (90s) but nudge continuously; the
	// nudge heartbeat keeps LastAckAt within the freshness window.
	now := time.Now().UTC()
	seen := now.Add(-(heartbeatWriteInterval + 25*time.Second))
	rec := workerRecord{ID: "w", Status: "active", LastAckAt: &seen}
	if !workerFreshForClients(rec, now) {
		t.Fatal("worker within the heartbeat write interval must stay fresh")
	}
	if _, ok := botWorkerProblemEntry(rec, now); ok {
		t.Fatal("worker within the heartbeat write interval must not be reported down")
	}
}

func TestRealityFallbackRoutesAreOptInAndFlowless(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "fallback-worker")
	if _, err := s.store.upsertPendingWorker("fallback-worker", map[string]any{
		"egress_ip": "203.0.113.5",
		"reality":   map[string]any{"address": "203.0.113.5", "port": 443, "publicKey": "pub", "shortId": "sid", "network": "tcp"},
		"reality_profiles": []any{
			map[string]any{"name": "base", "address": "203.0.113.5", "port": 443, "network": "tcp", "public_key": "pub", "short_id": "sid", "flows": []any{"", realityFlowVision}},
			map[string]any{"name": "xh", "address": "203.0.113.5", "port": 8443, "network": "xhttp", "public_key": "pub", "short_id": "sid", "flows": []any{""}, "xhttp": map[string]any{"path": "/x", "mode": "auto"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.store.worker(w.ID)
	item, _ := s.clientWorkerPayloadForClient(rec, "")
	if n := len(item["routes"].([]any)); n != 1 {
		t.Fatalf("fallback routes must be off by default, routes=%d", n)
	}
	s.cfg.RealityFallbackProfiles = true
	item, _ = s.clientWorkerPayloadForClient(rec, "")
	routes := item["routes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("want primary + xhttp fallback, got %d", len(routes))
	}
	fb := routes[1].(map[string]any)
	if intFromMap(fb, "port", 0) != 8443 || fb["network"] != "xhttp" || fb["flow"] != nil || fb["flows"] != nil {
		t.Fatalf("bad fallback route: %v", fb)
	}
}
