package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func enrollWithCapabilities(t *testing.T, s *server, token string, caps []string) deviceEnrollResponse {
	t.Helper()
	return enrollVersionWithCapabilities(t, s, token, "0.2.0", caps)
}

func enrollVersionWithCapabilities(t *testing.T, s *server, token, version string, caps []string) deviceEnrollResponse {
	t.Helper()
	raw, _ := json.Marshal(deviceEnrollRequest{
		BootstrapToken: token, IdentityPubKey: "identity-pub", IdentityKeyType: "ed25519",
		ClientVersion: version, AWGPublicKey: "awg-dev", Capabilities: caps,
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
	// Re-enrolling after an upgrade records the new version for AWG profile
	// selection; an empty version keeps the stored one.
	enrollVersionWithCapabilities(t, s, "boot-v", "0.3.0", nil)
	if dev, _ := s.store.device(again.DeviceID); dev.ClientVersion != "0.3.0" {
		t.Fatalf("re-enroll must store the new client version, got %q", dev.ClientVersion)
	}
	enrollVersionWithCapabilities(t, s, "boot-v", "", nil)
	if dev, _ := s.store.device(again.DeviceID); dev.ClientVersion != "0.3.0" {
		t.Fatalf("empty version must keep the stored one, got %q", dev.ClientVersion)
	}
	// The shared client bundle never carries a flow.
	bundle, err := s.buildClientBundle()
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

// X-M4: the primary AWG route is the base profile; other, non-drained
// profiles are nested alternatives. Only a base drained before this rule
// keeps the old behaviour (first remaining profile as primary).
func TestAWGPrimaryIsBaseWithNestedAlternatives(t *testing.T) {
	rec := workerRecord{SelfDescribe: map[string]any{
		"awg":          map[string]any{"endpoint": "w:51888", "public_key": "k1", "profile": "awg"},
		"awg_profiles": []any{map[string]any{"endpoint": "w:51999", "public_key": "k2", "profile": "awg-new", "min_version_code": 131}},
	}}
	primary, ok := awgPrimaryProfile(rec)
	if !ok || primary.Name != "awg" {
		t.Fatalf("primary=%+v", primary)
	}
	nested := nestedAWGProfiles(rec, primary.Name)
	if len(nested) != 1 || nested[0].(map[string]any)["profile"] != "awg-new" || nested[0].(map[string]any)["min_version_code"] != 131 {
		t.Fatalf("nested=%v", nested)
	}
	rec.DrainingAWGProfiles = []string{"awg-new"}
	if len(nestedAWGProfiles(rec, "awg")) != 0 {
		t.Fatal("a draining profile must not be offered")
	}
	rec.DrainingAWGProfiles = []string{"awg"}
	if primary, _ := awgPrimaryProfile(rec); primary.Name != "awg-new" {
		t.Fatalf("legacy drained base: primary=%q", primary.Name)
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

// P1/X-M2/X-L2/X-L11: other REALITY profiles are nested alternatives of the
// primary route, never separate routes; vision and flows agree; IPv6 comes
// from the base profile; a distinct xhttp host is kept.
func TestRealityAlternativesAreNested(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "fallback-worker")
	if _, err := s.store.upsertPendingWorker("fallback-worker", map[string]any{
		"egress_ip": "203.0.113.5",
		"reality":   map[string]any{"address": "203.0.113.5", "port": 443, "publicKey": "pub", "shortId": "sid", "network": "tcp", "fingerprint": "firefox"},
		"reality_profiles": []any{
			map[string]any{"name": "reality", "address": "203.0.113.5", "address_v6": "2001:db8::5", "port": 443, "network": "tcp", "public_key": "pub", "short_id": "sid", "flows": []any{"", realityFlowVision}},
			map[string]any{"name": "xh", "address": "203.0.113.5", "port": 8443, "network": "xhttp", "server_name": "a.example", "public_key": "pub", "short_id": "sid", "flows": []any{""}, "xhttp": map[string]any{"path": "/x", "mode": "auto", "host": "b.example"}},
			map[string]any{"name": "tcp2", "address": "203.0.113.5", "port": 2053, "network": "tcp", "public_key": "pub", "short_id": "sid"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.store.worker(w.ID)
	item, _ := s.clientWorkerPayload(rec, "", false)
	routes := item["routes"].([]any)
	var reality map[string]any
	for _, r := range routes {
		if r.(map[string]any)["type"] == "reality" {
			if reality != nil {
				t.Fatal("more than one reality route per worker")
			}
			reality = r.(map[string]any)
		}
	}
	params := reality["params"].(map[string]any)
	if reality["vision"] != true || params["address_v6"] != "2001:db8::5" || params["fingerprint"] != "chrome" {
		t.Fatalf("primary: vision=%v v6=%v fp=%v", reality["vision"], params["address_v6"], params["fingerprint"])
	}
	nested := params["reality_profiles"].([]any)
	if len(nested) != 2 {
		t.Fatalf("nested=%v", nested)
	}
	xh := nested[0].(map[string]any)
	if xh["vision"] != false || xh["xhttp"].(map[string]any)["host"] != "b.example" || len(xh["flows"].([]any)) != 1 {
		t.Fatalf("xhttp alternative=%v", xh)
	}
	tcp2 := nested[1].(map[string]any)
	if tcp2["vision"] != false || len(tcp2["flows"].([]any)) != 1 {
		t.Fatalf("tcp alternative without flows or capability must not claim vision: %v", tcp2)
	}
	// With the reality_flow capability a TCP profile without flows gets
	// both flows.
	rec.SelfDescribe["capabilities"] = []any{"reality_flow"}
	nested = nestedRealityProfiles(rec, 443, baseRealityProfile(rec, 443))
	if tcp2 := nested[1].(map[string]any); tcp2["vision"] != true || len(tcp2["flows"].([]any)) != 2 {
		t.Fatalf("capability tcp alternative=%v", tcp2)
	}
}

func TestEnrollClientCapabilitiesAlias(t *testing.T) {
	req := deviceEnrollRequest{
		ClientCapabilities: []string{"tunnel_dns", "reality_vision", " "},
		Capabilities:       []string{"reality_vision", "ipv6_endpoints"},
	}
	got := req.capabilities()
	want := []string{"ipv6_endpoints", "reality_vision", "tunnel_dns"}
	if !slices.Equal(got, want) {
		t.Fatalf("capabilities=%v want %v", got, want)
	}
	if deviceRealityFlow(deviceEnrollRequest{ClientCapabilities: []string{"reality_vision"}}.capabilities()) != realityFlowVision {
		t.Fatal("client_capabilities must negotiate Vision")
	}
}
