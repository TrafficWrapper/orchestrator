package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func enrollRequestForTest(t *testing.T, s *server, req deviceEnrollRequest) deviceEnrollResponse {
	t.Helper()
	req.IdentityPubKey, req.IdentityKeyType, req.AWGPublicKey = "identity-pub", "ed25519", "awg-dev"
	raw, _ := json.Marshal(req)
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

func workerDeviceFlow(t *testing.T, s *server, workerID string) any {
	t.Helper()
	devices := workerConfigForTest(t, s, workerID)["approved_devices"].([]any)
	if len(devices) != 1 {
		t.Fatalf("devices=%v", devices)
	}
	return devices[0].(map[string]any)["reality_flow"]
}

// ORC-L5: unknown capabilities are dropped without an error and the list is
// bounded.
func TestClientCapabilitiesAllowlist(t *testing.T) {
	raw := []string{"Reality_Vision", "made_up", strings.Repeat("x", 100), "tunnel_dns", "tunnel_dns"}
	if got := allowedClientCapabilities(raw); !slices.Equal(got, []string{"reality_vision", "tunnel_dns"}) {
		t.Fatalf("allowed=%v", got)
	}
	many := make([]string, 0, 40)
	for range 35 {
		many = append(many, "junk")
	}
	many = append(many, "reality_vision")
	if got := allowedClientCapabilities(many); len(got) != 0 {
		t.Fatalf("entries past the limit must be ignored: %v", got)
	}

	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "caps-worker")
	if _, err := s.store.createBootstrapToken("boot-caps", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-caps", ClientVersion: "0.1.31", Capabilities: []string{"route_alternatives_v1", "something_new"}})
	dev, _ := s.store.device(resp.DeviceID)
	if !slices.Equal(dev.ClientCapabilities, []string{"route_alternatives_v1"}) {
		t.Fatalf("stored capabilities=%v", dev.ClientCapabilities)
	}
	// P3: the derived version code is stored for diagnostics.
	if dev.ClientVersionCode != 131 {
		t.Fatalf("client_version_code=%d", dev.ClientVersionCode)
	}
	enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-caps", ClientVersion: "0.1.32", ClientVersionCode: 132})
	if dev, _ := s.store.device(resp.DeviceID); dev.ClientVersionCode != 132 {
		t.Fatalf("re-enroll client_version_code=%d", dev.ClientVersionCode)
	}
}

// X-L13: an app declaring reality_flow_ack gets Vision in two phases; the
// worker account switches only after the ack.
func TestVisionTwoPhaseWithAck(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "ack-worker")
	if _, err := s.store.createBootstrapToken("boot-ack", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	first := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-ack"})
	if first.RealityFlow != "" {
		t.Fatalf("flow=%q", first.RealityFlow)
	}
	caps := []string{"reality_vision", "reality_flow_ack"}
	offer := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-ack", Capabilities: caps})
	if offer.RealityFlow != "" || offer.RealityFlowPending != realityFlowVision {
		t.Fatalf("offer: flow=%q pending=%q", offer.RealityFlow, offer.RealityFlowPending)
	}
	if flow := workerDeviceFlow(t, s, w.ID); flow != nil {
		t.Fatalf("worker switched before the ack: %v", flow)
	}
	// A wrong ack keeps the offer open.
	again := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-ack", Capabilities: caps, RealityFlowAck: "other"})
	if again.RealityFlow != "" || again.RealityFlowPending != realityFlowVision {
		t.Fatalf("wrong ack: flow=%q pending=%q", again.RealityFlow, again.RealityFlowPending)
	}
	acked := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-ack", Capabilities: caps, RealityFlowAck: realityFlowVision})
	if acked.RealityFlow != realityFlowVision || acked.RealityFlowPending != "" {
		t.Fatalf("acked: flow=%q pending=%q", acked.RealityFlow, acked.RealityFlowPending)
	}
	if flow := workerDeviceFlow(t, s, w.ID); flow != realityFlowVision {
		t.Fatalf("worker flow after ack=%v", flow)
	}
	// Turning Vision off is immediate.
	off := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-ack", Capabilities: []string{"reality_flow_ack"}})
	if off.RealityFlow != "" || off.RealityFlowPending != "" {
		t.Fatalf("off: flow=%q pending=%q", off.RealityFlow, off.RealityFlowPending)
	}
}

// ORC-L5: switching Vision on again right after a switch keeps the previous
// flow without an error and without bumping the fleet.
func TestVisionSwitchRateLimited(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "rl-worker")
	if _, err := s.store.createBootstrapToken("boot-rl", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	vision := []string{"reality_vision"}
	resp := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rl", Capabilities: vision})
	enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rl"})
	before, _ := s.store.worker(w.ID)
	blocked := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rl", Capabilities: vision})
	if blocked.RealityFlow != "" {
		t.Fatalf("switch within the minimum gap: flow=%q", blocked.RealityFlow)
	}
	if after, _ := s.store.worker(w.ID); after.DesiredSeq != before.DesiredSeq {
		t.Fatalf("rate-limited re-enroll bumped the worker: %d -> %d", before.DesiredSeq, after.DesiredSeq)
	}
	if _, err := s.store.updateDevice(resp.DeviceID, false, func(rec *deviceRecord) error {
		old := time.Now().UTC().Add(-realityFlowSwitchMinGap - time.Minute)
		rec.RealityFlowChangedAt = &old
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if later := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rl", Capabilities: vision}); later.RealityFlow != realityFlowVision {
		t.Fatalf("switch after the gap: flow=%q", later.RealityFlow)
	}
}

// X-L3: short IDs compare lower-cased; the base short ID and the last cohort
// cannot be revoked.
func TestShortIDRevocationCaseAndGuards(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "sid-worker")
	if _, err := s.store.upsertPendingWorker("sid-worker", map[string]any{
		"egress_ip": "203.0.113.5",
		"reality":   map[string]any{"address": "203.0.113.5", "port": 8444, "publicKey": testRealityPublicKey, "shortId": "abcd", "cohort_short_ids": []any{"c0", "c1"}},
	}); err != nil {
		t.Fatal(err)
	}
	call := func(id string) int {
		return adminCall(t, s.handleAdminWorkerShortID, "/admin/v1/workers/short-id", map[string]any{"id": w.ID, "short_id": id, "revoked": true}, nil).Code
	}
	if code := call("ABCD"); code != http.StatusBadRequest {
		t.Fatalf("base short ID revoked: %d", code)
	}
	if code := call("C1"); code != http.StatusOK {
		t.Fatalf("cohort revoke: %d", code)
	}
	rec, _ := s.store.worker(w.ID)
	if !slices.Equal(rec.RevokedShortIDs, []string{"c1"}) || strings.Join(clientCohortShortIDs(rec), ",") != "c0," {
		t.Fatalf("revoked=%v cohorts=%v", rec.RevokedShortIDs, clientCohortShortIDs(rec))
	}
	if code := call("c0"); code != http.StatusBadRequest {
		t.Fatalf("last cohort revoked: %d", code)
	}
	// Entries stored before lower-casing are normalized for workers.
	rec.RevokedShortIDs = []string{"C1", "c1"}
	if got := normalizeShortIDs(rec.RevokedShortIDs); !slices.Equal(got, []string{"c1"}) {
		t.Fatalf("normalized=%v", got)
	}
}

// X-M4: draining the base AWG profile is refused while approved devices lack
// route alternatives, unless forced with step-up.
func TestBaseAWGDrainNeedsForce(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	w := addApprovedWorkerWithStatic(t, s, "drain-worker")
	if _, err := s.store.createBootstrapToken("boot-drain", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-drain", ClientVersion: "0.1.31"})
	call := func(body map[string]any) int {
		body["id"], body["profile"], body["draining"] = w.ID, "awg", true
		return adminCall(t, s.handleAdminWorkerAWGDrain, "/admin/v1/workers/awg-drain", body, nil).Code
	}
	if code := call(map[string]any{}); code != http.StatusConflict {
		t.Fatalf("base drain without force: %d", code)
	}
	if code := call(map[string]any{"force": true}); code != http.StatusForbidden {
		t.Fatalf("forced base drain without step-up: %d", code)
	}
	if rec, _ := s.store.worker(w.ID); len(rec.DrainingAWGProfiles) != 0 {
		t.Fatalf("drained: %v", rec.DrainingAWGProfiles)
	}
	if code := call(map[string]any{"force": true, "current_secret": "owner-secret-value"}); code != http.StatusOK {
		t.Fatalf("forced base drain with step-up: %d", code)
	}
	if rec, _ := s.store.worker(w.ID); !slices.Equal(rec.DrainingAWGProfiles, []string{"awg"}) {
		t.Fatalf("drained: %v", rec.DrainingAWGProfiles)
	}
}

// X-M4: devices enrolled before a profile existed get credentials for it
// without re-enrolling, and workers are told to pull.
func TestAWGCredentialBackfill(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "backfill-worker")
	if _, err := s.store.createBootstrapToken("boot-bf", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-bf"})
	if _, ok := resp.AWGProfiles["awg2"]; ok {
		t.Fatal("unexpected awg2 credentials")
	}
	before, _ := s.store.worker(w.ID)
	profiles := []awgProfile{{Name: "awg", Subnet: "10.13.13.0/24"}, {Name: "awg2", Subnet: "10.14.0.0/24"}}
	n, err := s.store.backfillDeviceAWGProfiles(profiles)
	if err != nil || n != 1 {
		t.Fatalf("backfill: n=%d err=%v", n, err)
	}
	dev, _ := s.store.device(resp.DeviceID)
	creds := dev.AWGProfiles["awg2"]
	if !strings.HasPrefix(creds.InternalIP, "10.14.0.") || creds.PSK2 == "" || dev.InternalIP != resp.InternalIP {
		t.Fatalf("backfilled device: %+v", dev.AWGProfiles)
	}
	if after, _ := s.store.worker(w.ID); after.DesiredSeq <= before.DesiredSeq {
		t.Fatal("backfill must bump worker config")
	}
	if n, err := s.store.backfillDeviceAWGProfiles(profiles); err != nil || n != 0 {
		t.Fatalf("second backfill: n=%d err=%v", n, err)
	}
}
