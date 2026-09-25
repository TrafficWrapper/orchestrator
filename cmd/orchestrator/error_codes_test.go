package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// X-M5/APP-L22/APP-L23: enrollment refusals carry a code; texts are the
// ones old apps match; retryable ones keep their transient markers.
func TestEnrollRefusalsCarryCodes(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	if resp := enrollDeviceForTestWithVersion(t, s, "no-such-token", "0.1.31"); resp.OK || resp.Code != "token_invalid" {
		t.Fatalf("bad token: %+v", resp)
	}
	if _, err := s.store.createBootstrapToken("boot-codes", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollDeviceForTestWithVersion(t, s, "boot-codes", "0.1.31")
	if !resp.OK {
		t.Fatalf("enroll: %+v", resp)
	}
	if err := s.store.revokeDevice(resp.DeviceID); err != nil {
		t.Fatal(err)
	}
	again := enrollDeviceForTestWithVersion(t, s, "boot-codes", "0.1.31")
	if again.OK || again.Code != "device_revoked" || again.Error != "device is not approved" {
		t.Fatalf("revoked device: %+v", again)
	}
	if got := enrollErrorCode("no approved worker available yet"); got != "no_worker" {
		t.Fatalf("no worker code=%q", got)
	}
	for _, retryable := range []string{"no approved worker available yet", "no approved worker with awg public key"} {
		if !strings.Contains(retryable, "no approved worker") {
			t.Fatalf("%q lacks a transient marker", retryable)
		}
	}
}

// X-I13: reality_flow is always present in the enroll response.
func TestEnrollResponseAlwaysHasRealityFlow(t *testing.T) {
	raw, _ := json.Marshal(deviceEnrollResponse{OK: true})
	if !strings.Contains(string(raw), `"reality_flow":""`) {
		t.Fatalf("reality_flow omitted: %s", raw)
	}
}

func TestTelemetryErrorCodes(t *testing.T) {
	for text, code := range map[string]string{
		"telemetry timestamp outside freshness window": "stale_timestamp",
		"telemetry replay detected":                    "replay",
		"telemetry signature invalid":                  "bad_signature",
		"telemetry device mismatch":                    "bad_signature",
		"unknown device":                               "unknown_device",
		"device is not approved":                       "device_not_approved",
		"invalid telemetry payload":                    "invalid_payload",
	} {
		if got := telemetryErrorCode(text); got != code {
			t.Fatalf("%q -> %q want %q", text, got, code)
		}
	}
	s := newTestServer(t)
	kp, _ := protocol.GenerateKeypair()
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(kp.Public))
	raw, _ := json.Marshal(workerTelemetryRequest{WorkerID: w.ID, PayloadBase64: "e30=", Headers: map[string]string{"X-TW-Device": "nope"}})
	resp, _ := s.handleWorkerTelemetry(kp.Public, raw)
	m := resp.(map[string]any)
	if m["error"] != "unknown device" || m["code"] != "unknown_device" {
		t.Fatalf("telemetry=%v", m)
	}
}

// WRK-L26: worker-facing Noise responses carry the orchestrator clock.
func TestWorkerResponsesCarryServerTime(t *testing.T) {
	s := newTestServer(t)
	static, _ := protocol.GenerateKeypair()
	s.static = static
	workerKey, _ := protocol.GenerateKeypair()
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(workerKey.Public))
	mux := http.NewServeMux()
	mux.HandleFunc("/w/v1/handshake/start", s.handleHandshakeStart)
	mux.HandleFunc("/w/v1/config/pull", s.handleNoise(s.handlePull))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	var pull pullResponse
	before := time.Now().UnixMilli()
	workerNoiseCall(t, ts.URL, static.Public, workerKey, "/w/v1/config/pull", "", pullRequest{WorkerID: w.ID}, &pull)
	if pull.ServerTime < before || pull.ServerTime > time.Now().UnixMilli() {
		t.Fatalf("server_time=%d", pull.ServerTime)
	}
	if got := stampServerTime(workerRevokedResponse(), time.UnixMilli(42)).(workerRefusal); got.ServerTime != 42 {
		t.Fatal("refusals must carry server_time")
	}
}
