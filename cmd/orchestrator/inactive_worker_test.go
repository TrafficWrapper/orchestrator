package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// R2 ORC-H2: a worker marked inactive after a pause is still an approved
// worker. When it comes back its first pull must carry its devices and keep
// its protocols enabled, and its usage and telemetry count.
func TestInactiveWorkerKeepsDevices(t *testing.T) {
	s := newTestServer(t)
	kp, _ := protocol.GenerateKeypair()
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(kp.Public))
	if _, err := s.store.createBootstrapToken("boot-inactive", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	dev := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-inactive"})
	if n, err := s.store.markStaleWorkersInactive(time.Now().UTC().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("mark inactive: n=%d err=%v", n, err)
	}
	rec, _ := s.store.worker(w.ID)
	if rec.Status != "inactive" {
		t.Fatalf("status=%q", rec.Status)
	}
	raw, _ := json.Marshal(pullRequest{WorkerID: w.ID, HaveSeq: 0})
	resp, err := s.handlePull(kp.Public, raw)
	if err != nil {
		t.Fatal(err)
	}
	pull := resp.(pullResponse)
	pull.releaseAfterWrite()
	var doc struct {
		DesiredState struct {
			Reality struct {
				Enabled bool `json:"enabled"`
			} `json:"reality"`
			AWG struct {
				Enabled bool `json:"enabled"`
			} `json:"awg"`
			Devices []any `json:"approved_devices"`
		} `json:"desired_state"`
	}
	if err := json.Unmarshal([]byte(pull.WorkerBundle.ConfigJSON), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.DesiredState.Devices) != 1 || !doc.DesiredState.Reality.Enabled || !doc.DesiredState.AWG.Enabled {
		t.Fatalf("inactive worker got an emptied config: %+v", doc.DesiredState)
	}

	// Telemetry relayed by it is recorded, not silently dropped.
	payload := base64.StdEncoding.EncodeToString([]byte(`{"event":"x"}`))
	treq, _ := json.Marshal(map[string]any{"worker_id": w.ID, "payload_base64": payload, "headers": map[string]string{"X-TW-Device": dev.DeviceID}})
	tresp, err := s.handleWorkerTelemetry(kp.Public, treq)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := tresp.(map[string]any); ok && m["ok"] == true && len(m) == 1 {
		t.Fatal("telemetry from an inactive worker was silently discarded")
	}

	// Usage it reports is accounted.
	ack, _ := json.Marshal(ackRequest{WorkerID: w.ID, AppliedVersion: 0, Usage: []deviceUsage{{DeviceID: dev.DeviceID, Source: "reality", RxBytes: 10, TxBytes: 10}}})
	if _, err := s.handleAckContext(context.Background(), kp.Public, ack); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.store.device(dev.DeviceID)
	if len(stored.UsageCounters) == 0 {
		t.Fatal("usage from an inactive worker was dropped")
	}
}
