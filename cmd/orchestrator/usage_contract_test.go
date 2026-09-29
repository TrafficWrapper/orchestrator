package main

import (
	"testing"
	"time"
)

// Contract test (ack.usage): the legacy AWG format (no source, by key) and
// the new one (source=awg with device_id) both account; unknown sources are
// dropped; the first report under any key is a baseline.
func TestAckUsageLegacyAndNewFormats(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{ID: "dev-legacy", Status: "approved", AWGPublicKey: "k-legacy", CreatedAt: time.Now().UTC(), ConfigSeq: 1})
	putQuotaDevice(t, s, deviceRecord{ID: "dev-new", Status: "approved", AWGPublicKey: "k-new", CreatedAt: time.Now().UTC(), ConfigSeq: 1})
	now := time.Now().UTC()
	report := func(rx uint64) []deviceUsage {
		return []deviceUsage{
			{AWGPublicKey: "k-legacy", RxBytes: rx},
			{DeviceID: "dev-new", Source: "awg", RxBytes: rx},
			{DeviceID: "dev-new", Source: "wireguard-v9", RxBytes: 999999},
		}
	}
	for i, rx := range []uint64{1000, 1500} {
		if _, err := s.store.applyDeviceUsageAndBlocks("w", report(rx), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"dev-legacy", "dev-new"} {
		rec, _ := s.store.device(id)
		if rec.UsageRxBytes != 500 {
			t.Fatalf("%s usage=%d want 500 (baseline 1000, then +500)", id, rec.UsageRxBytes)
		}
	}
}

// ORC-M9: a re-enrolled device does not inherit the lifetime total the
// worker still reports under its deterministic ID.
func TestReenrolledDeviceStartsFromBaseline(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{ID: "dev-r", Status: "approved", Limits: deviceLimits{TrafficQuotaBytes: 10 << 30}, CreatedAt: time.Now().UTC(), ConfigSeq: 1})
	blocked, err := s.store.applyDeviceUsageAndBlocks("w", []deviceUsage{{DeviceID: "dev-r", Source: "reality", RxBytes: 50 << 30}}, time.Now().UTC())
	if err != nil || blocked != 0 {
		t.Fatalf("lifetime total from before enrollment charged: blocked=%d err=%v", blocked, err)
	}
	if rec, _ := s.store.device("dev-r"); rec.UsageRxBytes != 0 || rec.Status != "approved" {
		t.Fatalf("device=%+v", rec)
	}
}

func TestOrchestratorAnnouncesUsageSourceAWG(t *testing.T) {
	caps := orchestratorCapabilities()
	found := false
	for _, c := range caps {
		found = found || c == orchCapUsageSourceAWG
	}
	if !found {
		t.Fatalf("capabilities=%v", caps)
	}
}
