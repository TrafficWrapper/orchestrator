package main

import (
	"testing"
	"time"
)

func TestApplyReportedDeviceUsageMatchesFullSweep(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report deviceUsage
	}{
		{"by device id", deviceUsage{DeviceID: "device-a", AWGPublicKey: "awg-pub-a"}},
		{"legacy awg key only", deviceUsage{AWGPublicKey: "awg-pub-a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			addApprovedWorker(t, s)
			for _, id := range []string{"device-a", "device-b"} {
				putQuotaDevice(t, s, deviceRecord{
					ID:           id,
					Status:       "approved",
					AWGPublicKey: "awg-pub-" + id[len(id)-1:],
					InternalIP:   "10.13.13.10/32",
					RealityUUID:  "uuid-" + id,
					Limits:       deviceLimits{TrafficQuotaBytes: 100},
					CreatedAt:    time.Now().UTC(),
					ConfigSeq:    1,
				})
			}
			first := tc.report
			if _, err := s.store.applyReportedDeviceUsage("worker-a", []deviceUsage{first}, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			next := tc.report
			next.RxBytes, next.TxBytes = 70, 50
			blocked, err := s.store.applyReportedDeviceUsage("worker-a", []deviceUsage{next}, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if blocked != 1 {
				t.Fatalf("blocked=%d want 1", blocked)
			}
			a, _ := s.store.device("device-a")
			b, _ := s.store.device("device-b")
			if a.Status != "revoked" || a.UsageRxBytes != 70 || a.UsageTxBytes != 50 {
				t.Fatalf("device-a=%+v", a)
			}
			if b.Status != "approved" || b.UsageRxBytes != 0 {
				t.Fatalf("unreported device changed: %+v", b)
			}
		})
	}
}

func TestApplyReportedDeviceUsageNoReportsIsNoop(t *testing.T) {
	s := newTestServer(t)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	putQuotaDevice(t, s, deviceRecord{ID: "device-x", Status: "approved", Limits: deviceLimits{ExpiresAt: &past}, CreatedAt: time.Now().UTC()})
	if blocked, err := s.store.applyReportedDeviceUsage("worker-a", nil, time.Now().UTC()); err != nil || blocked != 0 {
		t.Fatalf("empty ack must not sweep: blocked=%d err=%v", blocked, err)
	}
	if blocked, err := s.store.applyDeviceUsageAndBlocks("", nil, time.Now().UTC()); err != nil || blocked != 1 {
		t.Fatalf("janitor sweep must block expired device: blocked=%d err=%v", blocked, err)
	}
}
