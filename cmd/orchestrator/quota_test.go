package main

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestApplyDeviceUsageBlocksAtQuotaAndIsIdempotent(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		InternalIP:   "10.13.13.10/32",
		RealityUUID:  "uuid-a",
		Limits:       deviceLimits{TrafficQuotaBytes: 100},
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		RxBytes:  0,
		TxBytes:  0,
	}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	blocked, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		RxBytes:  60,
		TxBytes:  40,
	}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if blocked != 1 {
		t.Fatalf("blocked=%d want 1", blocked)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "revoked" || rec.BlockedReason != "traffic_quota_bytes" || rec.UsageRxBytes != 60 || rec.UsageTxBytes != 40 {
		t.Fatalf("bad blocked device: %+v", rec)
	}
	blocked, err = s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		RxBytes:  60,
		TxBytes:  40,
	}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if blocked != 0 {
		t.Fatalf("idempotent blocked=%d want 0", blocked)
	}
}

func TestApplyDeviceUsageQuotaZeroDoesNotBlock(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		InternalIP:   "10.13.13.10/32",
		RealityUUID:  "uuid-a",
		Limits:       deviceLimits{TrafficQuotaBytes: 0},
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	blocked, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		RxBytes:  1 << 30,
		TxBytes:  1 << 30,
	}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if blocked != 0 {
		t.Fatalf("blocked=%d want 0", blocked)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "approved" {
		t.Fatalf("quota=0 device blocked: %+v", rec)
	}
}

func TestApplyDeviceUsageSumsPerWorkerAndHandlesCounterReset(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		InternalIP:   "10.13.13.10/32",
		RealityUUID:  "uuid-a",
		Limits:       deviceLimits{TrafficQuotaBytes: 0},
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	now := time.Now().UTC()
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      0,
		TxBytes:      0,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-b", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      0,
		TxBytes:      0,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      50,
		TxBytes:      5,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-b", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      50,
		TxBytes:      5,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-b", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      50,
		TxBytes:      5,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      10,
		TxBytes:      1,
	}}, now); err != nil {
		t.Fatal(err)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsageRxBytes != 110 || rec.UsageTxBytes != 11 {
		t.Fatalf("usage=(%d,%d), want (110,11)", rec.UsageRxBytes, rec.UsageTxBytes)
	}
}

func TestApplyDeviceUsageCountsRealityAndBlocksAtQuota(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		RealityUUID:  "uuid-a",
		Limits:       deviceLimits{TrafficQuotaBytes: 100},
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	blocked, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		Source:   "reality",
		RxBytes:  60,
		TxBytes:  40,
	}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if blocked != 1 {
		t.Fatalf("blocked=%d want 1", blocked)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "revoked" || rec.BlockedReason != "traffic_quota_bytes" || rec.UsageRxBytes != 60 || rec.UsageTxBytes != 40 {
		t.Fatalf("bad reality quota block: %+v", rec)
	}
}

func TestApplyDeviceUsageSumsAWGAndRealitySources(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		RealityUUID:  "uuid-a",
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	now := time.Now().UTC()
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID:     "device-a",
		AWGPublicKey: "awg-pub-a",
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID:     "device-a",
		AWGPublicKey: "awg-pub-a",
		RxBytes:      50,
		TxBytes:      5,
	}, {
		DeviceID: "device-a",
		Source:   "reality",
		RxBytes:  30,
		TxBytes:  15,
	}}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsageRxBytes != 80 || rec.UsageTxBytes != 20 {
		t.Fatalf("usage=(%d,%d), want (80,20)", rec.UsageRxBytes, rec.UsageTxBytes)
	}
}

func TestApplyDeviceUsageRealityCounterResetAddsNewInterval(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{
		ID:          "device-a",
		Status:      "approved",
		RealityUUID: "uuid-a",
		CreatedAt:   time.Now().UTC(),
		ConfigSeq:   1,
	})
	now := time.Now().UTC()
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		Source:   "reality",
		RxBytes:  100,
		TxBytes:  50,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		Source:   "reality",
		RxBytes:  100,
		TxBytes:  50,
	}}, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		DeviceID: "device-a",
		Source:   "reality",
		RxBytes:  25,
		TxBytes:  10,
	}}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsageRxBytes != 125 || rec.UsageTxBytes != 60 {
		t.Fatalf("reset usage=(%d,%d), want (125,60)", rec.UsageRxBytes, rec.UsageTxBytes)
	}
}

func TestApplyDeviceUsageQuotaTotalSaturates(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		UsageRxBytes: ^uint64(0) - 5,
		UsageTxBytes: 10,
		Limits:       deviceLimits{TrafficQuotaBytes: ^uint64(0)},
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	blocked, err := s.store.applyDeviceUsageAndBlocks("worker-a", nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if blocked != 1 {
		t.Fatalf("blocked=%d want 1", blocked)
	}
}

func TestApplyDeviceUsageAdoptsFirstBaselineForLegacyUsage(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		InternalIP:   "10.13.13.10/32",
		RealityUUID:  "uuid-a",
		UsageRxBytes: 80,
		UsageTxBytes: 20,
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	now := time.Now().UTC()
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      80,
		TxBytes:      20,
	}}, now); err != nil {
		t.Fatal(err)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsageRxBytes != 80 || rec.UsageTxBytes != 20 {
		t.Fatalf("first legacy report double-counted usage=(%d,%d), want (80,20)", rec.UsageRxBytes, rec.UsageTxBytes)
	}
	if _, err := s.store.applyDeviceUsageAndBlocks("worker-a", []deviceUsage{{
		AWGPublicKey: "awg-pub-a",
		RxBytes:      90,
		TxBytes:      25,
	}}, now); err != nil {
		t.Fatal(err)
	}
	rec, err = s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsageRxBytes != 90 || rec.UsageTxBytes != 25 {
		t.Fatalf("second legacy report did not add delta usage=(%d,%d), want (90,25)", rec.UsageRxBytes, rec.UsageTxBytes)
	}
}

func TestApplyDeviceUsageBlocksExpiredDeviceWithoutUsage(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	putQuotaDevice(t, s, deviceRecord{
		ID:           "device-a",
		Status:       "approved",
		AWGPublicKey: "awg-pub-a",
		InternalIP:   "10.13.13.10/32",
		RealityUUID:  "uuid-a",
		Limits:       deviceLimits{ExpiresAt: &expired},
		CreatedAt:    time.Now().UTC(),
		ConfigSeq:    1,
	})
	blocked, err := s.store.applyDeviceUsageAndBlocks("worker-a", nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if blocked != 1 {
		t.Fatalf("blocked=%d want 1", blocked)
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "revoked" || rec.BlockedReason != "expires_at" {
		t.Fatalf("bad expired block: %+v", rec)
	}
}

func putQuotaDevice(t *testing.T, s *server, rec deviceRecord) {
	t.Helper()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	err := s.store.db.Update(func(tx *bolt.Tx) error {
		sealed, err := s.store.sealJSON(rec)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketDevices).Put([]byte(rec.ID), sealed)
	})
	if err != nil {
		t.Fatal(err)
	}
}
