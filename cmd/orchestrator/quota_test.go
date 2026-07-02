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
	blocked, err := s.store.applyDeviceUsageAndBlocks([]deviceUsage{{
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
	blocked, err = s.store.applyDeviceUsageAndBlocks([]deviceUsage{{
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
	blocked, err := s.store.applyDeviceUsageAndBlocks([]deviceUsage{{
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
	blocked, err := s.store.applyDeviceUsageAndBlocks(nil, time.Now().UTC())
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
