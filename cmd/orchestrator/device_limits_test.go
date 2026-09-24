package main

import (
	"testing"
	"time"
)

func TestDeviceLimitsChangeRestoresQuotaBlockedDevice(t *testing.T) {
	now := time.Now().UTC()
	rec := deviceRecord{
		Status:        "revoked",
		BlockedReason: "traffic_quota_bytes",
		BlockedAt:     &now,
		UsageRxBytes:  8 << 30,
		UsageTxBytes:  4 << 30,
		Limits:        deviceLimits{TrafficQuotaBytes: 10 << 30},
	}
	applyDeviceLimitsChange(&rec, deviceLimits{TrafficQuotaBytes: 20 << 30}, now)
	if rec.Status != "approved" || rec.BlockedReason != "" || rec.BlockedAt != nil {
		t.Fatalf("quota-blocked device not restored: %+v", rec)
	}
	if rec.UsageRxBytes != 0 || rec.UsageTxBytes != 0 {
		t.Fatalf("new quota must count from now: rx=%d tx=%d", rec.UsageRxBytes, rec.UsageTxBytes)
	}
}

func TestDeviceLimitsResetClearsUsageAndUnblocks(t *testing.T) {
	now := time.Now().UTC()
	rec := deviceRecord{Status: "revoked", BlockedReason: "expires_at", UsageRxBytes: 5}
	applyDeviceLimitsChange(&rec, deviceLimits{}, now)
	if rec.Status != "approved" || rec.UsageRxBytes != 0 {
		t.Fatalf("reset did not restore device: %+v", rec)
	}
}

func TestDeviceLimitsChangeKeepsManualRevoke(t *testing.T) {
	rec := deviceRecord{Status: "revoked", BlockedReason: "manual"}
	applyDeviceLimitsChange(&rec, deviceLimits{}, time.Now().UTC())
	if rec.Status != "revoked" {
		t.Fatal("limit change must not undo a manual revoke")
	}
	legacy := deviceRecord{Status: "revoked"}
	applyDeviceLimitsChange(&legacy, deviceLimits{}, time.Now().UTC())
	if legacy.Status != "revoked" {
		t.Fatal("limit change must not undo a revoke without an auto-block reason")
	}
}

func TestDeviceLimitsChangeKeepsBlockWhenStillExpired(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour).Format(time.RFC3339)
	rec := deviceRecord{Status: "revoked", BlockedReason: "expires_at"}
	applyDeviceLimitsChange(&rec, deviceLimits{ExpiresAt: &past}, now)
	if rec.Status != "revoked" {
		t.Fatal("device must stay blocked while the new expiry is in the past")
	}
}
