package main

import (
	"testing"
	"time"
)

func TestApprovedDevicesCacheFollowsConfigRevision(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "cache-worker")
	dev := deviceRecord{ID: "dev-c", Status: "approved", RealityUUID: "u", AWGPublicKey: "k", InternalIP: "10.13.13.10/32", CreatedAt: time.Now().UTC()}
	putQuotaDevice(t, s, dev)
	first, err := s.store.approvedDevices()
	if err != nil || len(first) != 1 {
		t.Fatalf("approved=%d err=%v", len(first), err)
	}
	s.store.approvedCacheMu.Lock()
	rev := s.store.approvedCacheRev
	s.store.approvedCacheMu.Unlock()
	// Heartbeats and usage writes must not invalidate the cache.
	rec, _ := s.store.worker(w.ID)
	_ = s.store.updateAckWithProbe(w.ID, rec.DesiredSeq, "", map[string]any{"x": "y"}, nil)
	if _, err := s.store.applyReportedDeviceUsage(w.ID, []deviceUsage{{DeviceID: "dev-c", RxBytes: 5}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.approvedDevices(); err != nil {
		t.Fatal(err)
	}
	s.store.approvedCacheMu.Lock()
	sameRev := s.store.approvedCacheRev == rev
	s.store.approvedCacheMu.Unlock()
	if !sameRev {
		t.Fatal("non-config writes must keep the approved cache valid")
	}
	if err := s.store.revokeDevice("dev-c"); err != nil {
		t.Fatal(err)
	}
	after, err := s.store.approvedDevices()
	if err != nil || len(after) != 0 {
		t.Fatalf("revoked device still served from cache: %d err=%v", len(after), err)
	}
	putQuotaDevice(t, s, dev)
	if again, _ := s.store.approvedDevices(); len(again) != 1 {
		t.Fatalf("config write not reflected: %d", len(again))
	}
}
