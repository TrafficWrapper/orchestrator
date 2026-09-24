package main

import (
	"testing"
	"time"
)

func TestApprovedDevicesCacheTracksEveryCommit(t *testing.T) {
	s := newTestServer(t)
	dev := deviceRecord{ID: "dev-c", Status: "approved", RealityUUID: "u", AWGPublicKey: "k", InternalIP: "10.13.13.10/32", CreatedAt: time.Now().UTC()}
	putQuotaDevice(t, s, dev)
	first, err := s.store.approvedDevices()
	if err != nil || len(first) != 1 {
		t.Fatalf("approved=%d err=%v", len(first), err)
	}
	s.store.approvedCacheMu.Lock()
	rev := s.store.approvedCacheTx
	s.store.approvedCacheMu.Unlock()
	if _, err := s.store.approvedDevices(); err != nil {
		t.Fatal(err)
	}
	s.store.approvedCacheMu.Lock()
	sameRev := s.store.approvedCacheTx == rev
	s.store.approvedCacheMu.Unlock()
	if !sameRev {
		t.Fatal("read without writes must hit the cache")
	}
	if err := s.store.revokeDevice("dev-c"); err != nil {
		t.Fatal(err)
	}
	after, err := s.store.approvedDevices()
	if err != nil || len(after) != 0 {
		t.Fatalf("revoked device still served from cache: %d err=%v", len(after), err)
	}
	// A raw write (bypassing store helpers) must invalidate as well.
	putQuotaDevice(t, s, dev)
	again, _ := s.store.approvedDevices()
	if len(again) != 1 {
		t.Fatalf("direct write not reflected: %d", len(again))
	}
}
