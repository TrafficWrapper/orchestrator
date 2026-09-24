package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSuccessfulLoginsDoNotLockNetwork(t *testing.T) {
	limiter := newLoginLimiter()
	for i := 0; i < adminLoginPrefixFailureLimit*2; i++ {
		if r := limiter.reserveAttempt("127.0.0.1"); r.Locked || r.LockedAfterAttempt {
			t.Fatalf("successful login %d locked the network", i)
		}
		limiter.recordSuccess("127.0.0.1")
	}
}

func TestResyncShipsAPKEvenIfStaleAckFollows(t *testing.T) {
	s := newTestServer(t)
	seedAPK := filepath.Join(s.cfg.StateDir, "seed.apk")
	if err := os.WriteFile(seedAPK, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.SeedAPKPath, s.cfg.SeedVersionCode, s.cfg.SeedVersionName, s.cfg.UpdatePublicKey = seedAPK, 1, "seed", ""
	priv, err := loadOrCreateUpdateSigningKey(&s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.seedUpdateAPKIfPresent(priv); err != nil {
		t.Fatal(err)
	}
	w := addApprovedWorkerWithStatic(t, s, "resync-worker")
	rec, _ := s.store.worker(w.ID)
	if _, err := pullArtifactForTest(s, rec, rec.DesiredSeq-1); err != nil {
		t.Fatal(err)
	}
	if err := s.store.updateAck(rec.ID, rec.DesiredSeq, "", nil); err != nil {
		t.Fatal(err)
	}
	have := rec.DesiredSeq
	if err := s.store.updateWorker(rec.ID, func(r *workerRecord) error { forceWorkerResync(r, have); return nil }); err != nil {
		t.Fatal(err)
	}
	// Stale ack of the old applied seq arrives before the resync pull.
	if err := s.store.updateAck(rec.ID, have, "", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	if update, _ := pullArtifactForTest(s, rec, have); update == nil {
		t.Fatal("resync pull must ship the APK")
	}
}

func TestDeviceIPPoolSkipsWorkerGatewayOfUnmaskedSubnet(t *testing.T) {
	s := newTestServer(t)
	err := s.store.db.Update(func(tx *bolt.Tx) error {
		for i := 0; i < 300; i++ {
			ip, err := s.store.allocateDeviceIP(tx, "10.13.13.0/23")
			if err != nil {
				return err
			}
			if ip == "10.13.13.1/32" || ip == "10.13.13.2/32" {
				t.Fatalf("allocated worker gateway/smoke address %s", ip)
			}
			rec := deviceRecord{ID: ip, Status: "approved", InternalIP: ip, CreatedAt: time.Now()}
			sealed, _ := s.store.sealJSON(bucketDevices, []byte(rec.ID), rec)
			if err := tx.Bucket(bucketDevices).Put([]byte(rec.ID), sealed); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTOTPReenrollConfirmsInSameStepAsLogin(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	orig := enableTestTOTP(t, s, now)
	code, _ := totpCode(orig, now.Unix()/totpPeriodSeconds+1)
	if ok, _, _ := s.store.verifyAdminTOTP(code, now.Add(time.Duration(totpPeriodSeconds)*time.Second)); !ok {
		t.Skip("step boundary; login verification not comparable")
	}
	pending, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(time.Duration(totpPeriodSeconds) * time.Second)
	newCode, _ := totpCode(pending.Secret, at.Unix()/totpPeriodSeconds)
	if err := s.store.enableAdminTOTP(newCode, at); err != nil {
		t.Fatalf("new secret rejected in the login's time step: %v", err)
	}
}

func TestDiscoveryInvalidationDuringBuildSurvives(t *testing.T) {
	s := newTestServer(t)
	s.discoveryCacheMu.Lock()
	s.discoveryCache.Current = &discoveryBundleSnapshot{GeneratedAt: time.Now().UTC(), Revision: "r"}
	s.discoveryCacheMu.Unlock()
	gen := s.discoveryInvalidGen.Load()
	s.invalidateDiscoveryCache()
	if s.discoveryInvalidGen.Load() == gen {
		t.Fatal("invalidation must advance the generation checked when publishing a build")
	}
}
