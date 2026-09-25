package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPullShipsAPKOnlyUntilWorkerAcksRelease(t *testing.T) {
	s := newTestServer(t)
	seedAPK := filepath.Join(s.cfg.StateDir, "seed-app.apk")
	if err := os.WriteFile(seedAPK, []byte("seed apk bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.SeedAPKPath = seedAPK
	s.cfg.SeedVersionCode = 7
	s.cfg.SeedVersionName = "seed-test"
	s.cfg.UpdatePublicKey = ""
	priv, err := loadOrCreateUpdateSigningKey(&s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.seedUpdateAPKIfPresent(priv); err != nil {
		t.Fatal(err)
	}
	worker := addApprovedWorkerWithStatic(t, s, "worker-static-apk")
	reload := func() workerRecord {
		t.Helper()
		rec, err := s.store.worker(worker.ID)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	rec := reload()
	update, err := pullArtifactForTest(s, rec, rec.DesiredSeq-1)
	if err != nil || update == nil || update.APKBase64 == "" {
		t.Fatalf("first pull must ship APK: update=%v err=%v", update != nil, err)
	}
	// Before the ack the APK keeps shipping.
	rec = reload()
	if update, _ := pullArtifactForTest(s, rec, rec.DesiredSeq-1); update == nil {
		t.Fatal("APK must be re-sent until the worker acks it")
	}
	if err := s.store.updateAck(rec.ID, rec.DesiredSeq, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.store.db.Update(s.store.bumpWorkerSeqsTx); err != nil {
		t.Fatal(err)
	}
	rec = reload()
	update, err = pullArtifactForTest(s, rec, rec.AppliedSeq)
	if err != nil || update != nil {
		t.Fatalf("config-only bump must not re-ship APK: update=%v err=%v", update != nil, err)
	}
	// A worker reporting no applied state gets the APK again.
	if update, _ := pullArtifactForTest(s, rec, 0); update == nil {
		t.Fatal("fresh worker state must receive APK")
	}

	apkPath := filepath.Join(s.cfg.StateDir, "next.apk")
	if err := os.WriteFile(apkPath, []byte("next apk"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, _, _ := s.store.currentAPKRelease()
	next := current
	next.Seq++
	next.APKPath = apkPath
	next.CreatedAt = time.Now().UTC()
	if err := s.store.setAPKRelease(next); err != nil {
		t.Fatal(err)
	}
	rec = reload()
	if update, _ := pullArtifactForTest(s, rec, rec.AppliedSeq); update == nil {
		t.Fatal("new APK release must ship")
	}
}

// pullArtifactForTest mirrors a pull: take the artifact, then release the
// shipment slot as handleNoiseContext does after writing the response.
func pullArtifactForTest(s *server, rec workerRecord, haveSeq int64) (*updateArtifact, error) {
	apk, err := s.apkDeliveryForPull(rec, haveSeq, nil)
	if apk.release != nil {
		apk.release()
	}
	return apk.update, err
}

func TestAPKShipmentsAreBoundedAndSkippedWhenBusy(t *testing.T) {
	s := newTestServer(t)
	var releases []func()
	for i := 0; i < maxConcurrentAPKShipments; i++ {
		release, ok := s.acquireAPKShipment(fmt.Sprintf("w%d", i), time.Second)
		if !ok {
			t.Fatalf("slot %d not granted", i)
		}
		releases = append(releases, release)
	}
	if _, ok := s.acquireAPKShipment("w-extra", 50*time.Millisecond); ok {
		t.Fatal("shipments beyond the bound must wait")
	}
	releases[0]()
	releases[0]() // idempotent
	if release, ok := s.acquireAPKShipment("w-extra", time.Second); !ok {
		t.Fatal("released slot must be reusable")
	} else {
		release()
	}
	releases[1]()
}
