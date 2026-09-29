package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
)

func pullForTest(t *testing.T, s *server, peer []byte, id string, haveSeq int64, caps []string) pullResponse {
	t.Helper()
	raw, _ := json.Marshal(pullRequest{WorkerID: id, HaveSeq: haveSeq, WorkerCapabilities: caps})
	resp, err := s.handlePull(peer, raw)
	if err != nil {
		t.Fatal(err)
	}
	out := resp.(pullResponse)
	if out.release != nil {
		out.release()
	}
	return out
}

func distributedAPKSelf(sha string, seq int64) map[string]any {
	dist := map[string]any{"apk_sha256": sha}
	if seq > 0 {
		dist["seq"] = float64(seq)
	}
	return map[string]any{"distributed_apk": dist}
}

// ORC-M15: update_ref leaves no legacy "applied" marker. The worker acks
// the config before its chunk download ends, so that ack must not count as
// the APK being applied: the next pull still carries update_ref.
func TestUpdateRefAckDoesNotMarkAPKApplied(t *testing.T) {
	s, w, _ := seededAPKServer(t, []byte("apk bytes"))
	caps := []string{workerCapAPKFetch}
	if d := deliveryForTest(t, s, w.ID, w.DesiredSeq-1, caps); d.ref == nil {
		t.Fatal("update_ref not sent")
	}
	rec, _ := s.store.worker(w.ID)
	if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	if rec.APKAppliedSeq != 0 || rec.APKSentSeq != 0 || rec.APKSentAtSeq != 0 {
		t.Fatalf("update_ref left legacy markers: applied=%d sent=%d at=%d", rec.APKAppliedSeq, rec.APKSentSeq, rec.APKSentAtSeq)
	}
	if err := s.store.db.Update(s.store.bumpWorkerSeqsTx); err != nil {
		t.Fatal(err)
	}
	if d := deliveryForTest(t, s, w.ID, rec.AppliedSeq, caps); d.ref == nil {
		t.Fatal("worker that never reported the APK got no update_ref")
	}
}

// ORC-M8: a failed chunk download is retried. The worker is current on
// config, so its periodic pull is answered NotModified; that answer still
// carries update_ref while the worker's distributed_apk is not the release.
func TestNotModifiedPullRetriesUpdateRef(t *testing.T) {
	s, w, peer := seededAPKServer(t, []byte("apk bytes"))
	rel, _, _ := s.store.currentAPKRelease()
	caps := []string{workerCapAPKFetch}
	rec, _ := s.store.worker(w.ID)
	first := pullForTest(t, s, peer, w.ID, rec.DesiredSeq-1, caps)
	if first.UpdateRef == nil || first.NotModified {
		t.Fatalf("first pull: ref=%v not_modified=%t", first.UpdateRef != nil, first.NotModified)
	}
	// The first config pull may move the worker's seq on (client seq
	// floor); the worker then applies the latest one.
	rec, _ = s.store.worker(w.ID)
	// Config applied, download failed: the worker still reports another
	// release (or none).
	stale := strings.Repeat("0", 64)
	for _, self := range []map[string]any{
		distributedAPKSelf(stale, rel.Seq+1000), // seq differs from the release
		distributedAPKSelf(rel.APKSHA256, rel.Seq+1),
		nil, // nothing distributed at all
	} {
		if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", self); err != nil {
			t.Fatal(err)
		}
		resp := pullForTest(t, s, peer, w.ID, rec.DesiredSeq, caps)
		if !resp.NotModified || resp.UpdateRef == nil || resp.UpdateRef.APKSeq != rel.Seq {
			t.Fatalf("self=%v: not_modified=%t ref=%+v", self, resp.NotModified, resp.UpdateRef)
		}
		if resp.Update != nil {
			t.Fatal("NotModified carried an inline APK")
		}
	}
	// Once the worker reports the release, NotModified carries nothing.
	if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", distributedAPKSelf(rel.APKSHA256, rel.Seq)); err != nil {
		t.Fatal(err)
	}
	if resp := pullForTest(t, s, peer, w.ID, rec.DesiredSeq, caps); !resp.NotModified || resp.UpdateRef != nil {
		t.Fatalf("applied release re-offered: ref=%v", resp.UpdateRef != nil)
	}
	// Workers without apk_fetch_v1 get a plain NotModified, as before.
	if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", nil); err != nil {
		t.Fatal(err)
	}
	if resp := pullForTest(t, s, peer, w.ID, rec.DesiredSeq, nil); !resp.NotModified || resp.UpdateRef != nil || resp.Update != nil {
		t.Fatalf("old worker NotModified changed: ref=%v update=%v", resp.UpdateRef != nil, resp.Update != nil)
	}
}

// ORC-M8: an apk_fetch_v1 worker that reports no distributed_apk.seq is judged
// by sha256 alone, so it is neither re-sent the release forever nor stuck on
// the legacy marker.
func TestUpdateRefAppliedBySHAWithoutSeq(t *testing.T) {
	s, w, peer := seededAPKServer(t, []byte("apk bytes"))
	rel, _, _ := s.store.currentAPKRelease()
	caps := []string{workerCapAPKFetch}
	rec, _ := s.store.worker(w.ID)
	if err := s.store.updateAck(w.ID, rec.DesiredSeq, "", distributedAPKSelf(strings.ToUpper(rel.APKSHA256), 0)); err != nil {
		t.Fatal(err)
	}
	if resp := pullForTest(t, s, peer, w.ID, rec.DesiredSeq, caps); resp.UpdateRef != nil {
		t.Fatal("release re-sent although the worker reports its sha256")
	}
	if err := s.store.db.Update(s.store.bumpWorkerSeqsTx); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(w.ID)
	if resp := pullForTest(t, s, peer, w.ID, rec.DesiredSeq-1, caps); resp.NotModified || resp.UpdateRef != nil {
		t.Fatalf("config pull: not_modified=%t ref=%v", resp.NotModified, resp.UpdateRef != nil)
	}
	// A legacy marker alone does not count for an apk_fetch_v1 worker.
	if err := s.store.updateWorker(w.ID, func(rec *workerRecord) error {
		rec.APKAppliedSeq = rel.Seq
		rec.SelfDescribe = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if resp := pullForTest(t, s, peer, w.ID, rec.DesiredSeq, caps); resp.UpdateRef == nil {
		t.Fatal("legacy marker hid a missing APK")
	}
}

// APP-L5: the package pin is fail-closed. An APK whose package cannot be
// read is refused once a package is pinned (ORCH_APK_PACKAGE or the current
// release), so one such publish cannot drop the implicit pin.
func TestAPKPackagePinFailsClosed(t *testing.T) {
	s := newTestServer(t)
	if err := s.checkAPKPackage(apkVersionInfo{}); err != nil {
		t.Fatalf("no pin yet: %v", err)
	}
	if err := s.store.setAPKRelease(apkReleaseRecord{Seq: 1, APKSHA256: strings.Repeat("a", 64), Package: "pro.trafficwrapper"}); err != nil {
		t.Fatal(err)
	}
	if err := s.checkAPKPackage(apkVersionInfo{}); err == nil {
		t.Fatal("unreadable package accepted under the release's pin")
	}
	if err := s.checkAPKPackage(apkVersionInfo{Package: "pro.trafficwrapper"}); err != nil {
		t.Fatal(err)
	}
	s2 := newTestServer(t)
	s2.cfg.APKPackage = "pro.trafficwrapper"
	if err := s2.checkAPKPackage(apkVersionInfo{}); err == nil {
		t.Fatal("unreadable package accepted under ORCH_APK_PACKAGE")
	}

	// End to end: a pinned publish of an APK without a readable package is
	// refused and the pin stays.
	s3, ts, token := autoPublishServer(t)
	if err := s3.store.setAPKRelease(apkReleaseRecord{Seq: 1, APKSHA256: strings.Repeat("a", 64), Package: "pro.trafficwrapper"}); err != nil {
		t.Fatal(err)
	}
	if code := publishStatus(t, ts.URL+"/admin/v1/apk/publish", token, buildTestAPKWithManifest(t, 1011, "0.1.11"), nil); code == 200 {
		t.Fatal("APK without a readable package published under a pin")
	}
	if rel, _, _ := s3.store.currentAPKRelease(); rel.Package != "pro.trafficwrapper" || rel.Seq != 1 {
		t.Fatalf("pin lost: %+v", rel)
	}
}

// APP-M5: re-signing keeps what the original manifest said beyond the
// builder's fields: mandatory, min_version and signing_cert_sha256.
func TestAPKManifestReissueKeepsMandatoryAndCert(t *testing.T) {
	s, _, _ := autoPublishServer(t)
	priv, _, err := s.loadServerUpdateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	apk := buildTestAPKWithManifest(t, 1011, "0.1.11")
	apkPath := filepath.Join(s.cfg.StateDir, "offline.apk")
	if err := os.WriteFile(apkPath, apk, 0o600); err != nil {
		t.Fatal(err)
	}
	sha, size, err := fileSHA256AndSize(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	base, err := buildAPKManifest(apkManifestInput{IssuedAt: time.Now().UTC(), TTL: s.apkManifestTTL(), Seq: 1, VersionCode: 1011, VersionName: "0.1.11",
		APKSHA256: sha, APKSize: size, APKName: "app.apk", MinVersion: 1005})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(base), &doc)
	cert := strings.Repeat("c", 64)
	doc["mandatory"] = true
	doc["signing_cert_sha256"] = cert
	manifestJSON, _ := canonicalJSON(doc)
	minisig := string(minisign.Sign(priv, []byte(manifestJSON)))
	manifest, err := parseAPKManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := s.storeAPKRelease(manifest, manifestJSON, minisig, file, nil); err != nil {
		t.Fatal(err)
	}
	did, err := s.reissueAPKManifestIfDue(time.Now().UTC().Add(s.apkManifestTTL()))
	if err != nil || !did {
		t.Fatalf("not re-signed: did=%t err=%v", did, err)
	}
	artifact, err := s.loadUpdateArtifact()
	if err != nil || artifact == nil {
		t.Fatal(err)
	}
	if err := verifyManifestSignature(artifact.ManifestJSON, artifact.ManifestMinisig, s.cfg.UpdatePublicKey); err != nil {
		t.Fatal(err)
	}
	var next map[string]any
	if err := json.Unmarshal([]byte(artifact.ManifestJSON), &next); err != nil {
		t.Fatal(err)
	}
	if next["mandatory"] != true || next["signing_cert_sha256"] != cert || next["min_version"] != float64(1005) {
		t.Fatalf("re-signed manifest dropped fields: %v", next)
	}
	if next["seq"] != float64(2) || next["expires_at"] == doc["expires_at"] {
		t.Fatalf("re-signed manifest not renewed: %v", next)
	}
}
