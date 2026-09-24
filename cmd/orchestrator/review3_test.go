package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAdminTLSRejectsTrustedCertForAnotherHostOnIPURL(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "attacker.example"}, DNSNames: []string{"attacker.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	adminTLSRoots = pool
	t.Cleanup(func() { adminTLSRoots = nil })

	gotToken := false
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("authorization") != ""
		_, _ = w.Write([]byte(`{}`))
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	ts.StartTLS()
	defer ts.Close()
	t.Setenv("ORCH_ADMIN_URL", ts.URL) // https://127.0.0.1:port
	t.Setenv("ORCH_ADMIN_SESSION_TOKEN", "secret-session")
	if err := adminGet(orchConfig{StateDir: t.TempDir(), TLS: true}, "/admin/v1/status", io.Discard); err == nil {
		t.Fatal("a trusted certificate for another host must be rejected")
	}
	if gotToken {
		t.Fatal("bearer token was sent to a server with a mismatching certificate")
	}
}

func TestAPKSkippedWhenBusyBumpsWorkerForRetry(t *testing.T) {
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
	old := apkShipmentWait
	apkShipmentWait = 20 * time.Millisecond
	t.Cleanup(func() { apkShipmentWait = old })
	for i := 0; i < maxConcurrentAPKShipments; i++ {
		release, ok := s.acquireAPKShipment(time.Second)
		if !ok {
			t.Fatal("slot not granted")
		}
		defer release()
	}
	w := addApprovedWorkerWithStatic(t, s, "busy-worker")
	rec, _ := s.store.worker(w.ID)
	update, release, err := s.updateArtifactForPull(rec, rec.DesiredSeq-1)
	if err != nil || update != nil || release != nil {
		t.Fatalf("busy slots must skip the APK: update=%v err=%v", update != nil, err)
	}
	after, _ := s.store.worker(w.ID)
	if after.DesiredSeq <= rec.DesiredSeq {
		t.Fatal("skipped APK must bump the worker so its next nudge pulls again")
	}
}
