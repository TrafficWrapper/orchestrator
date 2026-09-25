package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aead.dev/minisign"
)

func autoPublishServer(t *testing.T) (*server, *httptest.Server, string) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.cfg.UpdatePublicKey = mustText(pub)
	privText, _ := priv.MarshalText()
	if err := os.WriteFile(filepath.Join(s.cfg.StateDir, "update.key"), privText, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.route("/admin/v1/login"))
	mux.HandleFunc("/admin/v1/apk/publish", s.route("/admin/v1/apk/publish"))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	var login struct {
		SessionToken string `json:"session_token"`
	}
	postJSONForTest(t, ts.URL+"/admin/v1/login", map[string]string{"secret": "owner-secret"}, &login)
	return s, ts, login.SessionToken
}

func publishStatus(t *testing.T, url, token string, apk []byte, fields map[string]string) int {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("apk", "app.apk")
	_, _ = part.Write(apk)
	for k, v := range fields {
		_ = writer.WriteField(k, v)
	}
	_ = writer.Close()
	req, _ := http.NewRequest(http.MethodPost, url, &body)
	req.Header.Set("content-type", writer.FormDataContentType())
	req.Header.Set("authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// Contract test (apk-update-v1): what buildAPKManifest writes carries every
// field UpdateVerifier.parseManifest requires, including expires_at.
func TestAPKManifestCarriesFieldsAppsRequire(t *testing.T) {
	issued := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	raw, err := buildAPKManifest(apkManifestInput{IssuedAt: issued, TTL: 90 * 24 * time.Hour, Seq: 7, VersionCode: 131, VersionName: "0.1.31",
		APKSHA256: "ab" + string(bytes.Repeat([]byte("0"), 62)), APKSize: 10, APKName: "app.apk"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "ns", "seq", "version_code", "version_name", "apk_url", "apk_size", "apk_sha256", "issued_at", "expires_at"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("manifest lacks %s", key)
		}
	}
	if doc["expires_at"] != "2026-12-24T12:00:00Z" {
		t.Fatalf("expires_at=%v", doc["expires_at"])
	}
	if _, ok := doc["signing_cert_sha256"]; ok {
		t.Fatal("signing_cert_sha256 must be omitted unless computed from the APK signature")
	}
}

// APP-L5: the manifest must describe the APK it ships.
func TestAPKPublishRejectsVersionCodeMismatch(t *testing.T) {
	_, ts, token := autoPublishServer(t)
	apk := buildTestAPKWithManifest(t, 1011, "0.1.11")
	if code := publishStatus(t, ts.URL+"/admin/v1/apk/publish", token, apk, map[string]string{"version_code": "2000"}); code != http.StatusBadRequest {
		t.Fatalf("mismatched version_code accepted: %d", code)
	}
	if code := publishStatus(t, ts.URL+"/admin/v1/apk/publish", token, apk, map[string]string{"version_code": "1011"}); code != http.StatusOK {
		t.Fatalf("matching version_code rejected: %d", code)
	}
}

func TestAPKPackageMustStayTheSame(t *testing.T) {
	s := newTestServer(t)
	if err := s.checkAPKPackage(apkVersionInfo{Package: "pro.trafficwrapper"}); err != nil {
		t.Fatal(err)
	}
	s.cfg.APKPackage = "pro.trafficwrapper"
	if err := s.checkAPKPackage(apkVersionInfo{Package: "com.example.other"}); err == nil {
		t.Fatal("foreign package accepted")
	}
}

// APP-M5: a server-signed manifest is re-signed under a new seq, same APK,
// before it expires (and right away when it predates expires_at).
func TestAPKManifestReissuedBeforeExpiry(t *testing.T) {
	s, ts, token := autoPublishServer(t)
	apk := buildTestAPKWithManifest(t, 1011, "0.1.11")
	if code := publishStatus(t, ts.URL+"/admin/v1/apk/publish", token, apk, nil); code != http.StatusOK {
		t.Fatalf("publish: %d", code)
	}
	rel, _, _ := s.store.currentAPKRelease()
	if !rel.ServerSigned {
		t.Fatal("auto-published release must be marked server-signed")
	}
	if did, err := s.reissueAPKManifestIfDue(time.Now().UTC()); err != nil || did {
		t.Fatalf("fresh manifest re-signed: did=%t err=%v", did, err)
	}
	later := time.Now().UTC().Add(s.apkManifestTTL() * 3 / 4)
	did, err := s.reissueAPKManifestIfDue(later)
	if err != nil || !did {
		t.Fatalf("aging manifest not re-signed: did=%t err=%v", did, err)
	}
	next, _, _ := s.store.currentAPKRelease()
	if next.Seq != rel.Seq+1 || next.APKSHA256 != rel.APKSHA256 {
		t.Fatalf("re-signed release: %+v", next)
	}
	artifact, err := s.loadUpdateArtifact()
	if err != nil || artifact == nil {
		t.Fatal(err)
	}
	if err := verifyManifestSignature(artifact.ManifestJSON, artifact.ManifestMinisig, s.cfg.UpdatePublicKey); err != nil {
		t.Fatalf("re-signed manifest does not verify: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(artifact.ManifestJSON), &doc)
	if doc["seq"] != float64(next.Seq) || doc["expires_at"] == nil {
		t.Fatalf("manifest: %v", doc)
	}
}
