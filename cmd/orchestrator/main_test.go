package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/flynn/noise"
	bolt "go.etcd.io/bbolt"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func TestRejectForbiddenKeys(t *testing.T) {
	if err := rejectForbiddenKeys([]byte(`{"workers":[{"private_key":"x"}]}`)); err == nil {
		t.Fatal("private_key accepted")
	}
	if err := rejectForbiddenKeys([]byte(`{"workers":[{"public_key":"x","expected_egress_ip":"198.51.100.1"}]}`)); err != nil {
		t.Fatalf("public config rejected: %v", err)
	}
}

func TestWorkerEnrollTokenCanPinStaticPublicKey(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.createToken("worker-1", "secret", time.Hour, 1, "pinned-static"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.consumeToken("secret", "wrong-static"); err == nil {
		t.Fatal("pinned token accepted wrong worker static key")
	}
	if _, err := s.store.consumeToken("secret", "pinned-static"); err != nil {
		t.Fatalf("pinned token rejected correct worker static key: %v", err)
	}
	if _, err := s.store.consumeToken("secret", "pinned-static"); err == nil {
		t.Fatal("single-use pinned token accepted twice")
	}
}

func TestDeviceEnrollConsumesBootstrapOnceAndReturnsClientConfig(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	secret := "bootstrap-secret"
	token, err := s.store.createBootstrapToken(
		secret,
		time.Now().Add(time.Hour),
		json.RawMessage(`{"devices":1}`),
		[]string{"https://worker.example/tw"},
	)
	if err != nil {
		t.Fatal(err)
	}

	resp := enrollDeviceForTest(t, s, secret)
	if !resp.OK {
		t.Fatalf("enroll failed: %s", resp.Error)
	}
	if resp.SignerPublicKey != "RWQtest" {
		t.Fatalf("bad signer pubkey: %q", resp.SignerPublicKey)
	}
	if resp.ClientBundle.ConfigJSON == "" || resp.ClientBundle.Minisig == "" || resp.ClientBundle.ConfigSHA256 == "" {
		t.Fatalf("incomplete client bundle: %+v", resp.ClientBundle)
	}
	if resp.RealityUUID == "" || resp.InternalIP == "" || resp.PSK2 == "" || resp.ServerAWGPublic != "awgpub" {
		t.Fatalf("missing per-device credentials: %+v", resp)
	}
	if want := deviceID("identity-pub", ""); resp.DeviceID != want {
		t.Fatalf("device id not derived from identity public key: got %q want %q", resp.DeviceID, want)
	}
	if resp.DeviceID == "android-id" || !strings.HasPrefix(resp.DeviceID, "twpk_") {
		t.Fatalf("device id leaked request/android id: %q", resp.DeviceID)
	}
	if got, want := sha256Hex(resp.ClientBundle.ConfigJSON), resp.ClientBundle.ConfigSHA256; got != want {
		t.Fatalf("config sha mismatch: got %s want %s", got, want)
	}
	if err := rejectForbiddenKeys([]byte(resp.ClientBundle.ConfigJSON)); err != nil {
		t.Fatalf("client config has forbidden key: %v", err)
	}
	var config struct {
		NS      string `json:"ns"`
		Schema  int    `json:"schema"`
		Workers []struct {
			WorkerID string `json:"worker_id"`
			Routes   []struct {
				Type             string `json:"type"`
				Address          string `json:"address"`
				Port             int    `json:"port"`
				ExpectedEgressIP string `json:"expected_egress_ip"`
			} `json:"routes"`
		} `json:"workers"`
	}
	if err := json.Unmarshal([]byte(resp.ClientBundle.ConfigJSON), &config); err != nil {
		t.Fatal(err)
	}
	if config.NS != "client-config-v1" || config.Schema != 1 || len(config.Workers) != 1 || len(config.Workers[0].Routes) != 2 {
		t.Fatalf("bad client config shape: %+v", config)
	}
	if config.Workers[0].Routes[0].ExpectedEgressIP != "203.0.113.5" {
		t.Fatalf("expected egress not propagated: %+v", config.Workers[0].Routes[0])
	}
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	if workers[0].DesiredSeq < 2 {
		t.Fatalf("worker desired seq was not bumped after device enroll: %+v", workers[0])
	}
	workerBundle, _, err := s.buildBundles(workers[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(workerBundle.ConfigJSON, resp.RealityUUID) || !strings.Contains(workerBundle.ConfigJSON, "device-awg-public") {
		t.Fatalf("worker config does not contain approved device: %s", workerBundle.ConfigJSON)
	}
	used := bootstrapTokenForTest(t, s, token.ID)
	if used.Uses != 1 {
		t.Fatalf("first enroll token uses=%d want 1", used.Uses)
	}
	replay := enrollDeviceForTest(t, s, secret)
	if !replay.OK {
		t.Fatalf("idempotent replay rejected: %+v", replay)
	}
	if replay.RealityUUID != resp.RealityUUID || replay.InternalIP != resp.InternalIP || replay.PSK2 != resp.PSK2 {
		t.Fatalf("idempotent replay changed creds: first=%+v replay=%+v", resp, replay)
	}
	used = bootstrapTokenForTest(t, s, token.ID)
	if used.Uses != 1 {
		t.Fatalf("idempotent replay burned bootstrap use: uses=%d", used.Uses)
	}
	if err := s.store.revokeDevice(resp.DeviceID); err != nil {
		t.Fatal(err)
	}
	workers, err = s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	revokedBundle, _, err := s.buildBundles(workers[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(revokedBundle.ConfigJSON, resp.RealityUUID) {
		t.Fatalf("revoked device still present in worker config: %s", revokedBundle.ConfigJSON)
	}
}

func TestDeviceEnrollRejectsExistingBindingMismatches(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	secret := "bootstrap-mismatch-secret"
	if _, err := s.store.createBootstrapToken(
		secret,
		time.Now().Add(time.Hour),
		json.RawMessage(`{"devices":1}`),
		[]string{"https://worker.example/tw"},
	); err != nil {
		t.Fatal(err)
	}
	resp := enrollDeviceForTest(t, s, secret)
	if !resp.OK {
		t.Fatalf("enroll failed: %+v", resp)
	}
	churn := enrollDeviceForTestWithAWG(t, s, secret, "different-device-awg-public")
	if churn.OK || !strings.Contains(churn.Error, "awg public key mismatch") {
		t.Fatalf("awg key churn accepted or wrong error: %+v", churn)
	}
	if err := tamperDeviceIdentityForTest(s, resp.DeviceID, "other-identity-pub"); err != nil {
		t.Fatal(err)
	}
	mismatch := enrollDeviceForTest(t, s, secret)
	if mismatch.OK || !strings.Contains(mismatch.Error, "device identity mismatch") {
		t.Fatalf("identity mismatch accepted or wrong error: %+v", mismatch)
	}
}

func TestAdminDeleteDeviceRequiresCSRFAndPurgesActiveDevice(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	secret := "delete-device-bootstrap-secret"
	if _, err := s.store.createBootstrapToken(
		secret,
		time.Now().Add(time.Hour),
		json.RawMessage(`{"devices":1}`),
		[]string{"https://worker.example/tw"},
	); err != nil {
		t.Fatal(err)
	}
	enroll := enrollDeviceForTest(t, s, secret)
	if !enroll.OK {
		t.Fatalf("enroll failed: %s", enroll.Error)
	}
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	beforeSeq := workers[0].DesiredSeq

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/delete-device", s.handleAdminDeleteDevice)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	rawLogin, _ := json.Marshal(map[string]string{"secret": "owner-secret"})
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/login", bytes.NewReader(rawLogin))
	loginReq.Header.Set("content-type", "application/json")
	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	_ = loginResp.Body.Close()
	var login struct {
		CSRFToken string `json:"csrf_token"`
	}
	if loginResp.StatusCode != http.StatusOK || len(loginResp.Cookies()) == 0 {
		t.Fatalf("login status=%d body=%s cookies=%d", loginResp.StatusCode, string(loginBody), len(loginResp.Cookies()))
	}
	if err := json.Unmarshal(loginBody, &login); err != nil {
		t.Fatal(err)
	}
	cookie := loginResp.Cookies()[0]

	rawDelete, _ := json.Marshal(map[string]string{"id": enroll.DeviceID})
	noCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/delete-device", bytes.NewReader(rawDelete))
	noCSRFReq.Header.Set("content-type", "application/json")
	noCSRFReq.AddCookie(cookie)
	noCSRFResp, err := http.DefaultClient.Do(noCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRFResp.Body.Close()
	if noCSRFResp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without csrf status=%d", noCSRFResp.StatusCode)
	}
	if _, err := s.store.device(enroll.DeviceID); err != nil {
		t.Fatalf("device deleted without csrf: %v", err)
	}

	deleteReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/delete-device", bytes.NewReader(rawDelete))
	deleteReq.Header.Set("content-type", "application/json")
	deleteReq.Header.Set("x-csrf-token", login.CSRFToken)
	deleteReq.AddCookie(cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatal(err)
	}
	deleteBody, _ := io.ReadAll(io.LimitReader(deleteResp.Body, 1<<20))
	_ = deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteResp.StatusCode, string(deleteBody))
	}
	if _, err := s.store.device(enroll.DeviceID); err == nil {
		t.Fatalf("device still exists after delete")
	}
	workers, err = s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	if workers[0].DesiredSeq <= beforeSeq {
		t.Fatalf("worker seq was not bumped before active delete: before=%d after=%d", beforeSeq, workers[0].DesiredSeq)
	}
}

func TestAdminDeviceAliasRequiresCSRFAndSanitizes(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	secret := "device-alias-bootstrap-secret"
	if _, err := s.store.createBootstrapToken(
		secret,
		time.Now().Add(time.Hour),
		json.RawMessage(`{"devices":1}`),
		[]string{"https://worker.example/tw"},
	); err != nil {
		t.Fatal(err)
	}
	enroll := enrollDeviceForTest(t, s, secret)
	if !enroll.OK {
		t.Fatalf("enroll failed: %s", enroll.Error)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/device-alias", s.handleAdminDeviceAlias)
	mux.HandleFunc("/admin/v1/devices", s.handleAdminDevices)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	rawLogin, _ := json.Marshal(map[string]string{"secret": "owner-secret"})
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/login", bytes.NewReader(rawLogin))
	loginReq.Header.Set("content-type", "application/json")
	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	_ = loginResp.Body.Close()
	var login struct {
		SessionToken string `json:"session_token"`
		CSRFToken    string `json:"csrf_token"`
	}
	if loginResp.StatusCode != http.StatusOK || len(loginResp.Cookies()) == 0 {
		t.Fatalf("login status=%d body=%s cookies=%d", loginResp.StatusCode, string(loginBody), len(loginResp.Cookies()))
	}
	if err := json.Unmarshal(loginBody, &login); err != nil {
		t.Fatal(err)
	}
	cookie := loginResp.Cookies()[0]

	rawAlias, _ := json.Marshal(map[string]string{"id": enroll.DeviceID, "alias": "  Kitchen\u0007 phone  "})
	noCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/device-alias", bytes.NewReader(rawAlias))
	noCSRFReq.Header.Set("content-type", "application/json")
	noCSRFReq.AddCookie(cookie)
	noCSRFResp, err := http.DefaultClient.Do(noCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRFResp.Body.Close()
	if noCSRFResp.StatusCode != http.StatusForbidden {
		t.Fatalf("alias without csrf status=%d", noCSRFResp.StatusCode)
	}
	if rec, err := s.store.device(enroll.DeviceID); err != nil || rec.Alias != "" {
		t.Fatalf("alias changed without csrf: rec=%+v err=%v", rec, err)
	}

	aliasReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/device-alias", bytes.NewReader(rawAlias))
	aliasReq.Header.Set("content-type", "application/json")
	aliasReq.Header.Set("x-csrf-token", login.CSRFToken)
	aliasReq.AddCookie(cookie)
	aliasResp, err := http.DefaultClient.Do(aliasReq)
	if err != nil {
		t.Fatal(err)
	}
	aliasBody, _ := io.ReadAll(io.LimitReader(aliasResp.Body, 1<<20))
	_ = aliasResp.Body.Close()
	if aliasResp.StatusCode != http.StatusOK {
		t.Fatalf("alias status=%d body=%s", aliasResp.StatusCode, string(aliasBody))
	}
	rec, err := s.store.device(enroll.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Alias != "Kitchen phone" {
		t.Fatalf("alias was not sanitized/saved: %q", rec.Alias)
	}

	devicesReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/v1/devices", nil)
	devicesReq.Header.Set("authorization", "Bearer "+login.SessionToken)
	devicesResp, err := http.DefaultClient.Do(devicesReq)
	if err != nil {
		t.Fatal(err)
	}
	devicesBody, _ := io.ReadAll(io.LimitReader(devicesResp.Body, 1<<20))
	_ = devicesResp.Body.Close()
	if devicesResp.StatusCode != http.StatusOK || !bytes.Contains(devicesBody, []byte(`"alias":"Kitchen phone"`)) {
		t.Fatalf("alias not visible in devices API status=%d body=%s", devicesResp.StatusCode, string(devicesBody))
	}

	resetRaw, _ := json.Marshal(map[string]string{"id": enroll.DeviceID, "alias": ""})
	resetReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/device-alias", bytes.NewReader(resetRaw))
	resetReq.Header.Set("content-type", "application/json")
	resetReq.Header.Set("x-csrf-token", login.CSRFToken)
	resetReq.AddCookie(cookie)
	resetResp, err := http.DefaultClient.Do(resetReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("reset alias status=%d", resetResp.StatusCode)
	}
	rec, err = s.store.device(enroll.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Alias != "" {
		t.Fatalf("alias was not reset: %q", rec.Alias)
	}

	longRaw, _ := json.Marshal(map[string]string{"id": enroll.DeviceID, "alias": strings.Repeat("x", 65)})
	longReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/device-alias", bytes.NewReader(longRaw))
	longReq.Header.Set("content-type", "application/json")
	longReq.Header.Set("x-csrf-token", login.CSRFToken)
	longReq.AddCookie(cookie)
	longResp, err := http.DefaultClient.Do(longReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = longResp.Body.Close()
	if longResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("long alias status=%d", longResp.StatusCode)
	}
}

func TestDeviceEnrollHTTPNoiseEndToEnd(t *testing.T) {
	s := newTestServer(t)
	static, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s.static = static
	addApprovedWorker(t, s)
	secret := "http-bootstrap-secret"
	if _, err := s.store.createBootstrapToken(
		secret,
		time.Now().Add(time.Hour),
		json.RawMessage(`{"devices":1}`),
		[]string{"https://worker.example/tw"},
	); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/d/v1/handshake/start", s.handleHandshakeStart)
	mux.HandleFunc("/d/v1/enroll", s.handleNoise(s.handleDeviceEnroll))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	clientStatic, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var resp deviceEnrollResponse
	noiseCallForTest(t, ts.URL, static.Public, clientStatic, "/d/v1/enroll", deviceEnrollRequest{
		BootstrapToken:  secret,
		IdentityPubKey:  "identity-http",
		IdentityKeyType: "ed25519",
		EnrollmentNonce: "nonce-http",
		AWGPublicKey:    "device-awg-public",
	}, &resp)
	if !resp.OK {
		t.Fatalf("http noise enroll failed: %+v", resp)
	}
	if resp.ClientBundle.PublicKey != "RWQtest" || resp.ClientBundle.ConfigSHA256 != sha256Hex(resp.ClientBundle.ConfigJSON) {
		t.Fatalf("bad signed config: %+v", resp.ClientBundle)
	}

	var replay deviceEnrollResponse
	noiseCallForTest(t, ts.URL, static.Public, clientStatic, "/d/v1/enroll", deviceEnrollRequest{
		BootstrapToken: secret,
		IdentityPubKey: "identity-http-2",
		AWGPublicKey:   "device-awg-public-2",
	}, &replay)
	if replay.OK {
		t.Fatalf("replay accepted over http noise: %+v", replay)
	}
}

func TestWorkerTelemetryRequiresDeviceSignatureAndStoresSnapshot(t *testing.T) {
	s := newTestServer(t)
	workerPeer := bytes.Repeat([]byte{7}, 32)
	worker := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(workerPeer))

	identityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityDER, err := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	identityPub := base64.StdEncoding.EncodeToString(identityDER)
	secret := "telemetry-bootstrap-secret"
	if _, err := s.store.createBootstrapToken(
		secret,
		time.Now().Add(time.Hour),
		json.RawMessage(`{"devices":1}`),
		[]string{"https://worker.example/tw"},
	); err != nil {
		t.Fatal(err)
	}
	rawEnroll, _ := json.Marshal(deviceEnrollRequest{
		BootstrapToken:  secret,
		IdentityPubKey:  identityPub,
		IdentityKeyType: "ecdsa-p256-sha256",
		AndroidID:       "a15-public",
		Model:           "A15",
		EnrollmentNonce: "nonce",
		ClientVersion:   "public-test",
		AWGPublicKey:    "device-awg-public",
	})
	enrollRaw, err := s.handleDeviceEnroll(make([]byte, 32), rawEnroll)
	if err != nil {
		t.Fatal(err)
	}
	enroll := enrollRaw.(deviceEnrollResponse)
	if !enroll.OK {
		t.Fatalf("enroll failed: %s", enroll.Error)
	}
	if want := deviceID(identityPub, ""); enroll.DeviceID != want {
		t.Fatalf("telemetry enroll device id mismatch: got %q want %q", enroll.DeviceID, want)
	}
	if enroll.DeviceID == "a15-public" || !strings.HasPrefix(enroll.DeviceID, "twpk_") {
		t.Fatalf("telemetry device id leaked android id: %q", enroll.DeviceID)
	}
	payload := []byte(`{"did":"` + enroll.DeviceID + `","ver":"public-1.0.5","vc":1005,"sent_at":1710000000000,"events":[{"k":"heartbeat","t":1710000000000,"mono":123000,"active_route":"REALITY2","healthy":true,"stable":true,"rl2_carry":true}]}`)
	headers := signedTelemetryHeadersForTest(t, identityKey, enroll.DeviceID, identityPub, payload)
	reqRaw, _ := json.Marshal(workerTelemetryRequest{
		WorkerID:      worker.ID,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		Headers:       headers,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	})
	respRaw, err := s.handleWorkerTelemetry(workerPeer, reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	resp := respRaw.(map[string]any)
	if resp["ok"] != true {
		t.Fatalf("telemetry rejected: %+v", resp)
	}
	live, err := s.store.telemetrySnapshots()
	if err != nil {
		t.Fatal(err)
	}
	rec := live[enroll.DeviceID]
	if rec.ClientVersion != "public-1.0.5" || rec.Route != "REALITY-RU" || rec.Health != "stable" || !rec.Carry {
		t.Fatalf("bad telemetry snapshot: %+v", rec)
	}
	deviceAfterTelemetry, err := s.store.device(enroll.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if deviceAfterTelemetry.ClientVersion != "public-1.0.5" {
		t.Fatalf("telemetry did not self-heal device client version: %q", deviceAfterTelemetry.ClientVersion)
	}

	headers["X-TW-Sig"] = base64.StdEncoding.EncodeToString([]byte("bad-signature"))
	badReq, _ := json.Marshal(workerTelemetryRequest{
		WorkerID:      worker.ID,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		Headers:       headers,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	})
	badRaw, err := s.handleWorkerTelemetry(workerPeer, badReq)
	if err != nil {
		t.Fatal(err)
	}
	bad := badRaw.(map[string]any)
	if bad["ok"] == true || !strings.Contains(bad["error"].(string), "signature") {
		t.Fatalf("bad signature accepted: %+v", bad)
	}
}

func TestDeviceEnrollRejectsExpiredAndUnknownBootstrap(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	insertBootstrapToken(t, s.store, "expired-secret", time.Now().Add(-time.Minute))

	expired := enrollDeviceForTest(t, s, "expired-secret")
	if expired.OK || !strings.Contains(expired.Error, "expired") {
		t.Fatalf("expired token accepted or wrong error: %+v", expired)
	}
	unknown := enrollDeviceForTest(t, s, "missing-secret")
	if unknown.OK || !strings.Contains(unknown.Error, "invalid") {
		t.Fatalf("unknown token accepted or wrong error: %+v", unknown)
	}
}

func TestAdminAuthAndConfigEdit(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/config", s.handleAdminConfig)
	mux.HandleFunc("/admin/v1/config/edit", s.handleAdminConfigEdit)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/admin/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth config status=%d", resp.StatusCode)
	}

	var login struct {
		OK           bool   `json:"ok"`
		SessionToken string `json:"session_token"`
	}
	postJSONForTest(t, ts.URL+"/admin/v1/login", map[string]string{"secret": "owner-secret"}, &login)
	if !login.OK || login.SessionToken == "" {
		t.Fatalf("bad login response: %+v", login)
	}

	var before struct {
		OK     bool         `json:"ok"`
		Bundle signedConfig `json:"bundle"`
	}
	adminJSONForTest(t, http.MethodGet, ts.URL+"/admin/v1/config", login.SessionToken, nil, &before)
	if !before.OK || before.Bundle.ConfigJSON == "" {
		t.Fatalf("bad config response: %+v", before)
	}
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	workerID := workers[0].ID
	var edit struct {
		OK     bool         `json:"ok"`
		Bundle signedConfig `json:"bundle"`
	}
	adminJSONForTest(t, http.MethodPost, ts.URL+"/admin/v1/config/edit", login.SessionToken, map[string]any{
		"workers": []map[string]any{{
			"worker_id": workerID,
			"priority":  3,
			"weight":    25,
			"protocols": map[string]bool{"reality": false, "awg": true},
		}},
	}, &edit)
	if !edit.OK {
		t.Fatalf("edit failed: %+v", edit)
	}
	var config struct {
		Seq     int64 `json:"seq"`
		Workers []struct {
			Priority int `json:"priority"`
			Weight   int `json:"weight"`
			Routes   []struct {
				Type string `json:"type"`
			} `json:"routes"`
		} `json:"workers"`
	}
	if err := json.Unmarshal([]byte(edit.Bundle.ConfigJSON), &config); err != nil {
		t.Fatal(err)
	}
	if config.Seq <= 1 || len(config.Workers) != 1 || config.Workers[0].Priority != 3 || config.Workers[0].Weight != 25 {
		t.Fatalf("policy not reflected in config: %+v", config)
	}
	if len(config.Workers[0].Routes) != 1 || config.Workers[0].Routes[0].Type != "awg" {
		t.Fatalf("protocol toggle not reflected in routes: %+v", config.Workers[0].Routes)
	}
}

func TestAdminBootstrapQRCode(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/bootstrap-token/qr", s.handleAdminBootstrapTokenQR)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var login struct {
		OK           bool   `json:"ok"`
		SessionToken string `json:"session_token"`
	}
	postJSONForTest(t, ts.URL+"/admin/v1/login", map[string]string{"secret": "owner-secret"}, &login)
	if !login.OK || login.SessionToken == "" {
		t.Fatalf("bad login response: %+v", login)
	}

	var qr struct {
		OK    bool   `json:"ok"`
		Image string `json:"image"`
	}
	adminJSONForTest(t, http.MethodPost, ts.URL+"/admin/v1/bootstrap-token/qr", login.SessionToken, map[string]string{
		"data": "eyJib290c3RyYXBfdG9rZW4iOiJ0ZXN0In0=",
	}, &qr)
	const prefix = "data:image/png;base64,"
	if !qr.OK || !strings.HasPrefix(qr.Image, prefix) {
		t.Fatalf("bad QR response: %+v", qr)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(qr.Image, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Fatalf("QR is not PNG: %x", raw[:8])
	}
}

func TestWebUIRequiresSessionAndUsesCSRF(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.registerWebRoutes(mux)
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/workers/set-enabled", s.handleAdminWorkerSetEnabled)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	loginResp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK || !strings.Contains(string(loginBody), "Вход владельца") {
		t.Fatalf("bad login page status=%d body=%s", loginResp.StatusCode, string(loginBody))
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	workersResp, err := noRedirect.Get(ts.URL + "/workers")
	if err != nil {
		t.Fatal(err)
	}
	_ = workersResp.Body.Close()
	if workersResp.StatusCode != http.StatusFound || workersResp.Header.Get("location") != "/login" {
		t.Fatalf("workers without session status=%d location=%q", workersResp.StatusCode, workersResp.Header.Get("location"))
	}

	rawLogin, _ := json.Marshal(map[string]string{"secret": "owner-secret"})
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/login", bytes.NewReader(rawLogin))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, string(body))
	}
	var login struct {
		OK        bool   `json:"ok"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	if !login.OK || login.CSRFToken == "" || len(resp.Cookies()) == 0 {
		t.Fatalf("bad web login response: csrf=%q cookies=%d", login.CSRFToken, len(resp.Cookies()))
	}
	cookie := resp.Cookies()[0]
	workersPageReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/workers", nil)
	workersPageReq.AddCookie(cookie)
	workersPageResp, err := http.DefaultClient.Do(workersPageReq)
	if err != nil {
		t.Fatal(err)
	}
	workersPageBody, _ := io.ReadAll(io.LimitReader(workersPageResp.Body, 1<<20))
	_ = workersPageResp.Body.Close()
	if workersPageResp.StatusCode != http.StatusOK || !strings.Contains(string(workersPageBody), "Workers") {
		t.Fatalf("bad workers page status=%d body=%s", workersPageResp.StatusCode, string(workersPageBody))
	}

	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	rawDisable, _ := json.Marshal(map[string]any{"id": workers[0].ID, "enabled": false})
	noCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/workers/set-enabled", bytes.NewReader(rawDisable))
	noCSRFReq.Header.Set("content-type", "application/json")
	noCSRFReq.AddCookie(cookie)
	noCSRFResp, err := http.DefaultClient.Do(noCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRFResp.Body.Close()
	if noCSRFResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie post without csrf status=%d", noCSRFResp.StatusCode)
	}
	withCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/workers/set-enabled", bytes.NewReader(rawDisable))
	withCSRFReq.Header.Set("content-type", "application/json")
	withCSRFReq.Header.Set("x-csrf-token", login.CSRFToken)
	withCSRFReq.AddCookie(cookie)
	withCSRFResp, err := http.DefaultClient.Do(withCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	withCSRFBody, _ := io.ReadAll(io.LimitReader(withCSRFResp.Body, 1<<20))
	_ = withCSRFResp.Body.Close()
	if withCSRFResp.StatusCode != http.StatusOK {
		t.Fatalf("cookie post with csrf status=%d body=%s", withCSRFResp.StatusCode, string(withCSRFBody))
	}
}

func TestFirstRunPasswordMustChangeFlow(t *testing.T) {
	s := newTestServer(t)
	initial, generated, err := s.store.ensureAdminPassword("")
	if err != nil {
		t.Fatal(err)
	}
	if !generated || initial == "" {
		t.Fatalf("initial password not generated: generated=%t initial=%q", generated, initial)
	}
	ok, mustChange, err := s.store.verifyAdminPassword(initial)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !mustChange {
		t.Fatalf("initial password state ok=%t mustChange=%t", ok, mustChange)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/password/change", s.handleAdminPasswordChange)
	mux.HandleFunc("/admin/v1/config", s.handleAdminConfig)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	rawLogin, _ := json.Marshal(map[string]string{"secret": initial})
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/login", bytes.NewReader(rawLogin))
	loginReq.Header.Set("content-type", "application/json")
	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginResp.StatusCode, string(loginBody))
	}
	var login struct {
		OK         bool   `json:"ok"`
		MustChange bool   `json:"must_change"`
		CSRFToken  string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginBody, &login); err != nil {
		t.Fatal(err)
	}
	if !login.OK || !login.MustChange || login.CSRFToken == "" || len(loginResp.Cookies()) == 0 {
		t.Fatalf("bad must-change login: %+v cookies=%d", login, len(loginResp.Cookies()))
	}
	cookie := loginResp.Cookies()[0]

	configReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/v1/config", nil)
	configReq.AddCookie(cookie)
	configResp, err := http.DefaultClient.Do(configReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = configResp.Body.Close()
	if configResp.StatusCode != http.StatusForbidden {
		t.Fatalf("must-change session accessed admin API status=%d", configResp.StatusCode)
	}

	rawChange, _ := json.Marshal(map[string]string{"current_secret": initial, "new_secret": "new-owner-secret"})
	changeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/password/change", bytes.NewReader(rawChange))
	changeReq.Header.Set("content-type", "application/json")
	changeReq.Header.Set("x-csrf-token", login.CSRFToken)
	changeReq.AddCookie(cookie)
	changeResp, err := http.DefaultClient.Do(changeReq)
	if err != nil {
		t.Fatal(err)
	}
	changeBody, _ := io.ReadAll(io.LimitReader(changeResp.Body, 1<<20))
	_ = changeResp.Body.Close()
	if changeResp.StatusCode != http.StatusOK {
		t.Fatalf("change status=%d body=%s", changeResp.StatusCode, string(changeBody))
	}
	ok, mustChange, err = s.store.verifyAdminPassword("new-owner-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || mustChange {
		t.Fatalf("new password state ok=%t mustChange=%t", ok, mustChange)
	}
}

func TestAdminPasswordChangeWithRegularSessionRequiresCurrentSecretAndCSRF(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("old-owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/password/change", s.handleAdminPasswordChange)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	rawLogin, _ := json.Marshal(map[string]string{"secret": "old-owner-secret"})
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/login", bytes.NewReader(rawLogin))
	loginReq.Header.Set("content-type", "application/json")
	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginResp.StatusCode, string(loginBody))
	}
	var login struct {
		OK         bool   `json:"ok"`
		MustChange bool   `json:"must_change"`
		CSRFToken  string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginBody, &login); err != nil {
		t.Fatal(err)
	}
	if !login.OK || login.MustChange || login.CSRFToken == "" || len(loginResp.Cookies()) == 0 {
		t.Fatalf("bad regular login: %+v cookies=%d", login, len(loginResp.Cookies()))
	}
	cookie := loginResp.Cookies()[0]

	badRaw, _ := json.Marshal(map[string]string{"current_secret": "wrong-secret", "new_secret": "new-owner-secret"})
	badReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/password/change", bytes.NewReader(badRaw))
	badReq.Header.Set("content-type", "application/json")
	badReq.Header.Set("x-csrf-token", login.CSRFToken)
	badReq.AddCookie(cookie)
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode < 400 {
		t.Fatalf("wrong current secret accepted: status=%d", badResp.StatusCode)
	}

	goodRaw, _ := json.Marshal(map[string]string{"current_secret": "old-owner-secret", "new_secret": "new-owner-secret"})
	noCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/password/change", bytes.NewReader(goodRaw))
	noCSRFReq.Header.Set("content-type", "application/json")
	noCSRFReq.AddCookie(cookie)
	noCSRFResp, err := http.DefaultClient.Do(noCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRFResp.Body.Close()
	if noCSRFResp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d", noCSRFResp.StatusCode)
	}

	goodReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/password/change", bytes.NewReader(goodRaw))
	goodReq.Header.Set("content-type", "application/json")
	goodReq.Header.Set("x-csrf-token", login.CSRFToken)
	goodReq.AddCookie(cookie)
	goodResp, err := http.DefaultClient.Do(goodReq)
	if err != nil {
		t.Fatal(err)
	}
	goodBody, _ := io.ReadAll(io.LimitReader(goodResp.Body, 1<<20))
	_ = goodResp.Body.Close()
	if goodResp.StatusCode != http.StatusOK {
		t.Fatalf("change status=%d body=%s", goodResp.StatusCode, string(goodBody))
	}
	oldOK, _, err := s.store.verifyAdminPassword("old-owner-secret")
	if err != nil {
		t.Fatal(err)
	}
	newOK, mustChange, err := s.store.verifyAdminPassword("new-owner-secret")
	if err != nil {
		t.Fatal(err)
	}
	if oldOK || !newOK || mustChange {
		t.Fatalf("password state oldOK=%t newOK=%t mustChange=%t", oldOK, newOK, mustChange)
	}
}

func TestWebBotTokenSettingsUsesSessionCSRFAndEncryptedStore(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/bot/set-token", s.handleAdminBotSetToken)
	mux.HandleFunc("/admin/v1/bot/status", s.handleAdminBotStatus)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	rawLogin, _ := json.Marshal(map[string]string{"secret": "owner-secret"})
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/login", bytes.NewReader(rawLogin))
	loginReq.Header.Set("content-type", "application/json")
	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	_ = loginResp.Body.Close()
	var login struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginBody, &login); err != nil {
		t.Fatal(err)
	}
	if login.CSRFToken == "" || len(loginResp.Cookies()) == 0 {
		t.Fatalf("bad login for bot settings: csrf=%q cookies=%d", login.CSRFToken, len(loginResp.Cookies()))
	}
	cookie := loginResp.Cookies()[0]

	payload := map[string]any{"token": "123456:secret-bot-token", "owner_id": int64(1001)}
	rawPayload, _ := json.Marshal(payload)
	noCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/bot/set-token", bytes.NewReader(rawPayload))
	noCSRFReq.Header.Set("content-type", "application/json")
	noCSRFReq.AddCookie(cookie)
	noCSRFResp, err := http.DefaultClient.Do(noCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRFResp.Body.Close()
	if noCSRFResp.StatusCode != http.StatusForbidden {
		t.Fatalf("bot set-token without csrf status=%d", noCSRFResp.StatusCode)
	}

	withCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/bot/set-token", bytes.NewReader(rawPayload))
	withCSRFReq.Header.Set("content-type", "application/json")
	withCSRFReq.Header.Set("x-csrf-token", login.CSRFToken)
	withCSRFReq.AddCookie(cookie)
	withCSRFResp, err := http.DefaultClient.Do(withCSRFReq)
	if err != nil {
		t.Fatal(err)
	}
	withCSRFBody, _ := io.ReadAll(io.LimitReader(withCSRFResp.Body, 1<<20))
	_ = withCSRFResp.Body.Close()
	if withCSRFResp.StatusCode != http.StatusOK {
		t.Fatalf("bot set-token status=%d body=%s", withCSRFResp.StatusCode, string(withCSRFBody))
	}
	if bytes.Contains(withCSRFBody, []byte("secret-bot-token")) {
		t.Fatalf("bot token leaked in API response: %s", string(withCSRFBody))
	}
	rec, ok, err := s.store.botSettings()
	if err != nil || !ok {
		t.Fatalf("bot settings missing ok=%t err=%v", ok, err)
	}
	if rec.Token != "123456:secret-bot-token" || rec.OwnerID != 1001 {
		t.Fatalf("bad bot settings: %+v", rec)
	}
}

func TestAdminAPKPublishStoresArtifactAndRejectsRollback(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.cfg.UpdatePublicKey = mustText(pub)
	addApprovedWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/apk/draft", s.handleAdminAPKDraft)
	mux.HandleFunc("/admin/v1/apk/publish", s.handleAdminAPKPublish)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var login struct {
		OK           bool   `json:"ok"`
		SessionToken string `json:"session_token"`
	}
	postJSONForTest(t, ts.URL+"/admin/v1/login", map[string]string{"secret": "owner-secret"}, &login)
	apk := []byte("signed public apk bytes")
	manifest, err := buildAPKManifest(apkManifestInput{
		Seq:         1,
		VersionCode: 1002,
		VersionName: "public-1.0.1",
		APKSHA256:   sha256HexBytes(apk),
		APKSize:     int64(len(apk)),
		APKName:     "app-public-1002.apk",
		MinVersion:  1001,
		Notes:       "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	minisigText := string(minisign.Sign(priv, []byte(manifest)))
	publishResp := postAPKPublishForTest(t, ts.URL+"/admin/v1/apk/publish", login.SessionToken, apk, manifest, minisigText)
	if !publishResp.OK || publishResp.Release.Seq != 1 {
		t.Fatalf("bad publish response: %+v", publishResp)
	}
	rec, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok {
		t.Fatalf("missing release ok=%t err=%v", ok, err)
	}
	if rec.APKSHA256 != sha256HexBytes(apk) || rec.APKSize != int64(len(apk)) {
		t.Fatalf("bad stored release: %+v", rec)
	}
	artifact, err := s.loadUpdateArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if artifact == nil || artifact.ManifestJSON == "" || artifact.APKBase64 == "" {
		t.Fatalf("missing artifact: %+v", artifact)
	}
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	if workers[0].DesiredSeq < 2 {
		t.Fatalf("worker seq was not bumped: %+v", workers[0])
	}
	rollback := postAPKPublishStatusForTest(t, ts.URL+"/admin/v1/apk/publish", login.SessionToken, apk, manifest, minisigText)
	if rollback < 400 {
		t.Fatalf("rollback publish accepted: status=%d", rollback)
	}
	badManifest, err := buildAPKManifest(apkManifestInput{
		Seq:         2,
		VersionCode: 1003,
		VersionName: "public-1.0.2",
		APKSHA256:   sha256HexBytes(apk),
		APKSize:     int64(len(apk)),
		APKName:     "app-public-1003.apk",
	})
	if err != nil {
		t.Fatal(err)
	}
	badSig := postAPKPublishStatusForTest(t, ts.URL+"/admin/v1/apk/publish", login.SessionToken, apk, badManifest, "bad-signature")
	if badSig < 400 {
		t.Fatalf("bad signature publish accepted: status=%d", badSig)
	}
}

func TestAPKVersionMetadataExtractedFromBinaryManifestZip(t *testing.T) {
	apk := buildTestAPKWithManifest(t, 1010, "0.1.10")
	path := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(path, apk, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	version, err := inspectAPKVersion(file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	if version.VersionCode != 1010 || version.VersionName != "0.1.10" {
		t.Fatalf("bad apk version: %+v", version)
	}
}

func TestAdminAPKPublishAutoSignsWithServerUpdateKey(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.cfg.UpdatePublicKey = mustText(pub)
	privText, err := priv.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.StateDir, "update.key"), privText, 0o600); err != nil {
		t.Fatal(err)
	}
	addApprovedWorker(t, s)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/apk/status", s.handleAdminAPKStatus)
	mux.HandleFunc("/admin/v1/apk/publish", s.handleAdminAPKPublish)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var login struct {
		OK           bool   `json:"ok"`
		SessionToken string `json:"session_token"`
	}
	postJSONForTest(t, ts.URL+"/admin/v1/login", map[string]string{"secret": "owner-secret"}, &login)
	var status struct {
		OK              bool `json:"ok"`
		ServerUpdateKey bool `json:"server_update_key"`
	}
	adminJSONForTest(t, http.MethodGet, ts.URL+"/admin/v1/apk/status", login.SessionToken, nil, &status)
	if !status.OK || !status.ServerUpdateKey {
		t.Fatalf("server update key not advertised: %+v", status)
	}

	apk := buildTestAPKWithManifest(t, 1011, "0.1.11")
	publishResp := postAPKAutoPublishForTest(t, ts.URL+"/admin/v1/apk/publish", login.SessionToken, apk, map[string]string{
		"min_version": "1009",
		"notes":       "auto",
	})
	if !publishResp.OK || publishResp.Release.Seq != 1 {
		t.Fatalf("bad auto publish response: %+v", publishResp)
	}
	if publishResp.Release.VersionCode != 1011 || publishResp.Release.VersionName != "0.1.11" || publishResp.Release.MinVersion != 1009 {
		t.Fatalf("bad auto release metadata: %+v", publishResp.Release)
	}
	artifact, err := s.loadUpdateArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if artifact == nil {
		t.Fatal("missing update artifact")
	}
	if err := verifyManifestSignature(artifact.ManifestJSON, artifact.ManifestMinisig, s.cfg.UpdatePublicKey); err != nil {
		t.Fatalf("auto minisig did not verify: %v", err)
	}
}

func TestAdminAPKDownloadRequiresAuthAndServesCurrentRelease(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/apk/download", s.handleAdminAPKDownload)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	noAuthResp, err := http.Get(ts.URL + "/admin/v1/apk/download")
	if err != nil {
		t.Fatal(err)
	}
	_ = noAuthResp.Body.Close()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("download without auth status=%d", noAuthResp.StatusCode)
	}

	var login struct {
		SessionToken string `json:"session_token"`
	}
	postJSONForTest(t, ts.URL+"/admin/v1/login", map[string]string{"secret": "owner-secret"}, &login)
	missingReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/v1/apk/download", nil)
	missingReq.Header.Set("authorization", "Bearer "+login.SessionToken)
	missingResp, err := http.DefaultClient.Do(missingReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusNotFound {
		t.Fatalf("download without release status=%d", missingResp.StatusCode)
	}

	apkPath := filepath.Join(s.cfg.StateDir, "published.apk")
	apk := []byte("published apk bytes")
	if err := os.WriteFile(apkPath, apk, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.store.setAPKRelease(apkReleaseRecord{
		Seq:         1,
		VersionCode: 1002,
		VersionName: "public-1.0.1",
		APKName:     "app-public-1002.apk",
		APKSHA256:   sha256HexBytes(apk),
		APKSize:     int64(len(apk)),
		APKPath:     apkPath,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	downloadReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/v1/apk/download", nil)
	downloadReq.Header.Set("authorization", "Bearer "+login.SessionToken)
	downloadResp, err := http.DefaultClient.Do(downloadReq)
	if err != nil {
		t.Fatal(err)
	}
	downloadBody, _ := io.ReadAll(io.LimitReader(downloadResp.Body, 1<<20))
	_ = downloadResp.Body.Close()
	if downloadResp.StatusCode != http.StatusOK || string(downloadBody) != string(apk) {
		t.Fatalf("bad download status=%d body=%q", downloadResp.StatusCode, string(downloadBody))
	}
	if got := downloadResp.Header.Get("content-disposition"); !strings.Contains(got, "TrafficWrapper-1002.apk") {
		t.Fatalf("bad content-disposition: %q", got)
	}
}

func TestSeedUpdateAPKPublishesManifestWithGeneratedKey(t *testing.T) {
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
	if strings.TrimSpace(s.cfg.UpdatePublicKey) == "" {
		t.Fatal("generated update public key missing")
	}
	if err := s.seedUpdateAPKIfPresent(priv); err != nil {
		t.Fatal(err)
	}
	release, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok {
		t.Fatalf("seed release missing ok=%t err=%v", ok, err)
	}
	if release.Seq != 1 || release.VersionCode != 7 || release.VersionName != "seed-test" {
		t.Fatalf("bad seed release: %+v", release)
	}
	artifact, err := s.loadUpdateArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestSignature(artifact.ManifestJSON, artifact.ManifestMinisig, s.cfg.UpdatePublicKey); err != nil {
		t.Fatalf("seed minisig did not verify: %v", err)
	}
	if err := s.seedUpdateAPKIfPresent(priv); err != nil {
		t.Fatal(err)
	}
	again, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok || again.Seq != release.Seq {
		t.Fatalf("seed was not idempotent: ok=%t err=%v release=%+v", ok, err, again)
	}
}

func newTestServer(t *testing.T) *server {
	t.Helper()
	cfg := orchConfig{StateDir: t.TempDir(), PublicURL: "https://orch.example"}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.close() })
	return &server{
		cfg:    cfg,
		store:  st,
		signer: fakeSigner{},
	}
}

func addApprovedWorker(t *testing.T, s *server) {
	t.Helper()
	addApprovedWorkerWithStatic(t, s, "worker-static")
}

func addApprovedWorkerWithStatic(t *testing.T, s *server, staticPub string) workerRecord {
	t.Helper()
	rec, err := s.store.upsertPendingWorker(staticPub, map[string]any{
		"label":     "Worker A",
		"egress_ip": "203.0.113.5",
		"reality": map[string]any{
			"address":   "203.0.113.5",
			"port":      8444,
			"publicKey": "pub",
			"shortId":   "sid",
		},
		"awg": map[string]any{
			"endpoint":   "203.0.113.5:51888",
			"port":       51888,
			"public_key": "awgpub",
			"subnet":     "10.13.13.0/24",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	return rec
}

func enrollDeviceForTest(t *testing.T, s *server, token string) deviceEnrollResponse {
	t.Helper()
	return enrollDeviceForTestWithAWG(t, s, token, "device-awg-public")
}

func enrollDeviceForTestWithAWG(t *testing.T, s *server, token string, awgPublicKey string) deviceEnrollResponse {
	t.Helper()
	raw, _ := json.Marshal(deviceEnrollRequest{
		BootstrapToken:  token,
		DeviceID:        "android-id",
		IdentityPubKey:  "identity-pub",
		IdentityKeyType: "ed25519",
		AndroidID:       "android-id",
		Model:           "A15",
		EnrollmentNonce: "nonce",
		ClientVersion:   "public-test",
		AWGPublicKey:    awgPublicKey,
	})
	resp, err := s.handleDeviceEnroll(make([]byte, 32), raw)
	if err != nil {
		t.Fatal(err)
	}
	typed, ok := resp.(deviceEnrollResponse)
	if !ok {
		t.Fatalf("unexpected response type %T", resp)
	}
	return typed
}

func bootstrapTokenForTest(t *testing.T, s *server, id string) tokenRecord {
	t.Helper()
	var rec tokenRecord
	if err := s.store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketTokens).Get([]byte(id))
		if raw == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(raw, &rec)
	}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func tamperDeviceIdentityForTest(s *server, id string, identityPub string) error {
	return s.store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		raw := b.Get([]byte(id))
		if raw == nil {
			return os.ErrNotExist
		}
		var rec deviceRecord
		if err := s.store.openJSON(raw, &rec); err != nil {
			return err
		}
		rec.IdentityPubKey = identityPub
		sealed, err := s.store.sealJSON(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), sealed)
	})
}

func insertBootstrapToken(t *testing.T, st *orchStore, secret string, expiresAt time.Time) {
	t.Helper()
	hash, err := protocol.HashSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	rec := tokenRecord{
		ID:        "expired",
		Hash:      hash,
		Kind:      "bootstrap",
		ExpiresAt: expiresAt,
		MaxUses:   1,
		CreatedAt: time.Now(),
	}
	raw, _ := json.Marshal(rec)
	if err := st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Put([]byte(rec.ID), raw)
	}); err != nil {
		t.Fatal(err)
	}
}

func signedTelemetryHeadersForTest(t *testing.T, key *ecdsa.PrivateKey, deviceID, publicKey string, payload []byte) map[string]string {
	t.Helper()
	sum := sha256.Sum256(payload)
	ts := "1710000000001"
	nonce := "test-nonce"
	canonical := strings.Join([]string{
		telemetrySignatureDomain,
		deviceID,
		ts,
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonical))
	sig, err := ecdsa.SignASN1(rand.Reader, key, canonicalHash[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"X-TW-Device":  deviceID,
		"X-TW-Pub":     publicKey,
		"X-TW-KeyType": "ecdsa-p256-sha256",
		"X-TW-Ts":      ts,
		"X-TW-Nonce":   nonce,
		"X-TW-Sig":     base64.StdEncoding.EncodeToString(sig),
	}
}

func noiseCallForTest(t *testing.T, baseURL string, serverPub []byte, static noise.DHKey, path string, req any, resp any) {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(protocol.Prologue),
		StaticKeypair: static,
		PeerStatic:    serverPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var start startResponse
	postJSONForTest(t, baseURL+"/d/v1/handshake/start", startRequest{Message: base64.StdEncoding.EncodeToString(msg1)}, &start)
	if !start.OK {
		t.Fatalf("handshake start failed: %+v", start)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		t.Fatal(err)
	}
	msg3, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncryptJSON(sendCipher, req)
	if err != nil {
		t.Fatal(err)
	}
	var envResp noiseEnvelopeResponse
	postJSONForTest(t, baseURL+path, noiseEnvelope{
		SID:     start.SID,
		Message: base64.StdEncoding.EncodeToString(msg3),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}, &envResp)
	if !envResp.OK {
		t.Fatalf("noise envelope failed: %+v", envResp)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envResp.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.DecryptJSON(recvCipher, encrypted, resp); err != nil {
		t.Fatal(err)
	}
}

func postJSONForTest(t *testing.T, url string, req any, resp any) {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpResp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if httpResp.StatusCode >= 300 {
		t.Fatalf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, strings.TrimSpace(string(body)))
	}
}

func adminJSONForTest(t *testing.T, method, url, token string, req any, resp any) {
	t.Helper()
	var body io.Reader
	if req != nil {
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	httpReq, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if req != nil {
		httpReq.Header.Set("content-type", "application/json")
	}
	httpReq.Header.Set("authorization", "Bearer "+token)
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if httpResp.StatusCode >= 300 {
		t.Fatalf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, strings.TrimSpace(string(raw)))
	}
}

func postAPKPublishForTest(t *testing.T, url, token string, apk []byte, manifest, minisigText string) struct {
	OK      bool             `json:"ok"`
	Release apkReleaseRecord `json:"release"`
} {
	t.Helper()
	var out struct {
		OK      bool             `json:"ok"`
		Release apkReleaseRecord `json:"release"`
	}
	resp := postAPKPublishRequestForTest(t, url, token, apk, manifest, minisigText)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		t.Fatalf("publish http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func postAPKPublishStatusForTest(t *testing.T, url, token string, apk []byte, manifest, minisigText string) int {
	t.Helper()
	resp := postAPKPublishRequestForTest(t, url, token, apk, manifest, minisigText)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func postAPKPublishRequestForTest(t *testing.T, url, token string, apk []byte, manifest, minisigText string) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("apk", "app-public-test.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(apk); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("manifest_json", manifest); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("manifest_minisig", minisigText); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", writer.FormDataContentType())
	req.Header.Set("authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postAPKAutoPublishForTest(t *testing.T, url, token string, apk []byte, fields map[string]string) struct {
	OK      bool             `json:"ok"`
	Release apkReleaseRecord `json:"release"`
} {
	t.Helper()
	var out struct {
		OK      bool             `json:"ok"`
		Release apkReleaseRecord `json:"release"`
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("apk", "app-public-test.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(apk); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", writer.FormDataContentType())
	req.Header.Set("authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		t.Fatalf("auto publish http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func buildTestAPKWithManifest(t *testing.T, versionCode int64, versionName string) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	manifest, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write(buildTestBinaryManifest(t, versionCode, versionName)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func buildTestBinaryManifest(t *testing.T, versionCode int64, versionName string) []byte {
	t.Helper()
	pool := buildTestAXMLStringPool(t, []string{
		"manifest",
		"http://schemas.android.com/apk/res/android",
		"versionCode",
		"versionName",
		versionName,
	})
	start := buildTestAXMLManifestStart(t, versionCode)
	total := 8 + len(pool) + len(start)
	var out bytes.Buffer
	writeTestChunkHeader(&out, 0x0003, 8, uint32(total))
	out.Write(pool)
	out.Write(start)
	return out.Bytes()
}

func buildTestAXMLStringPool(t *testing.T, values []string) []byte {
	t.Helper()
	var data bytes.Buffer
	offsets := make([]uint32, 0, len(values))
	for _, value := range values {
		if len(value) > 127 {
			t.Fatalf("test string too long: %q", value)
		}
		offsets = append(offsets, uint32(data.Len()))
		data.WriteByte(byte(len([]rune(value))))
		data.WriteByte(byte(len(value)))
		data.WriteString(value)
		data.WriteByte(0)
	}
	for data.Len()%4 != 0 {
		data.WriteByte(0)
	}
	headerSize := uint32(28)
	stringsStart := headerSize + uint32(len(values))*4
	chunkSize := stringsStart + uint32(data.Len())
	var out bytes.Buffer
	writeTestChunkHeader(&out, 0x0001, uint16(headerSize), chunkSize)
	writeTestU32(&out, uint32(len(values)))
	writeTestU32(&out, 0)
	writeTestU32(&out, 0x00000100)
	writeTestU32(&out, stringsStart)
	writeTestU32(&out, 0)
	for _, offset := range offsets {
		writeTestU32(&out, offset)
	}
	out.Write(data.Bytes())
	return out.Bytes()
}

func buildTestAXMLManifestStart(t *testing.T, versionCode int64) []byte {
	t.Helper()
	if versionCode <= 0 || versionCode > int64(^uint32(0)) {
		t.Fatalf("bad version code: %d", versionCode)
	}
	const chunkSize = 36 + 20*2
	var out bytes.Buffer
	writeTestChunkHeader(&out, 0x0102, 36, chunkSize)
	writeTestU32(&out, 1)
	writeTestU32(&out, ^uint32(0))
	writeTestU32(&out, ^uint32(0))
	writeTestU32(&out, 0)
	writeTestU16(&out, 20)
	writeTestU16(&out, 20)
	writeTestU16(&out, 2)
	writeTestU16(&out, 0)
	writeTestU16(&out, 0)
	writeTestU16(&out, 0)
	writeTestAXMLAttr(&out, 1, 2, ^uint32(0), 0x10, uint32(versionCode))
	writeTestAXMLAttr(&out, 1, 3, 4, 0x03, 4)
	return out.Bytes()
}

func writeTestAXMLAttr(out *bytes.Buffer, ns, name, rawValue uint32, dataType byte, data uint32) {
	writeTestU32(out, ns)
	writeTestU32(out, name)
	writeTestU32(out, rawValue)
	writeTestU16(out, 8)
	out.WriteByte(0)
	out.WriteByte(dataType)
	writeTestU32(out, data)
}

func writeTestChunkHeader(out *bytes.Buffer, chunkType, headerSize uint16, chunkSize uint32) {
	writeTestU16(out, chunkType)
	writeTestU16(out, headerSize)
	writeTestU32(out, chunkSize)
}

func writeTestU16(out *bytes.Buffer, value uint16) {
	var raw [2]byte
	binary.LittleEndian.PutUint16(raw[:], value)
	out.Write(raw[:])
}

func writeTestU32(out *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	out.Write(raw[:])
}

type fakeSigner struct{}

func (fakeSigner) publicKey() (string, error) { return "RWQtest", nil }

func (fakeSigner) sign(message string) (signedConfig, error) {
	return signedConfig{
		ConfigJSON:   message,
		Minisig:      "trusted-signature",
		PublicKey:    "RWQtest",
		ConfigSHA256: sha256Hex(message),
	}, nil
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sha256HexBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestAdminBaseURLPrefersLoopbackListener(t *testing.T) {
	cfg := orchConfig{
		Listen:    ":9091",
		PublicURL: "https://public.example:9091",
		TLS:       true,
	}
	if got := adminBaseURL(cfg); got != "https://127.0.0.1:9091" {
		t.Fatalf("admin base url = %q", got)
	}
	cfg.Listen = "0.0.0.0:9443"
	if got := adminBaseURL(cfg); got != "https://127.0.0.1:9443" {
		t.Fatalf("admin base url = %q", got)
	}
	cfg.Listen = "127.0.0.1:8080"
	cfg.TLS = false
	if got := adminBaseURL(cfg); got != "http://127.0.0.1:8080" {
		t.Fatalf("admin base url = %q", got)
	}
}

func TestSeedWorkerURLFromRealitySelfDescribe(t *testing.T) {
	rec := workerRecord{
		Status: "approved",
		SelfDescribe: map[string]any{
			"reality": map[string]any{
				"address": "worker.example",
				"port":    float64(2053),
			},
		},
	}
	if got := seedWorkerURL(rec); got != "https://worker.example:2053/tw" {
		t.Fatalf("seed worker url = %q", got)
	}
}

func TestDefaultSeedWorkersIncludesActiveWorkers(t *testing.T) {
	fresh := time.Now().UTC().Add(-time.Minute)
	stale := time.Now().UTC().Add(-3 * time.Minute)
	workers := []workerRecord{
		{
			Status:    "active",
			LastAckAt: &fresh,
			SelfDescribe: map[string]any{
				"reality": map[string]any{
					"address": "active.example",
					"port":    float64(2053),
				},
			},
		},
		{
			Status:    "approved",
			LastAckAt: &fresh,
			SelfDescribe: map[string]any{
				"reality": map[string]any{
					"address": "approved.example",
					"port":    float64(2053),
				},
			},
		},
		{
			Status:    "active",
			Disabled:  true,
			LastAckAt: &fresh,
			SelfDescribe: map[string]any{
				"reality": map[string]any{
					"address": "disabled.example",
					"port":    float64(2053),
				},
			},
		},
		{
			Status:    "active",
			LastAckAt: &stale,
			SelfDescribe: map[string]any{
				"reality": map[string]any{
					"address": "stale.example",
					"port":    float64(2053),
				},
			},
		},
		{
			Status: "pending",
			SelfDescribe: map[string]any{
				"reality": map[string]any{
					"address": "pending.example",
					"port":    float64(2053),
				},
			},
		},
	}
	got := defaultSeedWorkersFromRecords(workers)
	want := []string{"https://active.example:2053/tw", "https://approved.example:2053/tw"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("default seed workers = %#v, want %#v", got, want)
	}
}

func TestWebConfigSeqUsesLoadedWorkersOnly(t *testing.T) {
	workers := []workerRecord{
		{Status: "pending", DesiredSeq: 100},
		{Status: "approved", DesiredSeq: 3},
		{Status: "active", DesiredSeq: 7},
	}
	if got := webConfigSeq(workers); got != 7 {
		t.Fatalf("webConfigSeq = %d, want 7", got)
	}
	if got := webConfigSeq(nil); got != 1 {
		t.Fatalf("webConfigSeq(nil) = %d, want 1", got)
	}
}

func TestClientRoutePayloadIncludesCanonicalParams(t *testing.T) {
	reality, ok := clientRoutePayload("reality", map[string]any{
		"address":    "worker.example",
		"port":       2053,
		"publicKey":  "reality-pub",
		"shortId":    "short-id",
		"serverName": "www.microsoft.com",
		"region":     "Operator Lab",
	}, "198.51.100.8", "http://awg-gw:8080/tw")
	if !ok {
		t.Fatal("reality route was not built")
	}
	params, ok := reality["params"].(map[string]any)
	if !ok {
		t.Fatalf("reality params missing: %#v", reality["params"])
	}
	if params["public_key"] != "reality-pub" || params["short_id"] != "short-id" ||
		params["server_name"] != "www.microsoft.com" {
		t.Fatalf("bad reality params: %#v", params)
	}
	if flow, ok := params["flow"].(string); ok && flow != "" {
		t.Fatalf("reality flow should not be forced by orchestrator: %#v", params)
	}
	if params["network"] != "tcp" {
		t.Fatalf("reality network default = %#v, want tcp", params["network"])
	}
	if reality["expected_egress_ip"] != "198.51.100.8" || reality["config_url"] != "http://awg-gw:8080/tw" {
		t.Fatalf("bad reality route: %#v", reality)
	}
	if reality["region"] != "Operator Lab" || params["region"] != "Operator Lab" {
		t.Fatalf("route region was not preserved: route=%#v params=%#v", reality, params)
	}

	xhttpRoute, ok := clientRoutePayload("reality", map[string]any{
		"address":    "worker.example",
		"port":       443,
		"public_key": "reality-pub",
		"short_id":   "short-id",
		"serverName": "www.microsoft.com",
		"network":    "xhttp",
		"flow":       "xtls-rprx-vision",
		"xhttp": map[string]any{
			"host":  "cdn.operator.example",
			"path":  "/operator-path",
			"mode":  "auto",
			"extra": map[string]any{"headers": map[string]any{"X-Test": "1"}},
		},
	}, "198.51.100.8", "")
	if !ok {
		t.Fatal("xhttp reality route was not built")
	}
	xhttpParams := xhttpRoute["params"].(map[string]any)
	if xhttpParams["network"] != "xhttp" {
		t.Fatalf("xhttp network not preserved: %#v", xhttpParams)
	}
	xhttp := xhttpParams["xhttp"].(map[string]any)
	if xhttp["host"] != "cdn.operator.example" || xhttp["path"] != "/operator-path" || xhttp["mode"] != "auto" {
		t.Fatalf("xhttp params not preserved: %#v", xhttp)
	}
	if _, ok := xhttpParams["flow"]; ok {
		t.Fatalf("xhttp route should not include vision flow: %#v", xhttpParams)
	}

	awg, ok := clientRoutePayload("awg", map[string]any{
		"endpoint":   "worker.example:51888",
		"public_key": "awg-server-pub",
		"dialect":    map[string]any{"jc": 4},
	}, "198.51.100.8", "")
	if !ok {
		t.Fatal("awg route was not built")
	}
	awgParams, ok := awg["params"].(map[string]any)
	if !ok {
		t.Fatalf("awg params missing: %#v", awg["params"])
	}
	if awg["address"] != "worker.example" || awg["port"] != 51888 {
		t.Fatalf("bad awg endpoint parse: %#v", awg)
	}
	if awgParams["server_public"] != "awg-server-pub" || awgParams["server_public_key"] != "awg-server-pub" {
		t.Fatalf("bad awg params: %#v", awgParams)
	}
	if awg["dialect_id"] == "" || awgParams["dialect_id"] == "" {
		t.Fatalf("dialect id missing: route=%#v params=%#v", awg, awgParams)
	}
}
