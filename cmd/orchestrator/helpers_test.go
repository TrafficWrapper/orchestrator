package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	bolt "go.etcd.io/bbolt"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

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
			"publicKey": testRealityPublicKey,
			"shortId":   "sid",
		},
		"awg": map[string]any{
			"endpoint":   "203.0.113.5:51888",
			"port":       51888,
			"public_key": testAWGPublicKey,
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
		if err := s.store.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		rec.IdentityPubKey = identityPub
		sealed, err := s.store.sealJSON(bucketDevices, []byte(id), rec)
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
	return signedTelemetryHeadersForTestAt(t, key, deviceID, publicKey, payload, time.Now().UTC(), "test-nonce")
}

func signedTelemetryHeadersForTestAt(t *testing.T, key *ecdsa.PrivateKey, deviceID, publicKey string, payload []byte, ts time.Time, nonce string) map[string]string {
	t.Helper()
	sum := sha256.Sum256(payload)
	tsText := strconv.FormatInt(ts.UnixMilli(), 10)
	canonical := strings.Join([]string{
		telemetrySignatureDomain,
		deviceID,
		tsText,
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
		"X-TW-Ts":      tsText,
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

func buildTestBinaryManifest(t testing.TB, versionCode int64, versionName string) []byte {
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

func buildTestAXMLStringPool(t testing.TB, values []string) []byte {
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

func buildTestAXMLManifestStart(t testing.TB, versionCode int64) []byte {
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

// Well-formed keys for worker fixtures (32 zero bytes), so self_describe
// validation stays quiet in tests that are not about it.
const (
	testRealityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testAWGPublicKey     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
