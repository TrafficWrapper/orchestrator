package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aead.dev/minisign"
	"github.com/flynn/noise"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type orchConfig struct {
	StateDir                string
	Listen                  string
	SignerSocket            string
	PublicURL               string
	EgressProbeURL          string
	AdminSecret             string
	UpdatePublicKey         string
	DNSServers              []string
	DiscoveryNextSinks      []string
	DiscoveryRescuePointers []string
	SeedAPKPath             string
	SeedVersionCode         int64
	SeedVersionName         string
	APKKeepReleases         int
	TLS                     bool
}

type server struct {
	cfg            orchConfig
	store          *orchStore
	signer         configSigner
	static         noise.DHKey
	sessions       sync.Map
	sessionCount   atomic.Int64
	handshakeMu    sync.Mutex
	handshakeRates map[string]handshakeRate
	handshakePrune time.Time
	loginLimiterMu sync.Mutex
	loginLimiter   *loginLimiter
	audit          *auditLog
	discoverySeqMu sync.Mutex
	adminSessions  sync.Map
	botMu          sync.Mutex
	authApprover   authApprover
	bot            *telegramBot
	botCancel      context.CancelFunc
	botFactory     telegramClientFactory
}

type noiseSession struct {
	hs        *noise.HandshakeState
	createdAt time.Time
}

type handshakeRate struct {
	WindowStart time.Time
	Count       int
}

type adminSession struct {
	Token      string
	CSRFToken  string
	ExpiresAt  time.Time
	MustChange bool
}

type startRequest struct {
	Message string `json:"message"`
}

type startResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	SID     string `json:"sid,omitempty"`
	Message string `json:"message,omitempty"`
}

type noiseEnvelope struct {
	SID     string `json:"sid"`
	Message string `json:"message"`
	Payload string `json:"payload"`
}

type noiseEnvelopeResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type enrollRequest struct {
	Token           string         `json:"token"`
	WorkerStaticPub string         `json:"worker_static_pub"`
	SelfDescribe    map[string]any `json:"self_describe"`
}

type enrollResponse struct {
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
	WorkerID        string `json:"worker_id,omitempty"`
	Status          string `json:"status,omitempty"`
	SignerPublicKey string `json:"signer_public_key,omitempty"`
}

type deviceEnrollRequest struct {
	BootstrapToken  string `json:"bootstrap_token"`
	NoisePublicKey  string `json:"noise_public_key,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	AndroidID       string `json:"android_id,omitempty"`
	Model           string `json:"model,omitempty"`
	IdentityPubKey  string `json:"identity_pubkey"`
	IdentityKeyType string `json:"identity_key_type,omitempty"`
	EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	AWGPublicKey    string `json:"awg_public_key,omitempty"`
}

type deviceEnrollResponse struct {
	OK              bool                        `json:"ok"`
	Error           string                      `json:"error,omitempty"`
	DeviceID        string                      `json:"device_id,omitempty"`
	Status          string                      `json:"status,omitempty"`
	RealityUUID     string                      `json:"reality_uuid,omitempty"`
	InternalIP      string                      `json:"internal_ip,omitempty"`
	PSK2            string                      `json:"psk2,omitempty"`
	AWGProfiles     map[string]deviceAWGProfile `json:"awg_profiles,omitempty"`
	ServerAWGPublic string                      `json:"server_awg_public,omitempty"`
	SignerPublicKey string                      `json:"signer_public_key,omitempty"`
	ClientBundle    signedConfig                `json:"client_bundle,omitempty"`
}

type bootstrapPayload struct {
	OrchestratorURL string          `json:"orchestrator_url"`
	ConfigPubkeyPin string          `json:"config_pubkey_pin"`
	OrchNoisePublic string          `json:"orch_noise_public"`
	UpdatePubkey    string          `json:"update_pubkey,omitempty"`
	SeedWorkers     []string        `json:"seed_workers"`
	BootstrapToken  string          `json:"bootstrap_token"`
	Limits          json.RawMessage `json:"limits,omitempty"`
	Expires         string          `json:"expires"`
}

type pullRequest struct {
	WorkerID string `json:"worker_id"`
	HaveSeq  int64  `json:"have_seq"`
}

type pullResponse struct {
	OK           bool            `json:"ok"`
	Error        string          `json:"error,omitempty"`
	Status       string          `json:"status,omitempty"`
	WorkerID     string          `json:"worker_id,omitempty"`
	DesiredSeq   int64           `json:"desired_seq,omitempty"`
	NotModified  bool            `json:"not_modified,omitempty"`
	WorkerBundle signedConfig    `json:"worker_bundle,omitempty"`
	ClientBundle signedConfig    `json:"client_bundle,omitempty"`
	Update       *updateArtifact `json:"update,omitempty"`
}

type updateArtifact struct {
	ManifestJSON    string `json:"manifest_json,omitempty"`
	ManifestMinisig string `json:"manifest_minisig,omitempty"`
	APKName         string `json:"apk_name,omitempty"`
	APKSHA256       string `json:"apk_sha256,omitempty"`
	APKBase64       string `json:"apk_base64,omitempty"`
}

type ackRequest struct {
	WorkerID         string         `json:"worker_id"`
	AppliedVersion   int64          `json:"applied_version"`
	SelfCheck        string         `json:"self_check"`
	EgressIPObserved string         `json:"egress_ip_observed"`
	SelfDescribe     map[string]any `json:"self_describe,omitempty"`
	Usage            []deviceUsage  `json:"usage,omitempty"`
}

type ackResponse struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	DesiredSeq    int64  `json:"desired_seq,omitempty"`
	AppliedSeq    int64  `json:"applied_seq,omitempty"`
	EgressIPProbe string `json:"egress_ip_probe,omitempty"`
	EgressMatch   bool   `json:"egress_match"`
	QuotaBlocks   int    `json:"quota_blocks,omitempty"`
}

type deviceUsage struct {
	DeviceID     string `json:"device_id,omitempty"`
	AWGPublicKey string `json:"awg_public_key,omitempty"`
	RxBytes      uint64 `json:"rx_bytes,omitempty"`
	TxBytes      uint64 `json:"tx_bytes,omitempty"`
}

type nudgeRequest struct {
	WorkerID     string         `json:"worker_id"`
	HaveSeq      int64          `json:"have_seq"`
	SelfDescribe map[string]any `json:"self_describe,omitempty"`
}

type workerTelemetryRequest struct {
	WorkerID      string            `json:"worker_id"`
	PayloadBase64 string            `json:"payload_base64"`
	Headers       map[string]string `json:"headers,omitempty"`
	ReceivedAt    string            `json:"received_at,omitempty"`
}

const (
	telemetrySignatureDomain = "TrafficWrapper telemetry v1"
	telemetryMaxPayloadBytes = 64 << 10
	noiseSessionTTL          = 30 * time.Second
	noiseSessionJanitorEvery = 5 * time.Second
	maxNoiseSessions         = 1024
	handshakeRateWindow      = 10 * time.Second
	handshakeRateLimit       = 30
	handshakeRatePruneEvery  = time.Second
	maxHandshakeRateKeys     = 64 * 1024
	workerFreshTTL           = 2 * time.Minute
	workerJanitorEvery       = 30 * time.Second
)

type nudgeResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DesiredSeq int64  `json:"desired_seq,omitempty"`
	Heartbeat  bool   `json:"heartbeat,omitempty"`
}

type signedConfig struct {
	ConfigJSON   string `json:"config_json,omitempty"`
	Minisig      string `json:"minisig,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

func main() {
	if err := runMain(); err != nil {
		log.Printf("orchestrator: %v", err)
		os.Exit(1)
	}
}

func runMain() error {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	cfg := readConfig()
	switch cmd {
	case "serve":
		return runServe(cfg)
	case "signer":
		return runSigner(cfg)
	case "public-key":
		static, err := loadOrCreateStaticKey(cfg)
		if err != nil {
			return err
		}
		fmt.Println(protocol.KeyToBase64(static.Public))
		return nil
	case "token":
		return tokenCommand(cfg, os.Args[2:])
	case "bootstrap-token":
		return bootstrapTokenCommand(cfg, os.Args[2:])
	case "admin":
		return adminCommand(cfg, os.Args[2:])
	case "bot":
		return botCommand(cfg, os.Args[2:])
	case "device-enroll-smoke":
		return deviceEnrollSmokeCommand(cfg, os.Args[2:])
	case "revoke-device":
		if len(os.Args) < 3 {
			return errors.New("revoke-device requires device id")
		}
		if err := adminPost(cfg, "/admin/v1/revoke-device", map[string]string{"id": os.Args[2]}, os.Stdout); err == nil {
			return nil
		}
		st, err := openOrchStore(cfg)
		if err != nil {
			return err
		}
		defer st.close()
		return st.revokeDevice(os.Args[2])
	case "approve-worker":
		if len(os.Args) < 3 {
			return errors.New("approve-worker requires worker id")
		}
		if err := adminPost(cfg, "/admin/v1/approve-worker", map[string]string{"id": os.Args[2]}, os.Stdout); err == nil {
			return nil
		}
		st, err := openOrchStore(cfg)
		if err != nil {
			return err
		}
		defer st.close()
		return st.approveWorker(os.Args[2])
	case "status":
		return statusCommand(cfg)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func readConfig() orchConfig {
	return orchConfig{
		StateDir:                getenv("ORCH_STATE_DIR", "./orch-state"),
		Listen:                  getenv("ORCH_LISTEN", ":9091"),
		SignerSocket:            getenv("ORCH_SIGNER_SOCKET", "./orch-state/signer.sock"),
		PublicURL:               getenv("ORCH_PUBLIC_URL", "https://127.0.0.1:9091"),
		EgressProbeURL:          os.Getenv("ORCH_EGRESS_PROBE_URL"),
		AdminSecret:             os.Getenv("ORCH_ADMIN_SECRET"),
		UpdatePublicKey:         os.Getenv("ORCH_UPDATE_PUBKEY"),
		DNSServers:              splitCSV(os.Getenv("ORCH_DNS_SERVERS")),
		DiscoveryNextSinks:      splitCSV(os.Getenv("ORCH_DISCOVERY_NEXT_SINKS")),
		DiscoveryRescuePointers: splitCSV(os.Getenv("ORCH_DISCOVERY_RESCUE_POINTERS")),
		SeedAPKPath:             getenv("SEED_APK_PATH", "./seed/app.apk"),
		SeedVersionCode:         getenvInt64("SEED_APK_VERSION_CODE", 1),
		SeedVersionName:         getenv("SEED_APK_VERSION_NAME", "seed"),
		APKKeepReleases:         getenvInt("ORCH_APK_KEEP_RELEASES", 5),
		TLS:                     getenv("ORCH_TLS", "1") != "0",
	}
}

func runServe(cfg orchConfig) error {
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	initialPassword, generated, err := st.ensureAdminPassword(cfg.AdminSecret)
	if err != nil {
		return err
	}
	if generated {
		log.Printf("Initial admin password (change on first login): %s", initialPassword)
	}
	updatePrivate, err := loadOrCreateUpdateSigningKey(&cfg)
	if err != nil {
		return err
	}
	static, err := loadOrCreateStaticKey(cfg)
	if err != nil {
		return err
	}
	audit, err := openAuditLog(filepath.Join(cfg.StateDir, "audit.log"))
	if err != nil {
		return err
	}
	defer audit.Close()
	s := &server{cfg: cfg, store: st, signer: signerClient{socket: cfg.SignerSocket}, static: static, loginLimiter: newLoginLimiter(), audit: audit}
	if _, err := s.signer.publicKey(); err != nil {
		return fmt.Errorf("signer unavailable: %w", err)
	}
	if err := s.seedUpdateAPKIfPresent(updatePrivate); err != nil {
		return err
	}
	if err := s.startOptionalBot(context.Background(), newTelegramHTTPClient); err != nil {
		return err
	}
	go s.runNoiseSessionJanitor(context.Background())
	go s.runWorkerJanitor(context.Background())
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/discovery/endpoints.json", s.handleDiscoveryEndpointsJSON)
	mux.HandleFunc("/discovery/endpoints.json.minisig", s.handleDiscoveryEndpointsMinisig)
	s.registerWebRoutes(mux)
	mux.HandleFunc("/w/v1/handshake/start", s.handleHandshakeStart)
	mux.HandleFunc("/w/v1/enroll", s.handleNoise(s.handleEnroll))
	mux.HandleFunc("/w/v1/config/pull", s.handleNoise(s.handlePull))
	mux.HandleFunc("/w/v1/nudge/wait", s.handleNoiseContext(s.handleNudge))
	mux.HandleFunc("/w/v1/ack", s.handleNoise(s.handleAck))
	mux.HandleFunc("/w/v1/telemetry", s.handleNoise(s.handleWorkerTelemetry))
	mux.HandleFunc("/d/v1/handshake/start", s.handleHandshakeStart)
	mux.HandleFunc("/d/v1/enroll", s.handleNoise(s.handleDeviceEnroll))
	mux.HandleFunc("/admin/v1/login", s.handleAdminLogin)
	mux.HandleFunc("/admin/v1/password/change", s.handleAdminPasswordChange)
	mux.HandleFunc("/admin/v1/password/force-set", s.handleAdminPasswordForceSet)
	mux.HandleFunc("/admin/v1/totp/enroll", s.handleAdminTOTPEnroll)
	mux.HandleFunc("/admin/v1/totp/enable", s.handleAdminTOTPEnable)
	mux.HandleFunc("/admin/v1/totp/disable", s.handleAdminTOTPDisable)
	mux.HandleFunc("/admin/v1/bot/status", s.handleAdminBotStatus)
	mux.HandleFunc("/admin/v1/bot/set-token", s.handleAdminBotSetToken)
	mux.HandleFunc("/admin/v1/token/create", s.handleAdminTokenCreate)
	mux.HandleFunc("/admin/v1/bootstrap-token/create", s.handleAdminBootstrapTokenCreate)
	mux.HandleFunc("/admin/v1/bootstrap-token/qr", s.handleAdminBootstrapTokenQR)
	mux.HandleFunc("/admin/v1/approve-worker", s.handleAdminApproveWorker)
	mux.HandleFunc("/admin/v1/revoke-device", s.handleAdminRevokeDevice)
	mux.HandleFunc("/admin/v1/delete-device", s.handleAdminDeleteDevice)
	mux.HandleFunc("/admin/v1/device-alias", s.handleAdminDeviceAlias)
	mux.HandleFunc("/admin/v1/workers", s.handleAdminWorkers)
	mux.HandleFunc("/admin/v1/workers/set-enabled", s.handleAdminWorkerSetEnabled)
	mux.HandleFunc("/admin/v1/workers/protocol", s.handleAdminWorkerProtocol)
	mux.HandleFunc("/admin/v1/devices", s.handleAdminDevices)
	mux.HandleFunc("/admin/v1/config", s.handleAdminConfig)
	mux.HandleFunc("/admin/v1/config/edit", s.handleAdminConfigEdit)
	mux.HandleFunc("/admin/v1/apk/status", s.handleAdminAPKStatus)
	mux.HandleFunc("/admin/v1/apk/download", s.handleAdminAPKDownload)
	mux.HandleFunc("/admin/v1/apk/inspect", s.handleAdminAPKInspect)
	mux.HandleFunc("/admin/v1/apk/draft", s.handleAdminAPKDraft)
	mux.HandleFunc("/admin/v1/apk/publish", s.handleAdminAPKPublish)
	mux.HandleFunc("/admin/v1/discovery/bump", s.handleAdminDiscoveryBump)
	mux.HandleFunc("/admin/v1/status", s.handleAdminStatus)
	addr := cfg.Listen
	log.Printf("orchestrator serve listen=%s tls=%t public_key=%s", addr, cfg.TLS, protocol.KeyToBase64(static.Public))
	if cfg.TLS {
		cert, key, err := loadOrCreateTLS(cfg)
		if err != nil {
			return err
		}
		return http.ListenAndServeTLS(addr, cert, key, mux)
	}
	return http.ListenAndServe(addr, mux)
}

func (s *server) handleHandshakeStart(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	reserved, reason := s.reserveHandshakeStart(r)
	if !reserved {
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, startResponse{OK: false, Error: reason})
		return
	}
	stored := false
	defer func() {
		if !stored {
			s.sessionCount.Add(-1)
		}
	}()
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	msg1, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeJSON(w, startResponse{OK: false, Error: "bad message"})
		return
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     false,
		Prologue:      []byte(protocol.Prologue),
		StaticKeypair: s.static,
	})
	if err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	msg2, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	sid := randID()
	s.sessions.Store(sid, noiseSession{hs: hs, createdAt: time.Now()})
	stored = true
	writeJSON(w, startResponse{OK: true, SID: sid, Message: base64.StdEncoding.EncodeToString(msg2)})
}

func (s *server) reserveHandshakeStart(r *http.Request) (bool, string) {
	now := time.Now()
	key := rateLimitKey(clientIP(r))
	s.handshakeMu.Lock()
	if s.handshakeRates == nil {
		s.handshakeRates = map[string]handshakeRate{}
	}
	s.pruneHandshakeRatesLocked(now)
	rate, exists := s.handshakeRates[key]
	if !exists && len(s.handshakeRates) >= maxHandshakeRateKeys {
		s.handshakeMu.Unlock()
		return false, "handshake rate limit exceeded"
	}
	if rate.WindowStart.IsZero() || now.Sub(rate.WindowStart) > handshakeRateWindow {
		rate = handshakeRate{WindowStart: now}
	}
	if rate.Count >= handshakeRateLimit {
		s.handshakeMu.Unlock()
		return false, "handshake rate limit exceeded"
	}
	rate.Count++
	s.handshakeRates[key] = rate
	s.handshakeMu.Unlock()
	if s.sessionCount.Add(1) > maxNoiseSessions {
		s.sessionCount.Add(-1)
		return false, "too many pending handshakes"
	}
	return true, ""
}

func (s *server) pruneHandshakeRatesLocked(now time.Time) {
	if !s.handshakePrune.IsZero() && now.After(s.handshakePrune) && now.Sub(s.handshakePrune) < handshakeRatePruneEvery {
		return
	}
	s.handshakePrune = now
	for key, rate := range s.handshakeRates {
		if rate.WindowStart.IsZero() || now.Sub(rate.WindowStart) > 2*handshakeRateWindow {
			delete(s.handshakeRates, key)
		}
	}
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func (s *server) runNoiseSessionJanitor(ctx context.Context) {
	ticker := time.NewTicker(noiseSessionJanitorEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-noiseSessionTTL)
			s.sessions.Range(func(key, value any) bool {
				sess, ok := value.(noiseSession)
				if !ok || sess.createdAt.Before(cutoff) {
					if _, loaded := s.sessions.LoadAndDelete(key); loaded {
						s.sessionCount.Add(-1)
					}
				}
				return true
			})
		}
	}
}

func (s *server) handleNoise(fn func([]byte, []byte) (any, error)) http.HandlerFunc {
	return s.handleNoiseContext(func(_ context.Context, peer []byte, raw []byte) (any, error) {
		return fn(peer, raw)
	})
}

func (s *server) handleNoiseContext(fn func(context.Context, []byte, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var env noiseEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: err.Error()})
			return
		}
		v, ok := s.sessions.LoadAndDelete(env.SID)
		if !ok {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "noise session expired"})
			return
		}
		s.sessionCount.Add(-1)
		sess := v.(noiseSession)
		if time.Since(sess.createdAt) > noiseSessionTTL {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "noise session expired"})
			return
		}
		msg3, err := base64.StdEncoding.DecodeString(env.Message)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "bad message"})
			return
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "bad payload"})
			return
		}
		_, recvCipher, sendCipher, err := sess.hs.ReadMessage(nil, msg3)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: err.Error()})
			return
		}
		peer := append([]byte(nil), sess.hs.PeerStatic()...)
		resp, err := fn(r.Context(), peer, decryptBytes(recvCipher, payload))
		if err != nil {
			resp = map[string]any{"ok": false, "error": err.Error()}
		}
		encrypted, err := protocol.EncryptJSON(sendCipher, resp)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, noiseEnvelopeResponse{OK: true, Payload: base64.StdEncoding.EncodeToString(encrypted)})
	}
}

func decryptBytes(cipher *noise.CipherState, payload []byte) []byte {
	plain, err := cipher.Decrypt(nil, nil, payload)
	if err != nil {
		return []byte(`{"_decrypt_error":"` + err.Error() + `"}`)
	}
	return plain
}

func (s *server) handleEnroll(peer []byte, raw []byte) (any, error) {
	var req enrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	staticPub := protocol.KeyToBase64(peer)
	if strings.TrimSpace(req.WorkerStaticPub) != "" && req.WorkerStaticPub != staticPub {
		return nil, errors.New("worker static pub mismatch")
	}
	if _, err := s.store.consumeToken(req.Token, staticPub); err != nil {
		return enrollResponse{OK: false, Error: err.Error()}, nil
	}
	rec, err := s.store.upsertPendingWorker(staticPub, req.SelfDescribe)
	if err != nil {
		return nil, err
	}
	pub, err := s.signer.publicKey()
	if err != nil {
		return nil, err
	}
	return enrollResponse{OK: true, WorkerID: rec.ID, Status: rec.Status, SignerPublicKey: pub}, nil
}

func (s *server) handleDeviceEnroll(peer []byte, raw []byte) (any, error) {
	var req deviceEnrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	noisePub := protocol.KeyToBase64(peer)
	if strings.TrimSpace(req.NoisePublicKey) != "" && req.NoisePublicKey != noisePub {
		return deviceEnrollResponse{OK: false, Error: "device noise pub mismatch"}, nil
	}
	if strings.TrimSpace(req.BootstrapToken) == "" {
		return deviceEnrollResponse{OK: false, Error: "bootstrap token is required"}, nil
	}
	if strings.TrimSpace(req.IdentityPubKey) == "" {
		return deviceEnrollResponse{OK: false, Error: "identity_pubkey is required"}, nil
	}
	if strings.TrimSpace(req.AWGPublicKey) == "" {
		return deviceEnrollResponse{OK: false, Error: "awg_public_key is required"}, nil
	}
	identityPub := strings.TrimSpace(req.IdentityPubKey)
	awgPublic := strings.TrimSpace(req.AWGPublicKey)
	id := deviceID(req.IdentityPubKey, noisePub)
	workers, err := s.store.workers()
	if err != nil {
		return nil, err
	}
	awgProfiles := workerAWGProfiles(workers)
	serverAWGPublic := workerAWGPublicKeyFromProfiles(awgProfiles)
	if serverAWGPublic == "" {
		return deviceEnrollResponse{OK: false, Error: "no approved worker with awg public key"}, nil
	}
	existing, err := s.store.device(id)
	if err == nil {
		storedIdentityPub := strings.TrimSpace(existing.IdentityPubKey)
		storedNoisePub := strings.TrimSpace(existing.NoisePublicKey)
		storedAWGPublic := strings.TrimSpace(existing.AWGPublicKey)
		switch {
		case existing.Status != "approved":
			return deviceEnrollResponse{OK: false, Error: "device is not approved"}, nil
		case storedIdentityPub == "" || storedIdentityPub != identityPub:
			return deviceEnrollResponse{OK: false, Error: "device identity mismatch"}, nil
		case storedNoisePub == "" || storedNoisePub != noisePub:
			return deviceEnrollResponse{OK: false, Error: "device noise pub mismatch"}, nil
		case storedAWGPublic == "" || storedAWGPublic != awgPublic:
			return deviceEnrollResponse{OK: false, Error: "device awg public key mismatch"}, nil
		}
		existing, err = s.store.ensureDeviceAWGProfiles(existing.ID, awgProfiles, awgPublic)
		if err != nil {
			return nil, err
		}
		bundle, err := s.buildClientBundleForClient(0, existing.ClientVersion)
		if err != nil {
			return nil, err
		}
		pub, err := s.signer.publicKey()
		if err != nil {
			return nil, err
		}
		return deviceEnrollResponse{
			OK:              true,
			DeviceID:        existing.ID,
			Status:          existing.Status,
			RealityUUID:     existing.RealityUUID,
			InternalIP:      existing.InternalIP,
			PSK2:            existing.PSK2,
			AWGProfiles:     existing.AWGProfiles,
			ServerAWGPublic: serverAWGPublic,
			SignerPublicKey: pub,
			ClientBundle:    bundle,
		}, nil
	} else if err.Error() != "device not found" {
		return nil, err
	}
	device := deviceRecord{
		ID:              id,
		NoisePublicKey:  noisePub,
		IdentityPubKey:  identityPub,
		IdentityKeyType: strings.TrimSpace(req.IdentityKeyType),
		AndroidID:       strings.TrimSpace(req.AndroidID),
		Model:           strings.TrimSpace(req.Model),
		EnrollmentNonce: strings.TrimSpace(req.EnrollmentNonce),
		ClientVersion:   strings.TrimSpace(req.ClientVersion),
		AWGPublicKey:    awgPublic,
	}
	_, stored, err := s.store.consumeBootstrapToken(req.BootstrapToken, device, awgProfiles)
	if err != nil {
		return deviceEnrollResponse{OK: false, Error: err.Error()}, nil
	}
	bundle, err := s.buildClientBundleForClient(0, stored.ClientVersion)
	if err != nil {
		return nil, err
	}
	pub, err := s.signer.publicKey()
	if err != nil {
		return nil, err
	}
	return deviceEnrollResponse{
		OK:              true,
		DeviceID:        stored.ID,
		Status:          stored.Status,
		RealityUUID:     stored.RealityUUID,
		InternalIP:      stored.InternalIP,
		PSK2:            stored.PSK2,
		AWGProfiles:     stored.AWGProfiles,
		ServerAWGPublic: serverAWGPublic,
		SignerPublicKey: pub,
		ClientBundle:    bundle,
	}, nil
}

func (s *server) handlePull(peer []byte, raw []byte) (any, error) {
	var req pullRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return pullResponse{OK: false, Error: err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return pullResponse{OK: false, Error: "worker identity mismatch"}, nil
	}
	if rec.Status == "pending" {
		return pullResponse{OK: false, Status: "pending", Error: "owner approval required"}, nil
	}
	if req.HaveSeq >= rec.DesiredSeq {
		return pullResponse{OK: true, Status: rec.Status, WorkerID: rec.ID, DesiredSeq: rec.DesiredSeq, NotModified: true}, nil
	}
	wb, cb, err := s.buildBundles(rec)
	if err != nil {
		return nil, err
	}
	update, err := s.loadUpdateArtifact()
	if err != nil {
		return nil, err
	}
	return pullResponse{OK: true, Status: rec.Status, WorkerID: rec.ID, DesiredSeq: rec.DesiredSeq, WorkerBundle: wb, ClientBundle: cb, Update: update}, nil
}

func (s *server) handleNudge(ctx context.Context, peer []byte, raw []byte) (any, error) {
	var req nudgeRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(25 * time.Second)
	updatedHeartbeat := false
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		rec, err := s.store.worker(req.WorkerID)
		if err != nil {
			return nudgeResponse{OK: false, Error: err.Error()}, nil
		}
		if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
			return nudgeResponse{OK: false, Error: "worker identity mismatch"}, nil
		}
		if !updatedHeartbeat {
			_ = s.store.updateWorkerHeartbeat(rec.ID, req.HaveSeq, req.SelfDescribe)
			updatedHeartbeat = true
		}
		if rec.DesiredSeq > req.HaveSeq || time.Now().After(deadline) {
			return nudgeResponse{OK: true, DesiredSeq: rec.DesiredSeq, Heartbeat: rec.DesiredSeq <= req.HaveSeq}, nil
		}
		select {
		case <-ctx.Done():
			return nudgeResponse{OK: false, Error: ctx.Err().Error()}, nil
		case <-ticker.C:
		}
	}
}

func (s *server) handleAck(peer []byte, raw []byte) (any, error) {
	var req ackRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return ackResponse{OK: false, Error: err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return ackResponse{OK: false, Error: "worker identity mismatch"}, nil
	}
	probe := s.probeEgressIP(rec)
	egressMatch := probe != "" && probe == req.EgressIPObserved
	if probe == "" {
		log.Printf("worker %s egress probe unavailable; observed=%q", rec.ID, req.EgressIPObserved)
	}
	_ = s.store.setProbe(rec.ID, probe)
	if err := s.store.updateAck(rec.ID, req.AppliedVersion, req.EgressIPObserved, req.SelfDescribe); err != nil {
		return nil, err
	}
	quotaBlocks, err := s.store.applyDeviceUsageAndBlocks(req.Usage, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if quotaBlocks > 0 {
		log.Printf("quota enforcement blocked devices count=%d worker=%s", quotaBlocks, rec.ID)
	}
	updated, err := s.store.worker(rec.ID)
	if err != nil {
		return nil, err
	}
	return ackResponse{OK: true, DesiredSeq: updated.DesiredSeq, AppliedSeq: req.AppliedVersion, EgressIPProbe: probe, EgressMatch: egressMatch, QuotaBlocks: quotaBlocks}, nil
}

func (s *server) handleWorkerTelemetry(peer []byte, raw []byte) (any, error) {
	var req workerTelemetryRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return map[string]any{"ok": false, "error": "worker identity mismatch"}, nil
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
	if err != nil || len(payload) == 0 || len(payload) > telemetryMaxPayloadBytes || !json.Valid(payload) {
		return map[string]any{"ok": false, "error": "invalid telemetry payload"}, nil
	}
	deviceID := strings.TrimSpace(req.Headers["X-TW-Device"])
	if deviceID == "" {
		var root map[string]any
		if err := json.Unmarshal(payload, &root); err == nil {
			deviceID, _ = root["did"].(string)
		}
	}
	device, err := s.store.device(deviceID)
	if err != nil {
		return map[string]any{"ok": false, "error": "unknown device"}, nil
	}
	if device.Status != "approved" {
		return map[string]any{"ok": false, "error": "device is not approved"}, nil
	}
	if err := verifyTelemetrySignature(device, payload, req.Headers); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	snapshot, err := summarizeTelemetryPayload(device.ID, rec.ID, payload, req.ReceivedAt)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	if err := s.store.setTelemetrySnapshot(snapshot); err != nil {
		return nil, err
	}
	if _, err := s.store.updateDeviceClientVersionFromTelemetry(device.ID, snapshot.ClientVersion); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func verifyTelemetrySignature(device deviceRecord, payload []byte, headers map[string]string) error {
	deviceID := strings.TrimSpace(headers["X-TW-Device"])
	if deviceID == "" || deviceID != device.ID {
		return errors.New("telemetry device mismatch")
	}
	if strings.TrimSpace(headers["X-TW-KeyType"]) != "ecdsa-p256-sha256" {
		return errors.New("telemetry key type mismatch")
	}
	if strings.TrimSpace(headers["X-TW-Pub"]) != strings.TrimSpace(device.IdentityPubKey) {
		return errors.New("telemetry public key mismatch")
	}
	ts := strings.TrimSpace(headers["X-TW-Ts"])
	nonce := strings.TrimSpace(headers["X-TW-Nonce"])
	sigText := strings.TrimSpace(headers["X-TW-Sig"])
	if ts == "" || nonce == "" || sigText == "" {
		return errors.New("telemetry signature headers missing")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(device.IdentityPubKey)
	if err != nil {
		return err
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubRaw)
	if err != nil {
		return err
	}
	pub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("telemetry public key is not ecdsa")
	}
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	canonical := strings.Join([]string{
		telemetrySignatureDomain,
		deviceID,
		ts,
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonical))
	if !ecdsa.VerifyASN1(pub, canonicalHash[:], sig) {
		return errors.New("telemetry signature invalid")
	}
	return nil
}

func summarizeTelemetryPayload(deviceID, workerID string, payload []byte, receivedAtRaw string) (telemetrySnapshotRecord, error) {
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return telemetrySnapshotRecord{}, err
	}
	if did, _ := root["did"].(string); strings.TrimSpace(did) != "" && strings.TrimSpace(did) != deviceID {
		return telemetrySnapshotRecord{}, errors.New("telemetry payload device mismatch")
	}
	receivedAt := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(receivedAtRaw)); err == nil {
		receivedAt = parsed.UTC()
	}
	rec := telemetrySnapshotRecord{
		DeviceID:      deviceID,
		WorkerID:      workerID,
		ReceivedAt:    receivedAt,
		SentAtMs:      int64FromAny(root["sent_at"]),
		ClientVersion: stringFromAny(root["ver"]),
		ClientVC:      int64FromAny(root["vc"]),
		Health:        "unknown",
		Fields:        map[string]string{},
	}
	events, _ := root["events"].([]any)
	if len(events) > 0 {
		start := len(events) - 5
		if start < 0 {
			start = 0
		}
		for _, rawEvent := range events[start:] {
			event, _ := rawEvent.(map[string]any)
			if len(event) == 0 {
				continue
			}
			kind := stringFromAny(event["k"])
			route := publicRouteLabel(firstNotBlank(stringFromAny(event["active_route"]), stringFromAny(event["route"])))
			status := telemetryEventStatus(event)
			errText := firstNotBlank(stringFromAny(event["err_kind"]), stringFromAny(event["err_where"]))
			if msg := stringFromAny(event["err_msg"]); msg != "" {
				errText = strings.TrimSpace(firstNotBlank(errText, "error") + ":" + msg)
			}
			rec.Recent = append(rec.Recent, telemetryEvent{
				Kind:   kind,
				AtMs:   int64FromAny(event["t"]),
				Route:  route,
				Status: status,
				Error:  errText,
			})
			if route != "" {
				rec.Route = route
			}
			if status != "" {
				rec.Health = status
			}
			if carryFromTelemetryEvent(event, rec.Route) {
				rec.Carry = true
			}
			if errText != "" {
				rec.LastError = errText
			}
			if mono := int64FromAny(event["mono"]); mono > 0 {
				rec.UptimeSeconds = mono / 1000
			}
		}
	}
	if rec.Route == "" {
		rec.Route = "-"
	}
	if rec.Carry && rec.Health == "unknown" {
		rec.Health = "healthy"
	}
	rec.Fields["event_count"] = strconv.Itoa(len(events))
	return rec, nil
}

func telemetryEventStatus(event map[string]any) string {
	healthy, healthyOK := boolFromAny(event["healthy"])
	stable, stableOK := boolFromAny(event["stable"])
	switch {
	case stableOK && stable:
		return "stable"
	case healthyOK && healthy:
		return "healthy"
	case healthyOK && !healthy:
		return "degraded"
	default:
		return ""
	}
}

func carryFromTelemetryEvent(event map[string]any, route string) bool {
	if stable, ok := boolFromAny(event["stable"]); ok && stable {
		return true
	}
	keys := []string{"rl2_carry", "rl_carry", "awgru_carry", "awg_carry"}
	switch route {
	case "REALITY-RU":
		keys = []string{"rl2_carry"}
	case "REALITY-TW":
		keys = []string{"rl_carry"}
	case "AWG-RU":
		keys = []string{"awgru_carry"}
	case "AWG-NL":
		keys = []string{"awg_carry"}
	}
	for _, key := range keys {
		if value, ok := boolFromAny(event[key]); ok && value {
			return true
		}
	}
	return false
}

func publicRouteLabel(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "REALITY2", "REALITY_RU", "REALITY-RU":
		return "REALITY-RU"
	case "REALITY", "REALITY_TW", "REALITY-TW":
		return "REALITY-TW"
	case "AWG_RU", "AWG-RU", "AWGRU", "AWG_RU_UPSTREAM", "AWG-RU-UPSTREAM":
		return "AWG-RU"
	case "AWG", "AWG_NL", "AWG-NL":
		return "AWG-NL"
	default:
		return strings.TrimSpace(value)
	}
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func int64FromAny(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		out, _ := v.Int64()
		return out
	default:
		return 0
	}
}

func boolFromAny(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		}
	}
	return false, false
}

func (s *server) buildBundles(rec workerRecord) (signedConfig, signedConfig, error) {
	issued := time.Now().UTC()
	approvedDevices, err := s.store.approvedDevices()
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	workerPayload := map[string]any{
		"schema":    1,
		"ns":        "worker-config-v1",
		"seq":       rec.DesiredSeq,
		"worker_id": rec.ID,
		"issued_at": issued.Format(time.RFC3339),
		"desired_state": map[string]any{
			"reality":          map[string]any{"enabled": !rec.Disabled && workerProtocolEnabled(rec, "reality"), "public": rec.SelfDescribe["reality"]},
			"awg":              map[string]any{"enabled": !rec.Disabled && workerProtocolEnabled(rec, "awg"), "public": rec.SelfDescribe["awg"]},
			"egress_policy":    "direct",
			"approved_devices": approvedDevicePayloads(approvedDevices),
			"client_artifacts": map[string]any{"config_json_path": "/tw/config.json", "version_json_path": "/tw/version.json"},
		},
	}
	workerJSON, err := canonicalJSON(workerPayload)
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	workerSigned, err := s.signer.sign(workerJSON)
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	clientSigned, err := s.buildClientBundle(rec.DesiredSeq)
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	return workerSigned, clientSigned, nil
}

func (s *server) buildClientBundle(minSeq int64) (signedConfig, error) {
	return s.buildClientBundleForClient(minSeq, "")
}

func (s *server) buildClientBundleForClient(minSeq int64, clientVersion string) (signedConfig, error) {
	workers, err := s.store.workers()
	if err != nil {
		return signedConfig{}, err
	}
	issued := time.Now().UTC()
	seq := minSeq
	var items []any
	for _, rec := range workers {
		if rec.Status != "approved" && rec.Status != "active" {
			continue
		}
		if rec.DesiredSeq > seq {
			seq = rec.DesiredSeq
		}
		if rec.Disabled {
			continue
		}
		if !workerFreshForClients(rec, issued) {
			continue
		}
		item, ok := clientWorkerPayloadForClient(rec, clientVersion)
		if ok {
			items = append(items, item)
		}
	}
	if seq < 1 {
		seq = 1
	}
	clientPayload := map[string]any{
		"schema":     1,
		"ns":         "client-config-v1",
		"seq":        seq,
		"issued_at":  issued.Format(time.RFC3339),
		"expires_at": issued.Add(24 * time.Hour).Format(time.RFC3339),
		"workers":    items,
	}
	if strings.TrimSpace(s.cfg.UpdatePublicKey) != "" {
		clientPayload["update_pubkey"] = strings.TrimSpace(s.cfg.UpdatePublicKey)
	}
	if pub := s.discoveryPublicKey(); pub != "" {
		clientPayload["discovery_pubkey"] = pub
	}
	if len(s.cfg.DiscoveryRescuePointers) > 0 {
		clientPayload["discovery_rescue_pointers"] = append([]string(nil), s.cfg.DiscoveryRescuePointers...)
	}
	if len(s.cfg.DNSServers) > 0 {
		clientPayload["dns_servers"] = append([]string(nil), s.cfg.DNSServers...)
	}
	clientJSON, err := canonicalJSON(clientPayload)
	if err != nil {
		return signedConfig{}, err
	}
	if err := rejectForbiddenKeys([]byte(clientJSON)); err != nil {
		return signedConfig{}, err
	}
	return s.signer.sign(clientJSON)
}

func clientWorkerPayload(rec workerRecord) (map[string]any, bool) {
	return clientWorkerPayloadForClient(rec, "")
}

func clientWorkerPayloadForClient(rec workerRecord, clientVersion string) (map[string]any, bool) {
	expected := stringFromMap(rec.SelfDescribe, "egress_ip")
	configURL := stringFromMap(rec.SelfDescribe, "distributor_url")
	routes := make([]any, 0, 2)
	if workerProtocolEnabled(rec, "reality") {
		if route, ok := clientRoutePayloadForClient("reality", rec.SelfDescribe["reality"], expected, configURL, clientVersion); ok {
			routes = append(routes, route)
		}
	}
	if workerProtocolEnabled(rec, "awg") {
		if profile, ok := selectAWGProfileForClient(awgProfilesFromWorker(rec), clientVersion); ok {
			if route, ok := clientRoutePayload("awg", profile.Params, expected, configURL); ok {
				route["profile"] = profile.Name
				route["awg_profile"] = profile.Name
				routes = append(routes, route)
			}
		} else if route, ok := clientRoutePayload("awg", rec.SelfDescribe["awg"], expected, configURL); ok {
			routes = append(routes, route)
		}
	}
	if len(routes) == 0 {
		return nil, false
	}
	return map[string]any{
		"worker_id": rec.ID,
		"label":     stringFromMap(rec.SelfDescribe, "label"),
		"priority":  effectiveWorkerPriority(rec),
		"weight":    effectiveWorkerWeight(rec),
		"routes":    routes,
	}, true
}

func effectiveWorkerPriority(rec workerRecord) int {
	if rec.ConfigPriority != nil {
		return *rec.ConfigPriority
	}
	return intFromMap(rec.SelfDescribe, "priority", 10)
}

func effectiveWorkerWeight(rec workerRecord) int {
	if rec.ConfigWeight != nil {
		return *rec.ConfigWeight
	}
	return intFromMap(rec.SelfDescribe, "weight", 100)
}

func workerProtocolEnabled(rec workerRecord, protocolName string) bool {
	normalized := normalizeProtocolName(protocolName)
	if normalized == "" {
		return false
	}
	if rec.ProtocolEnabled == nil {
		return true
	}
	enabled, ok := rec.ProtocolEnabled[normalized]
	if !ok {
		return true
	}
	return enabled
}

func clientRoutePayload(routeType string, raw any, expected, configURL string) (map[string]any, bool) {
	return clientRoutePayloadForClient(routeType, raw, expected, configURL, "")
}

func clientRoutePayloadForClient(routeType string, raw any, expected, configURL, clientVersion string) (map[string]any, bool) {
	params, ok := raw.(map[string]any)
	if !ok || len(params) == 0 {
		return nil, false
	}
	routeParams := canonicalClientRouteParamsForClient(routeType, params, clientVersion)
	route := cloneMap(routeParams)
	route["type"] = routeType
	route["enabled"] = true
	route["expected_egress_ip"] = expected
	if configURL != "" {
		route["config_url"] = strings.TrimRight(configURL, "/")
	}
	if _, ok := route["address"].(string); !ok {
		if endpoint := stringFromMap(params, "endpoint"); endpoint != "" {
			host, _, _ := strings.Cut(endpoint, ":")
			route["address"] = host
		}
	}
	if _, ok := route["port"]; !ok {
		if endpoint := stringFromMap(params, "endpoint"); endpoint != "" {
			_, portText, _ := strings.Cut(endpoint, ":")
			if port, err := strconv.Atoi(portText); err == nil {
				route["port"] = port
			}
		}
	}
	if _, ok := route["dialect_id"].(string); !ok {
		route["dialect_id"] = dialectID(routeParams)
	}
	if region := firstStringFromMap(routeParams, "region"); region != "" {
		route["region"] = region
	}
	route["params"] = routeParams
	return route, true
}

func canonicalClientRouteParams(routeType string, params map[string]any) map[string]any {
	return canonicalClientRouteParamsForClient(routeType, params, "")
}

func canonicalClientRouteParamsForClient(routeType string, params map[string]any, clientVersion string) map[string]any {
	out := cloneMap(params)
	switch normalizeProtocolName(routeType) {
	case "reality":
		copyFirstString(out, "public_key", params, "public_key", "publicKey")
		copyFirstString(out, "publicKey", params, "publicKey", "public_key")
		copyFirstString(out, "short_id", params, "short_id", "shortId")
		copyFirstString(out, "shortId", params, "shortId", "short_id")
		copyFirstString(out, "server_name", params, "server_name", "serverName", "sni")
		copyFirstString(out, "serverName", params, "serverName", "server_name", "sni")
		if firstStringFromMap(params, "security") == "" {
			out["security"] = "reality"
		}
		if firstStringFromMap(params, "network") == "" {
			out["network"] = "tcp"
		}
		if strings.EqualFold(firstStringFromMap(out, "network"), "xhttp") {
			delete(out, "flow")
			normalizeClientXHTTPParams(out)
		}
		fingerprint := firstStringFromMap(params, "fingerprint")
		if fingerprint == "" {
			fingerprint = realityFingerprintForClientVersion(clientVersion)
		}
		out["fingerprint"] = clampRealityFingerprint(fingerprint)
		if firstStringFromMap(params, "spiderX") == "" {
			out["spiderX"] = "/"
		}
	case "awg":
		copyFirstString(out, "public_key", params, "public_key", "server_public", "server_public_key")
		copyFirstString(out, "server_public", params, "server_public", "public_key", "server_public_key")
		copyFirstString(out, "server_public_key", params, "server_public_key", "public_key", "server_public")
		if firstStringFromMap(params, "dialect_id") == "" {
			out["dialect_id"] = dialectID(out)
		}
	}
	return out
}

func normalizeClientXHTTPParams(params map[string]any) {
	raw, ok := params["xhttp"].(map[string]any)
	if !ok {
		return
	}
	xhttp := cloneMap(raw)
	delete(xhttp, "host")
	mode := firstStringFromMap(xhttp, "mode")
	if mode == "" || strings.EqualFold(mode, "auto") {
		xhttp["mode"] = "stream-up"
	}
	params["xhttp"] = xhttp
}

func approvedDevicePayloads(devices []deviceRecord) []any {
	out := make([]any, 0, len(devices))
	for _, device := range devices {
		payload := map[string]any{
			"device_id":      device.ID,
			"reality_uuid":   device.RealityUUID,
			"awg_public_key": device.AWGPublicKey,
			"internal_ip":    device.InternalIP,
			"psk2":           device.PSK2,
			"status":         device.Status,
		}
		if len(device.AWGProfiles) > 0 {
			payload["awg_profiles"] = device.AWGProfiles
		}
		if !deviceLimitsEmpty(device.Limits) {
			payload["limits"] = device.Limits
			if device.Limits.ExpiresAt != nil && strings.TrimSpace(*device.Limits.ExpiresAt) != "" {
				payload["expires_at"] = strings.TrimSpace(*device.Limits.ExpiresAt)
			}
		}
		out = append(out, payload)
	}
	return out
}

func workerAWGSubnet(workers []workerRecord) string {
	return baseAWGSubnet(workerAWGProfiles(workers))
}

func workerAWGPublicKey(workers []workerRecord) string {
	return workerAWGPublicKeyFromProfiles(workerAWGProfiles(workers))
}

func workerAWGPublicKeyFromProfiles(profiles []awgProfile) string {
	if profile, ok := selectAWGProfileForClient(profiles, ""); ok && profile.ServerPublicKey != "" {
		return profile.ServerPublicKey
	}
	for _, profile := range profiles {
		if profile.ServerPublicKey != "" {
			return profile.ServerPublicKey
		}
	}
	return ""
}

func rejectForbiddenKeys(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	forbidden := map[string]struct{}{"private_key": {}, "privatekey": {}, "psk2": {}, "internal_ip": {}, "internalip": {}, "server_private_key": {}}
	var walk func(any, string) error
	walk = func(v any, path string) error {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				n := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
				if _, ok := forbidden[n]; ok {
					return fmt.Errorf("forbidden config field: %s%s", path, k)
				}
				if err := walk(child, path+k+"."); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range x {
				if err := walk(child, fmt.Sprintf("%s[%d].", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, "")
}

func (s *server) probeEgressIP(rec workerRecord) string {
	if s.cfg.EgressProbeURL == "" {
		return stringFromMap(rec.SelfDescribe, "egress_ip")
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(s.cfg.EgressProbeURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err == nil {
		return stringFromMap(body, "egress_ip")
	}
	return strings.TrimSpace(string(raw))
}

func tokenCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: orchestrator token create --id ID --value TOKEN --ttl 1h")
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	id := fs.String("id", "", "token id")
	value := fs.String("value", "", "token value")
	ttlText := fs.String("ttl", "1h", "ttl")
	workerStaticPub := fs.String("worker-static-pub", "", "optional pinned worker static public key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ttl, err := time.ParseDuration(*ttlText)
	if err != nil {
		return err
	}
	if err := adminPost(cfg, "/admin/v1/token/create", map[string]string{"id": *id, "value": *value, "ttl": ttl.String(), "worker_static_pub": *workerStaticPub}, os.Stdout); err == nil {
		return nil
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	if err := st.createToken(*id, *value, ttl, 1, *workerStaticPub); err != nil {
		return err
	}
	fmt.Printf("token_created id=%s ttl=%s max_uses=1\n", *id, ttl)
	return nil
}

func bootstrapTokenCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: orchestrator bootstrap-token create --limits JSON --expires RFC3339 [--seed-workers URL,URL]")
	}
	fs := flag.NewFlagSet("bootstrap-token create", flag.ContinueOnError)
	limitsText := fs.String("limits", "{}", "bootstrap limits json")
	expiresText := fs.String("expires", "", "RFC3339 expiry")
	seedWorkersText := fs.String("seed-workers", "", "comma-separated seed worker URLs")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	expiresAt, err := parseRFC3339Required(*expiresText)
	if err != nil {
		return err
	}
	limits, err := parseJSONObjectRaw(*limitsText)
	if err != nil {
		return err
	}
	seedWorkers := splitCSV(*seedWorkersText)
	req := map[string]any{
		"limits":       json.RawMessage(limits),
		"expires":      expiresAt.Format(time.RFC3339),
		"seed_workers": seedWorkers,
	}
	if err := adminPost(cfg, "/admin/v1/bootstrap-token/create", req, os.Stdout); err == nil {
		return nil
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	if len(seedWorkers) == 0 {
		workers, err := st.workers()
		if err == nil {
			seedWorkers = defaultSeedWorkersFromRecords(workers)
		}
	}
	signer := signerClient{socket: cfg.SignerSocket}
	pub, err := signer.publicKey()
	if err != nil {
		return err
	}
	static, err := loadOrCreateStaticKey(cfg)
	if err != nil {
		return err
	}
	secret, err := randomTokenSecret()
	if err != nil {
		return err
	}
	rec, err := st.createBootstrapToken(secret, expiresAt, limits, seedWorkers)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(makeBootstrapPayload(cfg, pub, protocol.KeyToBase64(static.Public), secret, rec))
}

func statusCommand(cfg orchConfig) error {
	if err := adminGet(cfg, "/admin/v1/status", os.Stdout); err == nil {
		return nil
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	workers, err := st.workers()
	if err != nil {
		return err
	}
	for _, w := range workers {
		fmt.Printf("worker=%s status=%s desired=%d applied=%d egress_ack=%s egress_probe=%s\n", w.ID, w.Status, w.DesiredSeq, w.AppliedSeq, w.EgressIPObserved, w.EgressIPProbe)
	}
	return nil
}

func deviceEnrollSmokeCommand(cfg orchConfig, args []string) error {
	fs := flag.NewFlagSet("device-enroll-smoke", flag.ContinueOnError)
	token := fs.String("bootstrap-token", "", "one-time bootstrap token secret")
	deviceID := fs.String("device-id", "smoke-device", "device id")
	identityPub := fs.String("identity-pub", "smoke-identity", "device identity public key")
	awgPublic := fs.String("awg-public-key", "", "device AWG public key, generated if empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*token) == "" {
		return errors.New("--bootstrap-token is required")
	}
	clientStatic, err := protocol.GenerateKeypair()
	if err != nil {
		return err
	}
	awgPrivate := ""
	if strings.TrimSpace(*awgPublic) == "" {
		awgKey, err := protocol.GenerateKeypair()
		if err != nil {
			return err
		}
		awgPrivate = protocol.KeyToBase64(awgKey.Private)
		*awgPublic = protocol.KeyToBase64(awgKey.Public)
	}
	serverStatic, err := loadOrCreateStaticKey(cfg)
	if err != nil {
		return err
	}
	var resp deviceEnrollResponse
	if err := noiseJSONRequest(
		cfg,
		protocol.KeyToBase64(serverStatic.Public),
		clientStatic,
		"/d/v1/enroll",
		deviceEnrollRequest{
			BootstrapToken:  *token,
			NoisePublicKey:  protocol.KeyToBase64(clientStatic.Public),
			DeviceID:        *deviceID,
			IdentityPubKey:  *identityPub,
			IdentityKeyType: "smoke",
			EnrollmentNonce: randID(),
			ClientVersion:   "device-enroll-smoke",
			AWGPublicKey:    *awgPublic,
		},
		&resp,
	); err != nil {
		return err
	}
	out := map[string]any{
		"response":        resp,
		"awg_private_key": awgPrivate,
		"awg_public_key":  *awgPublic,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func adminCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 || args[0] != "set-password" {
		return errors.New("usage: orchestrator admin set-password (--stdin | --env VAR | --file PATH)")
	}
	fs := flag.NewFlagSet("admin set-password", flag.ContinueOnError)
	value := fs.String("value", "", "deprecated unsafe admin secret")
	stdin := fs.Bool("stdin", false, "read admin secret from stdin")
	envName := fs.String("env", "", "read admin secret from environment variable")
	filePath := fs.String("file", "", "read admin secret from file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	secret, err := readSecretInput(secretInputOptions{
		Value:       *value,
		Stdin:       *stdin,
		EnvName:     *envName,
		FilePath:    *filePath,
		UnsafeLabel: "--value",
	})
	if err != nil {
		return err
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		if err := adminPost(cfg, "/admin/v1/password/force-set", map[string]string{"new_secret": secret}, os.Stdout); err == nil {
			return nil
		}
		return err
	}
	defer st.close()
	if err := st.setAdminPassword(secret); err != nil {
		return err
	}
	fmt.Println("admin_password_set")
	return nil
}

type secretInputOptions struct {
	Value       string
	Stdin       bool
	EnvName     string
	FilePath    string
	UnsafeLabel string
}

func readSecretInput(opts secretInputOptions) (string, error) {
	sources := 0
	if opts.Value != "" {
		sources++
	}
	if opts.Stdin {
		sources++
	}
	if strings.TrimSpace(opts.EnvName) != "" {
		sources++
	}
	if strings.TrimSpace(opts.FilePath) != "" {
		sources++
	}
	if sources != 1 {
		return "", errors.New("provide exactly one secret source: --stdin, --env, --file, or deprecated open argument")
	}
	switch {
	case opts.Value != "":
		label := firstNotBlank(opts.UnsafeLabel, "open argument")
		log.Printf("WARNING: %s exposes the secret via shell history and process list; use --stdin, --env, or --file", label)
		return strings.TrimSpace(opts.Value), nil
	case opts.Stdin:
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	case strings.TrimSpace(opts.EnvName) != "":
		value, ok := os.LookupEnv(strings.TrimSpace(opts.EnvName))
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", opts.EnvName)
		}
		return strings.TrimSpace(value), nil
	case strings.TrimSpace(opts.FilePath) != "":
		raw, err := os.ReadFile(strings.TrimSpace(opts.FilePath))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	default:
		return "", errors.New("secret source is required")
	}
}

func (s *server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	limiter := s.adminLoginLimiter()
	var req struct {
		Secret   string `json:"secret"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	attempt := limiter.reserveAttempt(ip)
	if !attempt.Allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
		s.auditEvent(auditEntry{
			Event:  "admin_login",
			IP:     ip,
			Result: "locked",
			Fields: map[string]string{"locked_until": attempt.LockedUntil.UTC().Format(time.RFC3339)},
		})
		http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
		return
	}
	ok, mustChange, err := s.store.verifyAdminPassword(req.Secret)
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: map[string]string{"reason": "verify_error"}})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !ok {
		fields := map[string]string{"reason": "bad_secret"}
		if attempt.LockedAfterAttempt {
			fields["locked_until"] = attempt.LockedUntil.UTC().Format(time.RFC3339)
			w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
			s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "locked", Fields: fields})
			http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
			return
		}
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: fields})
		http.Error(w, "invalid admin secret", http.StatusForbidden)
		return
	}
	if enabled, totpOK, err := s.store.verifyAdminTOTP(req.TOTPCode, time.Now().UTC()); err != nil {
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: map[string]string{"reason": "totp_error"}})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	} else if enabled && !totpOK {
		fields := map[string]string{"reason": "bad_totp"}
		if attempt.LockedAfterAttempt {
			fields["locked_until"] = attempt.LockedUntil.UTC().Format(time.RFC3339)
			w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
			s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "locked", Fields: fields})
			http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
			return
		}
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: fields})
		http.Error(w, "invalid totp code", http.StatusForbidden)
		return
	}
	limiter.recordSuccess(ip)
	s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "ok"})
	if mustChange {
		s.createAdminSession(w, true)
		return
	}
	if approver := s.currentAuthApprover(); approver != nil && approver.enabled() {
		approved, err := approver.requestLoginApproval(r.Context(), loginApprovalRequest{
			RemoteAddr: ip,
			UserAgent:  r.UserAgent(),
			CreatedAt:  time.Now().UTC(),
		})
		if err != nil {
			s.auditEvent(auditEntry{Event: "admin_login_approval", IP: ip, Result: "failed", Fields: map[string]string{"reason": "approval_error"}})
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !approved {
			s.auditEvent(auditEntry{Event: "admin_login_approval", IP: ip, Result: "denied"})
			http.Error(w, "admin login approval denied", http.StatusForbidden)
			return
		}
	}
	s.createAdminSession(w, false)
}

func (s *server) createAdminSession(w http.ResponseWriter, mustChange bool) {
	token := randID() + randID() + randID()
	csrf := randID() + randID()
	expires := time.Now().UTC().Add(12 * time.Hour)
	s.adminSessions.Store(token, adminSession{Token: token, CSRFToken: csrf, ExpiresAt: expires, MustChange: mustChange})
	http.SetCookie(w, &http.Cookie{
		Name:     "tw_admin_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	writeJSON(w, map[string]any{
		"ok":            true,
		"session_token": token,
		"csrf_token":    csrf,
		"expires_at":    expires.Format(time.RFC3339),
		"must_change":   mustChange,
	})
}

func (s *server) handleAdminTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditEvent(auditEntry{Event: "admin_totp_enroll", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{
		"ok":          true,
		"secret":      rec.Secret,
		"otpauth_url": totpProvisioningURL(rec.Secret),
	})
}

func (s *server) handleAdminTOTPEnable(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.enableAdminTOTP(req.Code, time.Now().UTC()); err != nil {
		s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "failed"})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.store.disableAdminTOTP(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditEvent(auditEntry{Event: "admin_totp_disable", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) lookupAdminSession(r *http.Request) (string, string, adminSession, bool) {
	token := ""
	source := ""
	auth := r.Header.Get("authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[len("bearer "):])
		source = "bearer"
	}
	if token == "" {
		if cookie, err := r.Cookie("tw_admin_session"); err == nil {
			token = cookie.Value
			source = "cookie"
		}
	}
	if token == "" {
		return "", "", adminSession{}, false
	}
	value, ok := s.adminSessions.Load(token)
	if !ok {
		return token, source, adminSession{}, false
	}
	session := value.(adminSession)
	if time.Now().UTC().After(session.ExpiresAt) {
		s.adminSessions.Delete(token)
		return token, source, adminSession{}, false
	}
	return token, source, session, true
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	token, source, session, ok := s.lookupAdminSession(r)
	if token == "" {
		http.Error(w, "admin session required", http.StatusUnauthorized)
		return false
	}
	if !ok {
		http.Error(w, "admin session invalid", http.StatusForbidden)
		return false
	}
	if session.MustChange {
		http.Error(w, "password change required", http.StatusForbidden)
		return false
	}
	if source == "cookie" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if session.CSRFToken == "" || r.Header.Get("x-csrf-token") != session.CSRFToken {
			http.Error(w, "csrf token required", http.StatusForbidden)
			return false
		}
	}
	return true
}

func (s *server) handleAdminPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	token, source, session, ok := s.lookupAdminSession(r)
	if token == "" {
		http.Error(w, "admin session required", http.StatusUnauthorized)
		return
	}
	if !ok {
		http.Error(w, "admin session invalid", http.StatusForbidden)
		return
	}
	if source == "cookie" && (session.CSRFToken == "" || r.Header.Get("x-csrf-token") != session.CSRFToken) {
		http.Error(w, "csrf token required", http.StatusForbidden)
		return
	}
	var req struct {
		CurrentSecret string `json:"current_secret"`
		NewSecret     string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	okPassword, _, err := s.store.verifyAdminPassword(req.CurrentSecret)
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "verify_error"}})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !okPassword {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "bad_current_secret"}})
		http.Error(w, "invalid current admin secret", http.StatusForbidden)
		return
	}
	if err := s.store.setAdminPassword(req.NewSecret); err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "set_failed"}})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("admin password changed at=%s remote=%s", time.Now().UTC().Format(time.RFC3339), r.RemoteAddr)
	s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "ok"})
	s.adminSessions.Delete(token)
	if approver := s.currentAuthApprover(); approver != nil && approver.enabled() {
		approved, err := approver.requestLoginApproval(r.Context(), loginApprovalRequest{
			RemoteAddr: ip,
			UserAgent:  r.UserAgent(),
			CreatedAt:  time.Now().UTC(),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !approved {
			http.Error(w, "admin login approval denied", http.StatusForbidden)
			return
		}
	}
	s.createAdminSession(w, false)
}

func (s *server) handleAdminPasswordForceSet(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NewSecret string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.setAdminPassword(req.NewSecret); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "status": "admin_password_set"})
}

func (s *server) handleAdminBotStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, ok, err := s.store.botSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, map[string]any{"ok": true, "configured": false})
		return
	}
	writeJSON(w, map[string]any{
		"ok":         true,
		"configured": true,
		"owner_id":   rec.OwnerID,
		"updated_at": rec.UpdatedAt.Format(time.RFC3339),
	})
}

func (s *server) handleAdminBotSetToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token   string `json:"token"`
		OwnerID int64  `json:"owner_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.setBotSettings(req.Token, req.OwnerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.hasBotFactory() {
		if err := s.restartOptionalBot(context.Background()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.auditEvent(auditEntry{Event: "bot_token_set", IP: clientIP(r), Result: "ok", Fields: map[string]string{"owner_id": strconv.FormatInt(req.OwnerID, 10)}})
	writeJSON(w, map[string]any{"ok": true, "configured": true, "owner_id": req.OwnerID})
}

func (s *server) handleAdminTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID              string `json:"id"`
		Value           string `json:"value"`
		TTL             string `json:"ttl"`
		WorkerStaticPub string `json:"worker_static_pub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.createToken(req.ID, req.Value, ttl, 1, req.WorkerStaticPub); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "enroll_token_create", IP: clientIP(r), Result: "ok", Fields: map[string]string{"id": req.ID, "ttl": ttl.String(), "pinned_worker": strconv.FormatBool(strings.TrimSpace(req.WorkerStaticPub) != "")}})
	fmt.Fprintf(w, "token_created id=%s ttl=%s max_uses=1\n", req.ID, ttl)
}

func (s *server) handleAdminBootstrapTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Limits      json.RawMessage `json:"limits"`
		Expires     string          `json:"expires"`
		SeedWorkers []string        `json:"seed_workers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	expiresAt, err := parseRFC3339Required(req.Expires)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limits, err := parseJSONObjectRaw(string(req.Limits))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pub, err := s.signer.publicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secret, err := randomTokenSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	seedWorkers := req.SeedWorkers
	if len(seedWorkers) == 0 {
		seedWorkers = s.defaultSeedWorkers()
	}
	rec, err := s.store.createBootstrapToken(secret, expiresAt, limits, seedWorkers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "bootstrap_token_create", IP: clientIP(r), Result: "ok", Fields: map[string]string{"id": rec.ID, "expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339)}})
	writeJSON(w, makeBootstrapPayload(s.cfg, pub, protocol.KeyToBase64(s.static.Public), secret, rec))
}

func (s *server) handleAdminBootstrapTokenQR(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data := strings.TrimSpace(req.Data)
	if data == "" {
		http.Error(w, "data is required", http.StatusBadRequest)
		return
	}
	if len(data) > 4096 {
		http.Error(w, "data is too large for bootstrap QR", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(data, qrcode.Medium, 288)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"ok":    true,
		"image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (s *server) defaultSeedWorkers() []string {
	workers, err := s.store.workers()
	if err != nil {
		return nil
	}
	return defaultSeedWorkersFromRecords(workers)
}

func (s *server) runWorkerJanitor(ctx context.Context) {
	ticker := time.NewTicker(workerJanitorEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().UTC().Add(-workerFreshTTL)
			n, err := s.store.markStaleWorkersInactive(cutoff)
			if err != nil {
				log.Printf("worker stale janitor failed: %v", err)
			} else if n > 0 {
				log.Printf("worker stale janitor marked inactive count=%d", n)
			}
		}
	}
}

func defaultSeedWorkersFromRecords(workers []workerRecord) []string {
	seeds := make([]string, 0, len(workers))
	seen := map[string]bool{}
	now := time.Now().UTC()
	for _, rec := range workers {
		if rec.Disabled || (rec.Status != "approved" && rec.Status != "active") {
			continue
		}
		if !workerFreshForClients(rec, now) {
			continue
		}
		seed := seedWorkerURL(rec)
		if seed == "" || seen[seed] {
			continue
		}
		seen[seed] = true
		seeds = append(seeds, seed)
	}
	return seeds
}

func workerFreshForClients(rec workerRecord, now time.Time) bool {
	if rec.LastAckAt != nil {
		return now.Sub(rec.LastAckAt.UTC()) <= workerFreshTTL
	}
	if rec.ApprovedAt != nil {
		return now.Sub(rec.ApprovedAt.UTC()) <= workerFreshTTL
	}
	return now.Sub(rec.CreatedAt.UTC()) <= workerFreshTTL
}

func seedWorkerURL(rec workerRecord) string {
	if reality, ok := rec.SelfDescribe["reality"].(map[string]any); ok {
		address := stringFromMap(reality, "address")
		port := intFromMap(reality, "port", 0)
		if address != "" && port > 0 {
			return fmt.Sprintf("https://%s:%d/tw", address, port)
		}
	}
	if distributor := stringFromMap(rec.SelfDescribe, "distributor_url"); strings.HasPrefix(distributor, "https://") {
		return strings.TrimRight(distributor, "/")
	}
	return ""
}

func (s *server) handleAdminApproveWorker(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.approveWorker(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_approve", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID}})
	fmt.Fprintf(w, "worker_approved id=%s\n", req.ID)
}

func (s *server) handleAdminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.revokeDevice(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "device_revoke", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": req.ID}})
	fmt.Fprintf(w, "device_revoked id=%s\n", req.ID)
}

func (s *server) handleAdminDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.deleteDevice(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "device_delete", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": req.ID}})
	fmt.Fprintf(w, "device_deleted id=%s\n", req.ID)
}

func (s *server) handleAdminDeviceAlias(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID    string `json:"id"`
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.store.setDeviceAlias(req.ID, req.Alias)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "device_id": rec.ID, "alias": rec.Alias})
}

func (s *server) handleAdminWorkers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	workers, err := s.store.workers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items := make([]any, 0, len(workers))
	for _, worker := range workers {
		items = append(items, adminWorkerPayload(worker))
	}
	writeJSON(w, map[string]any{"ok": true, "workers": items})
}

func (s *server) handleAdminWorkerSetEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "enabled is required", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{Enabled: req.Enabled}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminWorkerProtocol(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "enabled is required", http.StatusBadRequest)
		return
	}
	protocol := normalizeProtocolName(req.Protocol)
	if protocol == "" {
		http.Error(w, "unsupported protocol", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{Protocols: map[string]*bool{protocol: req.Enabled}}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices, err := s.store.devices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	telemetry, err := s.store.telemetrySnapshots()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	apkRelease, apkPublished, err := s.store.currentAPKRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items := make([]any, 0, len(devices))
	for _, device := range devices {
		live, hasLive := telemetry[device.ID]
		installedVersion, versionSource := resolveInstalledVersion(device, live, hasLive)
		updateAvailable, _ := computeUpdateAvailable(hasLive, live.ClientVC, apkPublished, apkRelease)
		items = append(items, map[string]any{
			"device_id":                device.ID,
			"alias":                    device.Alias,
			"status":                   device.Status,
			"client_version":           device.ClientVersion, // enroll-time snapshot kept for API compatibility
			"installed_version":        installedVersion,
			"installed_version_source": versionSource,
			"update_available":         updateAvailable,
			"model":                    device.Model,
			"android_id":               device.AndroidID,
			"enrolled_at":              device.CreatedAt.Format(time.RFC3339),
			"internal_ip":              device.InternalIP,
			"config_seq":               device.ConfigSeq,
			"telemetry":                adminTelemetryPayload(live, hasLive),
		})
	}
	writeJSON(w, map[string]any{"ok": true, "devices": items})
}

func (s *server) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := s.buildClientBundle(0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var parsed any
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &parsed); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "bundle": bundle, "config": parsed})
}

func (s *server) handleAdminConfigEdit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Workers []struct {
			ID        string          `json:"id"`
			WorkerID  string          `json:"worker_id"`
			Enabled   *bool           `json:"enabled"`
			Priority  *int            `json:"priority"`
			Weight    *int            `json:"weight"`
			Protocols map[string]bool `json:"protocols"`
		} `json:"workers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, item := range req.Workers {
		id := item.WorkerID
		if id == "" {
			id = item.ID
		}
		protocols := map[string]*bool{}
		for key, value := range item.Protocols {
			enabled := value
			protocols[key] = &enabled
		}
		if err := s.store.updateWorkerPolicy(id, workerPolicyPatch{
			Enabled:   item.Enabled,
			Priority:  item.Priority,
			Weight:    item.Weight,
			Protocols: protocols,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	bundle, err := s.buildClientBundle(0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "bundle": bundle})
}

func (s *server) handleAdminAPKStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, ok, err := s.store.currentAPKRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"ok":                       true,
		"update_pubkey_configured": strings.TrimSpace(s.cfg.UpdatePublicKey) != "",
		"server_update_key":        s.serverUpdateSigningAvailable(),
		"next_seq":                 mustNextAPKSeq(s.store),
		"release":                  optionalAPKRelease(rec, ok),
	})
}

func (s *server) handleAdminAPKDownload(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, ok, err := s.store.currentAPKRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || strings.TrimSpace(rec.APKPath) == "" {
		http.Error(w, "apk release is not published", http.StatusNotFound)
		return
	}
	file, err := os.Open(rec.APKPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := fmt.Sprintf("TrafficWrapper-%d.apk", rec.VersionCode)
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeContent(w, r, name, stat.ModTime(), file)
}

func (s *server) handleAdminAPKInspect(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(160 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	apkFile, apkHeader, err := r.FormFile("apk")
	if err != nil {
		http.Error(w, "apk file is required", http.StatusBadRequest)
		return
	}
	defer apkFile.Close()
	sha, size, err := hashMultipartFile(apkFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	version, versionErr := inspectAPKVersion(apkFile, size)
	if _, err := apkFile.Seek(0, io.SeekStart); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := map[string]any{
		"ok":         true,
		"apk_name":   safeAPKName(apkHeader.Filename, version.VersionCode),
		"apk_sha256": sha,
		"apk_size":   size,
	}
	if versionErr != nil {
		resp["version_detected"] = false
		resp["version_error"] = versionErr.Error()
	} else {
		resp["version_detected"] = true
		resp["version_code"] = version.VersionCode
		resp["version_name"] = version.VersionName
	}
	writeJSON(w, resp)
}

func (s *server) handleAdminAPKDraft(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		APKSHA256   string `json:"apk_sha256"`
		APKSize     int64  `json:"apk_size"`
		APKName     string `json:"apk_name"`
		MinVersion  int64  `json:"min_version"`
		Notes       string `json:"notes"`
		Seq         int64  `json:"seq"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	seq := req.Seq
	if seq <= 0 {
		var err error
		seq, err = s.store.nextAPKSeq()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	manifestJSON, err := buildAPKManifest(apkManifestInput{
		Seq:         seq,
		VersionCode: req.VersionCode,
		VersionName: req.VersionName,
		APKSHA256:   req.APKSHA256,
		APKSize:     req.APKSize,
		APKName:     req.APKName,
		MinVersion:  req.MinVersion,
		Notes:       req.Notes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "seq": seq, "manifest_json": manifestJSON})
}

func (s *server) handleAdminAPKPublish(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(160 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	manifestJSON := strings.TrimSpace(r.FormValue("manifest_json"))
	minisig := strings.TrimSpace(r.FormValue("manifest_minisig"))
	apkFile, apkHeader, err := r.FormFile("apk")
	if err != nil {
		http.Error(w, "apk file is required", http.StatusBadRequest)
		return
	}
	defer apkFile.Close()
	serverSigned := false
	var manifest apkReleaseRecord
	if manifestJSON == "" && minisig == "" {
		priv, pubText, err := s.loadServerUpdateSigningKey()
		if err != nil {
			http.Error(w, "server update signing key unavailable: "+err.Error(), http.StatusBadRequest)
			return
		}
		sha, size, err := hashMultipartFile(apkFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		version, versionErr := inspectAPKVersion(apkFile, size)
		if _, err := apkFile.Seek(0, io.SeekStart); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if parsed := parseFormInt64(r, "version_code"); parsed > 0 {
			version.VersionCode = parsed
		}
		if value := strings.TrimSpace(r.FormValue("version_name")); value != "" {
			version.VersionName = value
		}
		if versionErr != nil && (version.VersionCode <= 0 || strings.TrimSpace(version.VersionName) == "") {
			http.Error(w, "could not read APK version; fill version_code and version_name manually: "+versionErr.Error(), http.StatusBadRequest)
			return
		}
		seq, err := s.store.nextAPKSeq()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		manifestJSON, err = buildAPKManifest(apkManifestInput{
			Seq:         seq,
			VersionCode: version.VersionCode,
			VersionName: version.VersionName,
			APKSHA256:   sha,
			APKSize:     size,
			APKName:     firstNotBlank(r.FormValue("apk_name"), apkHeader.Filename),
			MinVersion:  parseFormInt64(r, "min_version"),
			Notes:       r.FormValue("notes"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		minisig = string(minisign.Sign(priv, []byte(manifestJSON)))
		if err := verifyManifestSignature(manifestJSON, minisig, pubText); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serverSigned = true
	} else {
		if manifestJSON == "" || minisig == "" {
			http.Error(w, "manifest_json and manifest_minisig are required for offline signing", http.StatusBadRequest)
			return
		}
		if err := verifyManifestSignature(manifestJSON, minisig, s.cfg.UpdatePublicKey); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	manifest, err = parseAPKManifest(manifestJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	release, err := s.storeAPKRelease(manifest, manifestJSON, minisig, apkFile, apkHeader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("published APK update seq=%d version=%s(%d) sha256=%s server_signed=%t", release.Seq, release.VersionName, release.VersionCode, release.APKSHA256, serverSigned)
	writeJSON(w, map[string]any{"ok": true, "release": release})
}

func (s *server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	workers, err := s.store.workers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, worker := range workers {
		fmt.Fprintf(w, "worker=%s status=%s desired=%d applied=%d egress_ack=%s egress_probe=%s\n",
			worker.ID, worker.Status, worker.DesiredSeq, worker.AppliedSeq, worker.EgressIPObserved, worker.EgressIPProbe)
	}
}

func adminWorkerPayload(worker workerRecord) map[string]any {
	return map[string]any{
		"id":                 worker.ID,
		"status":             worker.Status,
		"last_seen":          formatOptionalTime(worker.LastAckAt),
		"desired_seq":        worker.DesiredSeq,
		"applied_seq":        worker.AppliedSeq,
		"egress_ack":         worker.EgressIPObserved,
		"egress_probe":       worker.EgressIPProbe,
		"enabled":            !worker.Disabled,
		"priority":           effectiveWorkerPriority(worker),
		"weight":             effectiveWorkerWeight(worker),
		"protocols":          map[string]bool{"reality": workerProtocolEnabled(worker, "reality"), "awg": workerProtocolEnabled(worker, "awg")},
		"self_describe":      worker.SelfDescribe,
		"static_public_key8": shortString(worker.StaticPublicKey, 8),
	}
}

func adminTelemetryPayload(rec telemetrySnapshotRecord, ok bool) map[string]any {
	if !ok || rec.DeviceID == "" {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled":        true,
		"device_id":      rec.DeviceID,
		"worker_id":      rec.WorkerID,
		"last_seen":      rec.ReceivedAt.UTC().Format(time.RFC3339),
		"client_version": rec.ClientVersion,
		"client_vc":      rec.ClientVC,
		"route":          rec.Route,
		"health":         rec.Health,
		"carry":          rec.Carry,
		"uptime_s":       rec.UptimeSeconds,
		"last_error":     rec.LastError,
		"recent":         rec.Recent,
	}
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func shortString(value string, n int) string {
	value = strings.TrimSpace(value)
	if len(value) <= n {
		return value
	}
	return value[:n]
}

func adminPost(cfg orchConfig, path string, payload any, out io.Writer) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return adminRequest(cfg, http.MethodPost, path, bytes.NewReader(raw), out)
}

func adminGet(cfg orchConfig, path string, out io.Writer) error {
	return adminRequest(cfg, http.MethodGet, path, nil, out)
}

func noiseJSONRequest(cfg orchConfig, serverPublic string, clientStatic noise.DHKey, path string, req any, resp any) error {
	serverPub, err := protocol.DecodeKeyBase64(serverPublic)
	if err != nil {
		return err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(protocol.Prologue),
		StaticKeypair: clientStatic,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	var start startResponse
	if err := adminRequest(cfg, http.MethodPost, "/d/v1/handshake/start", bytes.NewReader(mustJSON(startRequest{Message: base64.StdEncoding.EncodeToString(msg1)})), discardDecode(&start)); err != nil {
		return err
	}
	if !start.OK {
		return errors.New(start.Error)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		return err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return err
	}
	msg3, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	payload, err := protocol.EncryptJSON(sendCipher, req)
	if err != nil {
		return err
	}
	var envResp noiseEnvelopeResponse
	if err := adminRequest(cfg, http.MethodPost, path, bytes.NewReader(mustJSON(noiseEnvelope{
		SID:     start.SID,
		Message: base64.StdEncoding.EncodeToString(msg3),
		Payload: base64.StdEncoding.EncodeToString(payload),
	})), discardDecode(&envResp)); err != nil {
		return err
	}
	if !envResp.OK {
		return errors.New(envResp.Error)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envResp.Payload)
	if err != nil {
		return err
	}
	return protocol.DecryptJSON(recvCipher, encrypted, resp)
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

type responseDecoder struct {
	target any
}

func discardDecode(target any) io.Writer {
	return responseDecoder{target: target}
}

func (d responseDecoder) Write(raw []byte) (int, error) {
	if err := json.Unmarshal(raw, d.target); err != nil {
		return 0, err
	}
	return len(raw), nil
}

func adminRequest(cfg orchConfig, method, path string, body io.Reader, out io.Writer) error {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequest(method, adminBaseURL(cfg)+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if token := strings.TrimSpace(os.Getenv("ORCH_ADMIN_SESSION_TOKEN")); token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("admin http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	_, _ = out.Write(raw)
	return nil
}

func adminBaseURL(cfg orchConfig) string {
	if value := strings.TrimRight(strings.TrimSpace(os.Getenv("ORCH_ADMIN_URL")), "/"); value != "" {
		return value
	}
	listen := strings.TrimSpace(cfg.Listen)
	if listen == "" {
		listen = ":9091"
	}
	host := "127.0.0.1"
	port := "9091"
	if strings.HasPrefix(listen, ":") {
		port = strings.TrimPrefix(listen, ":")
	} else {
		parts := strings.Split(listen, ":")
		if len(parts) > 1 {
			port = parts[len(parts)-1]
			candidateHost := strings.Join(parts[:len(parts)-1], ":")
			if candidateHost != "" && candidateHost != "0.0.0.0" && candidateHost != "::" && candidateHost != "[::]" {
				host = strings.Trim(candidateHost, "[]")
			}
		}
	}
	scheme := "https"
	if !cfg.TLS {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func loadOrCreateStaticKey(cfg orchConfig) (noise.DHKey, error) {
	path := filepath.Join(cfg.StateDir, "orch-static.json")
	if raw, err := os.ReadFile(path); err == nil {
		var file protocol.KeyPairFile
		if err := json.Unmarshal(raw, &file); err != nil {
			return noise.DHKey{}, err
		}
		return protocol.DecodeKeyPair(file.PrivateKey, file.PublicKey)
	} else if !errors.Is(err, os.ErrNotExist) {
		return noise.DHKey{}, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return noise.DHKey{}, err
	}
	key, err := protocol.GenerateKeypair()
	if err != nil {
		return noise.DHKey{}, err
	}
	raw, _ := json.MarshalIndent(protocol.NewKeyPairFile(key), "", "  ")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return noise.DHKey{}, err
	}
	return key, nil
}

func loadOrCreateTLS(cfg orchConfig) (string, string, error) {
	certPath := filepath.Join(cfg.StateDir, "tls.crt")
	keyPath := filepath.Join(cfg.StateDir, "tls.key")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}
	certPEM, keyPEM, err := selfSigned("trafficwrapper-orchestrator")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func selfSigned(name string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "trafficwrapper-orchestrator"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyRaw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyRaw}), nil
}

func canonicalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func firstStringFromMap(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(stringFromMap(m, key)); value != "" {
			return value
		}
	}
	return ""
}

func copyFirstString(dst map[string]any, dstKey string, src map[string]any, keys ...string) {
	if value := firstStringFromMap(src, keys...); value != "" {
		dst[dstKey] = value
	}
}

func intFromMap(m map[string]any, key string, fallback int) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	}
	return fallback
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+6)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func dialectID(params map[string]any) string {
	if v := stringFromMap(params, "dialect_id"); v != "" {
		return v
	}
	raw, _ := canonicalJSON(params["dialect"])
	if raw == "null" || raw == "" {
		raw, _ = canonicalJSON(params)
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func makeBootstrapPayload(cfg orchConfig, pubkey, orchNoisePublic, token string, rec tokenRecord) bootstrapPayload {
	return bootstrapPayload{
		OrchestratorURL: strings.TrimRight(cfg.PublicURL, "/"),
		ConfigPubkeyPin: pubkey,
		OrchNoisePublic: orchNoisePublic,
		UpdatePubkey:    strings.TrimSpace(cfg.UpdatePublicKey),
		SeedWorkers:     append([]string(nil), rec.SeedWorkers...),
		BootstrapToken:  token,
		Limits:          copyRawJSON(rec.Limits),
		Expires:         rec.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

type apkManifestInput struct {
	Seq         int64
	VersionCode int64
	VersionName string
	APKSHA256   string
	APKSize     int64
	APKName     string
	MinVersion  int64
	Notes       string
}

func buildAPKManifest(in apkManifestInput) (string, error) {
	if in.Seq <= 0 {
		return "", errors.New("seq must be positive")
	}
	if in.VersionCode <= 0 {
		return "", errors.New("version_code must be positive")
	}
	if strings.TrimSpace(in.VersionName) == "" {
		return "", errors.New("version_name is required")
	}
	if len(strings.TrimSpace(in.APKSHA256)) != 64 {
		return "", errors.New("apk_sha256 must be 64 hex chars")
	}
	if in.APKSize <= 0 {
		return "", errors.New("apk_size must be positive")
	}
	apkName := safeAPKName(in.APKName, in.VersionCode)
	payload := map[string]any{
		"schema":       1,
		"ns":           "apk-update-v1",
		"seq":          in.Seq,
		"version_code": in.VersionCode,
		"version_name": strings.TrimSpace(in.VersionName),
		"apk_sha256":   strings.ToLower(strings.TrimSpace(in.APKSHA256)),
		"apk_size":     in.APKSize,
		"apk_name":     apkName,
		"apk_url":      apkName,
		"min_version":  in.MinVersion,
		"notes":        strings.TrimSpace(in.Notes),
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	}
	return canonicalJSON(payload)
}

func parseAPKManifest(raw string) (apkReleaseRecord, error) {
	var root struct {
		Schema      int    `json:"schema"`
		Namespace   string `json:"ns"`
		Seq         int64  `json:"seq"`
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		APKSHA256   string `json:"apk_sha256"`
		APKSize     int64  `json:"apk_size"`
		APKName     string `json:"apk_name"`
		APKURL      string `json:"apk_url"`
		MinVersion  int64  `json:"min_version"`
		Notes       string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return apkReleaseRecord{}, err
	}
	if root.Schema != 1 || root.Namespace != "apk-update-v1" {
		return apkReleaseRecord{}, errors.New("unsupported apk manifest")
	}
	name := safeAPKName(firstNotBlank(root.APKName, root.APKURL), root.VersionCode)
	if root.Seq <= 0 || root.VersionCode <= 0 || root.APKSize <= 0 || len(strings.TrimSpace(root.APKSHA256)) != 64 {
		return apkReleaseRecord{}, errors.New("invalid apk manifest fields")
	}
	return apkReleaseRecord{
		Seq:         root.Seq,
		VersionCode: root.VersionCode,
		VersionName: strings.TrimSpace(root.VersionName),
		MinVersion:  root.MinVersion,
		Notes:       strings.TrimSpace(root.Notes),
		APKName:     name,
		APKSHA256:   strings.ToLower(strings.TrimSpace(root.APKSHA256)),
		APKSize:     root.APKSize,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func verifyManifestSignature(manifestJSON, minisigText, publicKey string) error {
	if strings.TrimSpace(publicKey) == "" {
		return errors.New("ORCH_UPDATE_PUBKEY is not configured")
	}
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(strings.TrimSpace(publicKey))); err != nil {
		return fmt.Errorf("invalid update public key: %w", err)
	}
	if !minisign.Verify(pub, []byte(manifestJSON), []byte(strings.TrimSpace(minisigText))) {
		return errors.New("update manifest signature invalid")
	}
	return nil
}

func (s *server) serverUpdateSigningAvailable() bool {
	_, _, err := s.loadServerUpdateSigningKey()
	return err == nil
}

func (s *server) loadServerUpdateSigningKey() (minisign.PrivateKey, string, error) {
	raw, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "update.key"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return minisign.PrivateKey{}, "", errors.New("update.key is not present")
		}
		return minisign.PrivateKey{}, "", err
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(raw); err != nil {
		return minisign.PrivateKey{}, "", fmt.Errorf("invalid update key: %w", err)
	}
	pubText, err := updatePublicKeyText(priv)
	if err != nil {
		return minisign.PrivateKey{}, "", err
	}
	if configured := strings.TrimSpace(s.cfg.UpdatePublicKey); configured != "" && configured != strings.TrimSpace(pubText) {
		return minisign.PrivateKey{}, "", errors.New("update.key does not match ORCH_UPDATE_PUBKEY")
	}
	return priv, strings.TrimSpace(pubText), nil
}

func hashMultipartFile(file multipart.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func parseFormInt64(r *http.Request, key string) int64 {
	value := strings.TrimSpace(r.FormValue(key))
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func (s *server) storeAPKRelease(manifest apkReleaseRecord, manifestJSON, minisig string, apk multipart.File, _ *multipart.FileHeader) (apkReleaseRecord, error) {
	releaseDir := filepath.Join(s.cfg.StateDir, "apk", "releases", fmt.Sprintf("%d", manifest.Seq))
	if err := os.MkdirAll(releaseDir, 0o700); err != nil {
		return apkReleaseRecord{}, err
	}
	tmpPath := filepath.Join(releaseDir, manifest.APKName+".tmp")
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return apkReleaseRecord{}, err
	}
	digest := sha256.New()
	size, copyErr := io.Copy(out, io.TeeReader(apk, digest))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return apkReleaseRecord{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return apkReleaseRecord{}, closeErr
	}
	actualSHA := hex.EncodeToString(digest.Sum(nil))
	if size != manifest.APKSize || !actualSHAEquals(actualSHA, manifest.APKSHA256) {
		_ = os.Remove(tmpPath)
		return apkReleaseRecord{}, fmt.Errorf("apk mismatch sha=%s size=%d", actualSHA, size)
	}
	apkPath := filepath.Join(releaseDir, manifest.APKName)
	if err := os.Rename(tmpPath, apkPath); err != nil {
		_ = os.Remove(tmpPath)
		return apkReleaseRecord{}, err
	}
	manifestPath := filepath.Join(releaseDir, "update-manifest.json")
	minisigPath := filepath.Join(releaseDir, "update-manifest.json.minisig")
	if err := os.WriteFile(manifestPath, []byte(strings.TrimSpace(manifestJSON)), 0o600); err != nil {
		return apkReleaseRecord{}, err
	}
	if err := os.WriteFile(minisigPath, []byte(strings.TrimSpace(minisig)), 0o600); err != nil {
		return apkReleaseRecord{}, err
	}
	manifest.APKPath = apkPath
	manifest.ManifestPath = manifestPath
	manifest.MinisigPath = minisigPath
	if err := s.store.setAPKRelease(manifest); err != nil {
		return apkReleaseRecord{}, err
	}
	if err := s.pruneOldAPKReleases(s.cfg.APKKeepReleases, manifest.Seq); err != nil {
		log.Printf("apk release prune failed: %v", err)
	}
	return manifest, nil
}

func (s *server) loadUpdateArtifact() (*updateArtifact, error) {
	rec, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok {
		return nil, err
	}
	manifestJSON, err := os.ReadFile(rec.ManifestPath)
	if err != nil {
		return nil, err
	}
	minisig, err := os.ReadFile(rec.MinisigPath)
	if err != nil {
		return nil, err
	}
	apk, err := os.ReadFile(rec.APKPath)
	if err != nil {
		return nil, err
	}
	return &updateArtifact{
		ManifestJSON:    strings.TrimSpace(string(manifestJSON)),
		ManifestMinisig: strings.TrimSpace(string(minisig)),
		APKName:         rec.APKName,
		APKSHA256:       rec.APKSHA256,
		APKBase64:       base64.StdEncoding.EncodeToString(apk),
	}, nil
}

func loadOrCreateUpdateSigningKey(cfg *orchConfig) (minisign.PrivateKey, error) {
	keyPath := filepath.Join(cfg.StateDir, "update.key")
	pubPath := filepath.Join(cfg.StateDir, "update.pub")
	if raw, err := os.ReadFile(keyPath); err == nil {
		var priv minisign.PrivateKey
		if err := priv.UnmarshalText(raw); err != nil {
			return minisign.PrivateKey{}, fmt.Errorf("invalid update key: %w", err)
		}
		if strings.TrimSpace(cfg.UpdatePublicKey) == "" {
			pubText, err := updatePublicKeyText(priv)
			if err != nil {
				return minisign.PrivateKey{}, err
			}
			cfg.UpdatePublicKey = pubText
		}
		return priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return minisign.PrivateKey{}, err
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	privText, err := priv.MarshalText()
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	if err := os.WriteFile(keyPath, privText, 0o600); err != nil {
		return minisign.PrivateKey{}, err
	}
	if err := os.WriteFile(pubPath, pubText, 0o644); err != nil {
		return minisign.PrivateKey{}, err
	}
	if strings.TrimSpace(cfg.UpdatePublicKey) == "" {
		cfg.UpdatePublicKey = string(pubText)
	}
	log.Printf("generated update minisign key public_key=%s", strings.TrimSpace(string(pubText)))
	return priv, nil
}

func updatePublicKeyText(priv minisign.PrivateKey) (string, error) {
	pub, ok := priv.Public().(minisign.PublicKey)
	if !ok {
		return "", errors.New("unexpected update public key type")
	}
	raw, err := pub.MarshalText()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *server) seedUpdateAPKIfPresent(updatePrivate minisign.PrivateKey) error {
	path := strings.TrimSpace(s.cfg.SeedAPKPath)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("SEED_APK_PATH points to a directory: %s", path)
	}
	if _, ok, err := s.store.currentAPKRelease(); err != nil || ok {
		return err
	}
	localPub, err := updatePublicKeyText(updatePrivate)
	if err != nil {
		return err
	}
	if strings.TrimSpace(s.cfg.UpdatePublicKey) != strings.TrimSpace(localPub) {
		return errors.New("seed apk requires ORCH_UPDATE_PUBKEY to match the local update key, or ORCH_UPDATE_PUBKEY must be empty")
	}
	sha, size, err := fileSHA256AndSize(path)
	if err != nil {
		return err
	}
	manifestJSON, err := buildAPKManifest(apkManifestInput{
		Seq:         1,
		VersionCode: s.cfg.SeedVersionCode,
		VersionName: s.cfg.SeedVersionName,
		APKSHA256:   sha,
		APKSize:     size,
		APKName:     filepath.Base(path),
		Notes:       "seed-on-first-run",
	})
	if err != nil {
		return err
	}
	minisigText := string(minisign.Sign(updatePrivate, []byte(manifestJSON)))
	manifest, err := parseAPKManifest(manifestJSON)
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := s.storeAPKRelease(manifest, manifestJSON, minisigText, file, nil); err != nil {
		return err
	}
	log.Printf("seeded APK update artifact seq=1 apk=%s sha256=%s", filepath.Base(path), sha)
	return nil
}

func fileSHA256AndSize(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func optionalAPKRelease(rec apkReleaseRecord, ok bool) any {
	if !ok {
		return nil
	}
	return rec
}

func mustNextAPKSeq(st *orchStore) int64 {
	seq, err := st.nextAPKSeq()
	if err != nil {
		return 0
	}
	return seq
}

func safeAPKName(value string, versionCode int64) string {
	name := filepath.Base(strings.TrimSpace(value))
	if name == "." || name == "/" || name == "" {
		name = fmt.Sprintf("app-public-%d.apk", versionCode)
	}
	if !strings.HasSuffix(strings.ToLower(name), ".apk") {
		name += ".apk"
	}
	return name
}

func actualSHAEquals(actual, expected string) bool {
	return strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected))
}

func parseRFC3339Required(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, errors.New("expires is required")
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

func parseJSONObjectRaw(value string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		trimmed = "{}"
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, fmt.Errorf("limits must be json object: %w", err)
	}
	return json.RawMessage(trimmed), nil
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func randID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getenvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
