package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/flynn/noise"
	bolt "go.etcd.io/bbolt"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func runServe(cfg orchConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := setClientIPHeaderMode(cfg.ClientIPHeader); err != nil {
		return err
	}
	if publicURLIsLoopback(cfg.PublicURL) {
		log.Printf("WARNING: ORCH_PUBLIC_URL=%s is a loopback address; bootstrap payloads will point devices at it. Set it to the orchestrator's reachable URL.", cfg.PublicURL)
	}
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
	s := &server{cfg: cfg, store: st, signer: signerClient{socket: cfg.SignerSocket}, static: static, loginLimiter: newLoginLimiter(), audit: audit, rootCtx: ctx}
	if _, err := s.signer.publicKey(); err != nil {
		return fmt.Errorf("signer unavailable: %w", err)
	}
	if err := s.seedUpdateAPKIfPresent(updatePrivate); err != nil {
		return err
	}
	if err := s.startOptionalBot(ctx, newTelegramHTTPClient); err != nil {
		return err
	}
	var background sync.WaitGroup
	background.Add(2)
	go func() { defer background.Done(); s.runNoiseSessionJanitor(ctx) }()
	go func() { defer background.Done(); s.runWorkerJanitor(ctx) }()
	// Deferred in reverse: wait for janitors before audit/store close.
	defer background.Wait()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", s.handleReadyz)
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
	mux.HandleFunc("/admin/v1/logout", s.handleAdminLogout)
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
	httpServer := newOrchestratorHTTPServer(addr, mux)
	// Handlers (notably the nudge long-poll) see the shutdown via r.Context().
	httpServer.BaseContext = func(net.Listener) context.Context { return ctx }
	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLS {
			cert, key, err := loadOrCreateTLS(cfg)
			if err != nil {
				serveErr <- err
				return
			}
			serveErr <- httpServer.ListenAndServeTLS(cert, key)
			return
		}
		serveErr <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-serveErr:
		stop()
		return err
	case <-ctx.Done():
	}
	log.Printf("orchestrator shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
	return nil
}

// shutdownTimeout bounds how long in-flight requests may finish on SIGTERM.
const shutdownTimeout = 20 * time.Second

func newOrchestratorHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           withSecurityHeaders(withRequestBodyLimits(handler)),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
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
			// Expiry-based blocks need no usage report, so they are swept here
			// instead of scanning every device on every worker ack.
			if _, err := s.store.pruneDeadTokens(time.Now().UTC()); err != nil {
				log.Printf("token prune failed: %v", err)
			}
			if blocked, err := s.store.applyDeviceUsageAndBlocks("", nil, time.Now().UTC()); err != nil {
				log.Printf("device expiry janitor failed: %v", err)
			} else if blocked > 0 {
				log.Printf("device expiry janitor blocked count=%d", blocked)
			}
		}
	}
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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
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

// readyzCacheTTL keeps frequent probes from hammering the signer.
const readyzCacheTTL = 5 * time.Second

// handleReadyz reports whether the orchestrator can serve configs: the signer
// answers (a signer outage breaks every pull and enroll while /healthz, a
// pure liveness probe, stays green) and the database is readable.
func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.readyMu.Lock()
	cached, at := s.readyResult, s.readyAt
	s.readyMu.Unlock()
	if at.IsZero() || time.Since(at) >= readyzCacheTTL {
		checks := map[string]string{"signer": "ok", "store": "ok"}
		if _, err := s.signer.publicKey(); err != nil {
			log.Printf("readyz: signer: %v", err)
			checks["signer"] = "unavailable"
		}
		if err := s.store.db.View(func(*bolt.Tx) error { return nil }); err != nil {
			log.Printf("readyz: store: %v", err)
			checks["store"] = "unavailable"
		}
		cached = checks
		s.readyMu.Lock()
		s.readyResult, s.readyAt = cached, time.Now()
		s.readyMu.Unlock()
	}
	ready := true
	for _, v := range cached {
		ready = ready && v == "ok"
	}
	w.Header().Set("Cache-Control", "no-store")
	if !ready {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "checks": cached})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "checks": cached})
}
