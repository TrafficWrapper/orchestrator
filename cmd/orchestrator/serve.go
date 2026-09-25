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
	if !cfg.TLS {
		log.Printf("WARNING: built-in TLS is disabled (ORCH_TLS=%q); serve plain HTTP only behind a TLS-terminating proxy", os.Getenv("ORCH_TLS"))
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
	background.Add(4)
	go func() { defer background.Done(); s.runNoiseSessionJanitor(ctx) }()
	go func() { defer background.Done(); s.runWorkerJanitor(ctx) }()
	go func() { defer background.Done(); s.runClientBundlePublisher(ctx) }()
	go func() { defer background.Done(); s.runAPKManifestReissue(ctx) }()
	// Deferred in reverse: wait for janitors before audit/store close.
	defer background.Wait()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", s.handleReadyz)
	s.registerWebRoutes(mux)
	for _, rt := range s.apiRoutes() {
		mux.HandleFunc(rt.path, rt.handler)
	}
	addr := cfg.Listen
	log.Printf("orchestrator serve listen=%s tls=%t public_key=%s", addr, cfg.TLS, protocol.KeyToBase64(static.Public))
	httpServer := newOrchestratorHTTPServer(addr, mux)
	// Handlers (notably the nudge long-poll) see the shutdown via r.Context().
	httpServer.BaseContext = func(net.Listener) context.Context { return ctx }
	serveErr := make(chan error, 1)
	go func() {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			serveErr <- err
			return
		}
		// Bound concurrent connections so a flood cannot exhaust file
		// descriptors or memory before any request is authenticated.
		listener = newLimitListener(listener, maxServerConnections)
		if cfg.TLS {
			cert, key, err := loadOrCreateTLS(cfg)
			if err != nil {
				_ = listener.Close()
				serveErr <- err
				return
			}
			serveErr <- httpServer.ServeTLS(listener, cert, key)
			return
		}
		serveErr <- httpServer.Serve(listener)
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
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}
}

const (
	// maxRequestHeaderBytes: no API needs more than a few KiB of headers.
	maxRequestHeaderBytes = 64 << 10
	// maxServerConnections bounds open connections; every worker holds at
	// most one long-poll at a time, so this leaves ample headroom.
	maxServerConnections = 8192
)

// limitListener caps concurrent connections: Accept waits for a free slot.
type limitListener struct {
	net.Listener
	slots chan struct{}
}

func newLimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, slots: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.slots }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
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

type apiRoute struct {
	path    string
	handler http.HandlerFunc
}

// apiRoutes is the single table of API endpoints. Admin handlers only get
// method, session and CSRF checks through s.admin, so they must never be
// registered from anywhere else (tests look routes up here too).
func (s *server) apiRoutes() []apiRoute {
	return []apiRoute{
		{"/discovery/endpoints.json", s.handleDiscoveryEndpointsJSON},
		{"/discovery/endpoints.json.minisig", s.handleDiscoveryEndpointsMinisig},
		{"/w/v1/handshake/start", s.handleHandshakeStart},
		{"/w/v1/enroll", s.handleNoise(s.handleEnroll)},
		{"/w/v1/config/pull", s.handleNoise(s.handlePull)},
		{"/w/v1/nudge/wait", s.handleNoiseContext(s.handleNudge)},
		{"/w/v1/ack", s.handleNoise(s.handleAck)},
		{"/w/v1/telemetry", s.handleNoise(s.handleWorkerTelemetry)},
		{"/d/v1/handshake/start", s.handleHandshakeStart},
		{"/d/v1/enroll", s.handleNoise(s.handleDeviceEnroll)},
		{"/admin/v1/login", s.handleAdminLogin},
		{"/admin/v1/logout", s.handleAdminLogout},
		{"/admin/v1/password/change", s.handleAdminPasswordChange},
		{"/admin/v1/password/force-set", s.admin(adminPOST, s.handleAdminPasswordForceSet)},
		{"/admin/v1/totp/enroll", s.admin(adminPOST, s.handleAdminTOTPEnroll)},
		{"/admin/v1/totp/enable", s.admin(adminPOST, s.handleAdminTOTPEnable)},
		{"/admin/v1/totp/disable", s.admin(adminPOST, s.handleAdminTOTPDisable)},
		{"/admin/v1/bot/status", s.admin(adminGET, s.handleAdminBotStatus)},
		{"/admin/v1/bot/set-token", s.admin(adminPOST, s.handleAdminBotSetToken)},
		{"/admin/v1/token/create", s.admin(adminPOST, s.handleAdminTokenCreate)},
		{"/admin/v1/bootstrap-token/create", s.admin(adminPOST, s.handleAdminBootstrapTokenCreate)},
		{"/admin/v1/bootstrap-token/qr", s.admin(adminPOST, s.handleAdminBootstrapTokenQR)},
		{"/admin/v1/approve-worker", s.admin(adminPOST, s.handleAdminApproveWorker)},
		{"/admin/v1/workers/revoke", s.admin(adminPOST, s.handleAdminWorkerRevoke)},
		{"/admin/v1/client-seq/floor", s.admin(adminPOST, s.handleAdminClientSeqFloor)},
		{"/admin/v1/revoke-device", s.admin(adminPOST, s.handleAdminRevokeDevice)},
		{"/admin/v1/delete-device", s.admin(adminPOST, s.handleAdminDeleteDevice)},
		{"/admin/v1/device-alias", s.admin(adminPOST, s.handleAdminDeviceAlias)},
		{"/admin/v1/workers", s.admin(adminGET, s.handleAdminWorkers)},
		{"/admin/v1/workers/set-enabled", s.admin(adminPOST, s.handleAdminWorkerSetEnabled)},
		{"/admin/v1/workers/protocol", s.admin(adminPOST, s.handleAdminWorkerProtocol)},
		{"/admin/v1/workers/short-id", s.admin(adminPOST, s.handleAdminWorkerShortID)},
		{"/admin/v1/workers/awg-drain", s.admin(adminPOST, s.handleAdminWorkerAWGDrain)},
		{"/admin/v1/devices", s.admin(adminGET, s.handleAdminDevices)},
		{"/admin/v1/config", s.admin(adminGET, s.handleAdminConfig)},
		{"/admin/v1/config/edit", s.admin(adminPOST, s.handleAdminConfigEdit)},
		{"/admin/v1/apk/status", s.admin(adminGET, s.handleAdminAPKStatus)},
		{"/admin/v1/apk/download", s.admin(adminGET, s.handleAdminAPKDownload)},
		{"/admin/v1/apk/inspect", s.admin(adminPOST, s.handleAdminAPKInspect)},
		{"/admin/v1/apk/draft", s.admin(adminPOST, s.handleAdminAPKDraft)},
		{"/admin/v1/apk/publish", s.admin(adminPOST, s.handleAdminAPKPublish)},
		{"/admin/v1/discovery/bump", s.admin(adminPOST, s.handleAdminDiscoveryBump)},
		{"/admin/v1/status", s.admin(adminGET, s.handleAdminStatus)},
	}
}
