package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type orchConfig struct {
	StateDir            string
	Listen              string
	SignerSocket        string
	SignerKeyPath       string
	SignerLegacyKeyPath string
	ClientIPHeader      string
	// ClientSeqFloor is the lowest client bundle seq ever published
	// (ORCH_CLIENT_SEQ_FLOOR); ClientBundleTTL sets expires_at.
	ClientSeqFloor  int64
	ClientBundleTTL time.Duration
	// AllowNewMasterKey lets the store create master.key over a database
	// that already holds encrypted records (discarding them);
	// AllowUnreadableRecords starts even if some records do not decrypt.
	AllowNewMasterKey      bool
	AllowUnreadableRecords bool
	// APKManifestTTL sets update manifest expires_at; APKPackage pins the
	// app package every published APK must carry.
	APKManifestTTL time.Duration
	APKPackage     string
	// APKInlineMaxBytes caps APKs shipped inside config pull
	// (ORCH_APK_INLINE_MAX_BYTES); APKMaxBytes caps published APKs.
	APKInlineMaxBytes       int64
	APKMaxBytes             int64
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
	cfg          orchConfig
	store        *orchStore
	signer       configSigner
	static       noise.DHKey
	sessions     sync.Map
	sessionCount atomic.Int64
	// Reserved pool for workers presenting a handshake cookie.
	workerSessionCount atomic.Int64
	cookieKeyOnce      sync.Once
	cookieKey          []byte
	handshakeMu        sync.Mutex
	handshakeRates     map[string]handshakeRate
	handshakePending   map[string]int
	handshakePrune     time.Time
	telemetryNonceMu   sync.Mutex
	telemetryNonces    map[string]map[string]time.Time
	loginLimiterMu     sync.Mutex
	loginLimiter       *loginLimiter
	audit              *auditLog
	discoverySeqMu     sync.Mutex
	discoveryCacheMu   sync.Mutex
	// discoveryBuildMu serializes bundle rebuilds; the fields below it are
	// guarded by it.
	discoveryBuildMu    sync.Mutex
	discoveryBuildErr   error
	discoveryBuildErrAt time.Time
	discoveryBuildErrGn uint64
	discoveryInvalidGen atomic.Uint64
	discoveryCache      discoveryBundleCache
	discoveryBuilds     atomic.Int64
	discoveryRateMu     sync.Mutex
	discoveryRates      map[string]discoveryRequestRate
	adminSessions       sync.Map
	botMu               sync.Mutex
	apkPublishMu        sync.Mutex
	readyMu             sync.Mutex
	readyResult         map[string]string
	readyAt             time.Time
	apkShipOnce         sync.Once
	apkShipSem          chan struct{}
	apkShipMu           sync.Mutex
	apkShipWorkers      map[string]bool
	apkRef              *updateRef
	apkChunkOnce        sync.Once
	apkChunkSem         chan struct{}
	// startedAt is when this process started serving (ORC-L34).
	startedAt           time.Time
	apkArtifactMu       sync.Mutex
	apkArtifact         *updateArtifact
	apkArtifactSeq      int64
	clientBundleMu      sync.Mutex
	apkReissueMu        sync.Mutex
	clientBundleSigned  signedClientBundle
	updateKeyMu         sync.Mutex
	updateKeyCache      *updateKeyCacheEntry
	signerPubMu         sync.Mutex
	signerPub           string
	egressProbeMu       sync.Mutex
	egressProbeValue    string
	egressProbeAt       time.Time
	egressProbeFetching bool
	authApprover        authApprover
	bot                 *telegramBot
	botCancel           context.CancelFunc
	botFactory          telegramClientFactory
	// botRestartMu serializes whole bot restarts so two concurrent restarts
	// cannot both start a poller (Telegram answers the second with 409).
	botRestartMu sync.Mutex
	// rootCtx is cancelled on shutdown; long-lived goroutines derive from it.
	rootCtx context.Context
}

const (
	telemetrySignatureDomain = "TrafficWrapper telemetry v1"
	telemetryMaxPayloadBytes = 64 << 10
	telemetryMaxClockSkew    = 120 * time.Second
	telemetryNonceLRUMax     = 4096
	telemetryNonceDeviceMax  = 16 * 1024
	noiseSessionTTL          = 30 * time.Second
	noiseSessionJanitorEvery = 5 * time.Second
	maxNoiseSessions         = 16 * 1024
	// Pending (unfinished) handshakes allowed per rate-limit key (IPv4 or
	// IPv6 /64) and per wider prefix (IPv4 /24, IPv6 /48), so a few sources
	// cannot occupy the global pool and lock real workers/devices out.
	maxPendingHandshakesPerKey    = 16
	maxPendingHandshakesPerPrefix = 128
	handshakeRateWindow           = 10 * time.Second
	handshakeRateLimit            = 30
	handshakeRatePruneEvery       = time.Second
	maxHandshakeRateKeys          = 64 * 1024
	workerFreshTTL                = 2 * time.Minute
	workerJanitorEvery            = 30 * time.Second
)

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
	cfg, err := readConfig()
	if err != nil {
		// Only the server refuses to start; signer and offline recovery
		// commands must keep working despite, say, a bad ORCH_PUBLIC_URL.
		if cmd == "serve" {
			return fmt.Errorf("invalid configuration: %w", err)
		}
		log.Printf("warning: invalid configuration: %v", err)
	}
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
		if err := adminPost(cfg, "/admin/v1/revoke-device", map[string]string{"id": os.Args[2]}, os.Stdout); !errors.Is(err, errAdminServerUnreachable) {
			// Reached the server: report its answer instead of bypassing it.
			return err
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
		if err := adminPost(cfg, "/admin/v1/approve-worker", map[string]string{"id": os.Args[2]}, os.Stdout); !errors.Is(err, errAdminServerUnreachable) {
			// Reached the server: report its answer instead of bypassing it.
			return err
		}
		st, err := openOrchStore(cfg)
		if err != nil {
			return err
		}
		defer st.close()
		return st.approveWorker(os.Args[2])
	case "status":
		return statusCommand(cfg)
	case "store-clear-sealed-marker":
		// Recovery after a start with the wrong master.key: legacy records
		// are accepted and migrated again on the next start. Stop the
		// orchestrator first.
		if err := clearSealedFormatMarker(cfg.StateDir); err != nil {
			return err
		}
		fmt.Println("sealed format marker cleared")
		return nil
	case "signer-accept-key":
		// After an intentional signer key rotation: forget the pinned
		// config-signing public key so the next start pins the new one.
		// Stop the orchestrator first.
		if err := clearSignerPin(cfg.StateDir); err != nil {
			return err
		}
		fmt.Println("pinned signer public key cleared")
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// readConfig loads the environment strictly: malformed numbers, booleans or
// URLs fail startup instead of silently falling back to defaults.
func readConfig() (orchConfig, error) {
	env := &envReader{}
	stateDir := getenv("ORCH_STATE_DIR", "./orch-state")
	cfg := orchConfig{
		StateDir:                stateDir,
		Listen:                  getenv("ORCH_LISTEN", ":9091"),
		SignerSocket:            getenv("ORCH_SIGNER_SOCKET", "./orch-state/signer.sock"),
		SignerKeyPath:           os.Getenv("ORCH_SIGNER_KEY_PATH"),
		SignerLegacyKeyPath:     os.Getenv("ORCH_SIGNER_LEGACY_KEY_PATH"),
		ClientIPHeader:          os.Getenv("ORCH_CLIENT_IP_HEADER"),
		PublicURL:               env.url("ORCH_PUBLIC_URL", "https://127.0.0.1:9091", true),
		EgressProbeURL:          env.url("ORCH_EGRESS_PROBE_URL", "", false),
		AdminSecret:             os.Getenv("ORCH_ADMIN_SECRET"),
		UpdatePublicKey:         os.Getenv("ORCH_UPDATE_PUBKEY"),
		DNSServers:              splitCSV(os.Getenv("ORCH_DNS_SERVERS")),
		DiscoveryNextSinks:      splitCSV(os.Getenv("ORCH_DISCOVERY_NEXT_SINKS")),
		DiscoveryRescuePointers: splitCSV(os.Getenv("ORCH_DISCOVERY_RESCUE_POINTERS")),
		SeedAPKPath:             getenv("SEED_APK_PATH", "./seed/app.apk"),
		SeedVersionCode:         env.int64("SEED_APK_VERSION_CODE", 1, 0),
		SeedVersionName:         getenv("SEED_APK_VERSION_NAME", "seed"),
		APKKeepReleases:         int(env.int64("ORCH_APK_KEEP_RELEASES", 5, 0)),
		TLS:                     env.bool("ORCH_TLS", true),
		ClientSeqFloor:          env.int64("ORCH_CLIENT_SEQ_FLOOR", 0, 0),
		ClientBundleTTL:         env.duration("ORCH_CLIENT_BUNDLE_TTL", 24*time.Hour, time.Hour),
		AllowNewMasterKey:       env.bool("ORCH_ALLOW_NEW_MASTER_KEY", false),
		AllowUnreadableRecords:  env.bool("ORCH_STORE_ALLOW_UNREADABLE", false),
		APKManifestTTL:          env.duration("ORCH_APK_MANIFEST_TTL", defaultAPKManifestTTL, 24*time.Hour),
		APKPackage:              strings.TrimSpace(os.Getenv("ORCH_APK_PACKAGE")),
		APKInlineMaxBytes:       env.int64("ORCH_APK_INLINE_MAX_BYTES", defaultAPKInlineMaxBytes, 0),
		APKMaxBytes:             env.int64("ORCH_APK_MAX_BYTES", defaultAPKMaxBytes, 1),
	}
	if err := validateAPKLimits(cfg); err != nil {
		env.errs = append(env.errs, err)
	}
	return cfg, errors.Join(env.errs...)
}

// envReader parses typed environment values and collects every error so a
// misconfiguration is reported in full at startup.
type envReader struct {
	errs []error
}

func (e *envReader) bool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	e.errs = append(e.errs, fmt.Errorf("%s=%q: want a boolean (1/0, true/false, yes/no, on/off)", key, value))
	return fallback
}

func (e *envReader) int64(key string, fallback, min int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < min {
		e.errs = append(e.errs, fmt.Errorf("%s=%q: want an integer >= %d", key, value, min))
		return fallback
	}
	return parsed
}

func (e *envReader) duration(key string, fallback, min time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < min {
		e.errs = append(e.errs, fmt.Errorf("%s=%q: want a duration >= %s", key, value, min))
		return fallback
	}
	return parsed
}

func (e *envReader) url(key, fallback string, required bool) string {
	value := getenv(key, fallback)
	if value == "" && !required {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		e.errs = append(e.errs, fmt.Errorf("%s=%q: want an absolute http(s) URL", key, value))
	}
	return value
}

// publicURLIsLoopback reports whether devices would be handed a bootstrap
// URL they cannot reach (the default ORCH_PUBLIC_URL).
func publicURLIsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
