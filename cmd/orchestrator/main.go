package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type orchConfig struct {
	StateDir                string
	Listen                  string
	SignerSocket            string
	SignerKeyPath           string
	SignerLegacyKeyPath     string
	ClientIPHeader          string
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
	cfg              orchConfig
	store            *orchStore
	signer           configSigner
	static           noise.DHKey
	sessions         sync.Map
	sessionCount     atomic.Int64
	handshakeMu      sync.Mutex
	handshakeRates   map[string]handshakeRate
	handshakePending map[string]int
	handshakePrune   time.Time
	telemetryNonceMu sync.Mutex
	telemetryNonces  map[string]map[string]time.Time
	loginLimiterMu   sync.Mutex
	loginLimiter     *loginLimiter
	audit            *auditLog
	discoverySeqMu   sync.Mutex
	discoveryCacheMu sync.Mutex
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
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func readConfig() orchConfig {
	return orchConfig{
		StateDir:                getenv("ORCH_STATE_DIR", "./orch-state"),
		Listen:                  getenv("ORCH_LISTEN", ":9091"),
		SignerSocket:            getenv("ORCH_SIGNER_SOCKET", "./orch-state/signer.sock"),
		SignerKeyPath:           os.Getenv("ORCH_SIGNER_KEY_PATH"),
		SignerLegacyKeyPath:     os.Getenv("ORCH_SIGNER_LEGACY_KEY_PATH"),
		ClientIPHeader:          os.Getenv("ORCH_CLIENT_IP_HEADER"),
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
