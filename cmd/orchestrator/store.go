package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

var (
	bucketWorkers   = []byte("workers")
	bucketTokens    = []byte("tokens")
	bucketDevices   = []byte("devices")
	bucketTelemetry = []byte("telemetry")
	bucketMeta      = []byte("meta")

	metaAdminSecret = []byte("admin_secret")
	metaAPKRelease  = []byte("apk_release")
	metaBotSettings = []byte("bot_settings")
	metaBotProblems = []byte("bot_problem_state")
	metaAdminTOTP   = []byte("admin_totp")
	// metaSealedFormat records that every sealed record uses the bound v2
	// format; from then on legacy (unbound) ciphertexts are rejected.
	metaSealedFormat = []byte("sealed_format")
)

type orchStore struct {
	db                      *bolt.DB
	aead                    cipher.AEAD
	tokenLookupKey          []byte
	discoveryWorkerRevision atomic.Uint64
	// rejectLegacySealed is set once migration has bound every record, so an
	// old unbound ciphertext (e.g. from a backup) cannot be planted under
	// another key.
	rejectLegacySealed atomic.Bool

	// seqSignal is closed (and replaced) after every commit that changes a
	// worker's DesiredSeq, waking nudge long-polls without DB polling.
	seqSignalMu sync.Mutex
	seqSignal   chan struct{}

	// approvedCache holds decrypted approved devices for the device-config
	// revision approvedCacheRev (the devices bucket sequence, see
	// approvedDevices).
	approvedCacheMu  sync.Mutex
	approvedCacheRev uint64
	approvedCacheSet bool
	approvedCache    []deviceRecord
}

type tokenRecord struct {
	ID              string          `json:"id"`
	Hash            string          `json:"hash"`
	Kind            string          `json:"kind,omitempty"`
	ExpiresAt       time.Time       `json:"expires_at"`
	MaxUses         int             `json:"max_uses"`
	Uses            int             `json:"uses"`
	CreatedAt       time.Time       `json:"created_at"`
	Limits          json.RawMessage `json:"limits,omitempty"`
	SeedWorkers     []string        `json:"seed_workers,omitempty"`
	WorkerStaticPub string          `json:"worker_static_pub,omitempty"`
	// Lookup is a keyed HMAC of the secret used to find the record without
	// running PBKDF2 against every stored token. Legacy records lack it.
	Lookup string `json:"lookup,omitempty"`
}

type workerRecord struct {
	ID               string          `json:"id"`
	Status           string          `json:"status"`
	StaticPublicKey  string          `json:"static_public_key"`
	SelfDescribe     map[string]any  `json:"self_describe"`
	CreatedAt        time.Time       `json:"created_at"`
	ApprovedAt       *time.Time      `json:"approved_at,omitempty"`
	DesiredSeq       int64           `json:"desired_seq"`
	AppliedSeq       int64           `json:"applied_seq"`
	LastAckAt        *time.Time      `json:"last_ack_at,omitempty"`
	EgressIPObserved string          `json:"egress_ip_observed,omitempty"`
	EgressIPProbe    string          `json:"egress_ip_probe,omitempty"`
	LastError        string          `json:"last_error,omitempty"`
	Disabled         bool            `json:"disabled,omitempty"`
	ConfigPriority   *int            `json:"config_priority,omitempty"`
	ConfigWeight     *int            `json:"config_weight,omitempty"`
	ProtocolEnabled  map[string]bool `json:"protocol_enabled,omitempty"`
	// APK delivery tracking: the release seq last shipped in a pull, the
	// worker config seq it shipped with, and the release seq the worker has
	// acknowledged applying. Lets pulls skip re-sending an unchanged APK.
	APKSentSeq    int64 `json:"apk_sent_seq,omitempty"`
	APKSentAtSeq  int64 `json:"apk_sent_at_seq,omitempty"`
	APKAppliedSeq int64 `json:"apk_applied_seq,omitempty"`
}

type adminTOTPRecord struct {
	Secret string `json:"secret"`
	// PendingSecret holds a re-enrollment secret while the current one stays
	// active, so an unfinished re-enrollment never switches 2FA off.
	PendingSecret string    `json:"pending_secret,omitempty"`
	Enabled       bool      `json:"enabled"`
	LastCounter   int64     `json:"last_counter"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type deviceRecord struct {
	ID              string                        `json:"id"`
	Alias           string                        `json:"alias,omitempty"`
	Status          string                        `json:"status"`
	NoisePublicKey  string                        `json:"noise_public_key"`
	IdentityPubKey  string                        `json:"identity_pubkey"`
	IdentityKeyType string                        `json:"identity_key_type,omitempty"`
	AndroidID       string                        `json:"android_id,omitempty"`
	Model           string                        `json:"model,omitempty"`
	EnrollmentNonce string                        `json:"enrollment_nonce,omitempty"`
	ClientVersion   string                        `json:"client_version,omitempty"`
	AWGPublicKey    string                        `json:"awg_public_key,omitempty"`
	RealityUUID     string                        `json:"reality_uuid,omitempty"`
	InternalIP      string                        `json:"internal_ip,omitempty"`
	PSK2            string                        `json:"psk2,omitempty"`
	AWGProfiles     map[string]deviceAWGProfile   `json:"awg_profiles,omitempty"`
	BootstrapToken  string                        `json:"bootstrap_token"`
	Limits          deviceLimits                  `json:"limits,omitempty"`
	UsageRxBytes    uint64                        `json:"usage_rx_bytes,omitempty"`
	UsageTxBytes    uint64                        `json:"usage_tx_bytes,omitempty"`
	UsageCounters   map[string]deviceUsageCounter `json:"usage_counters,omitempty"`
	UsageUpdatedAt  *time.Time                    `json:"usage_updated_at,omitempty"`
	BlockedAt       *time.Time                    `json:"blocked_at,omitempty"`
	BlockedReason   string                        `json:"blocked_reason,omitempty"`
	CreatedAt       time.Time                     `json:"created_at"`
	ConfigSeq       int64                         `json:"config_seq"`
}

type deviceUsageCounter struct {
	RxBytes uint64 `json:"rx_bytes,omitempty"`
	TxBytes uint64 `json:"tx_bytes,omitempty"`
}

type deviceAWGProfile struct {
	AWGPublicKey string `json:"awg_public_key,omitempty"`
	InternalIP   string `json:"internal_ip,omitempty"`
	PSK2         string `json:"psk2,omitempty"`
}

type deviceLimits struct {
	TrafficQuotaBytes uint64  `json:"traffic_quota_bytes,omitempty"`
	RateLimit         string  `json:"rate_limit,omitempty"`
	ExpiresAt         *string `json:"expires_at,omitempty"`
}

type telemetrySnapshotRecord struct {
	DeviceID      string            `json:"device_id"`
	WorkerID      string            `json:"worker_id"`
	ReceivedAt    time.Time         `json:"received_at"`
	SentAtMs      int64             `json:"sent_at_ms,omitempty"`
	ClientVersion string            `json:"client_version,omitempty"`
	ClientVC      int64             `json:"client_vc,omitempty"`
	Route         string            `json:"route,omitempty"`
	Health        string            `json:"health,omitempty"`
	Carry         bool              `json:"carry"`
	UptimeSeconds int64             `json:"uptime_s,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
	Recent        []telemetryEvent  `json:"recent,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

type telemetryEvent struct {
	Kind   string `json:"kind"`
	AtMs   int64  `json:"at_ms,omitempty"`
	Route  string `json:"route,omitempty"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type adminSecretRecord struct {
	Hash       string    `json:"hash"`
	UpdatedAt  time.Time `json:"updated_at"`
	MustChange bool      `json:"must_change,omitempty"`
}

type botSettingsRecord struct {
	Token     string    `json:"token"`
	OwnerID   int64     `json:"owner_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type apkReleaseRecord struct {
	Seq          int64     `json:"seq"`
	VersionCode  int64     `json:"version_code"`
	VersionName  string    `json:"version_name"`
	MinVersion   int64     `json:"min_version"`
	Notes        string    `json:"notes,omitempty"`
	APKName      string    `json:"apk_name"`
	APKSHA256    string    `json:"apk_sha256"`
	APKSize      int64     `json:"apk_size"`
	ManifestPath string    `json:"manifest_path"`
	MinisigPath  string    `json:"minisig_path"`
	APKPath      string    `json:"apk_path"`
	CreatedAt    time.Time `json:"created_at"`
}

func openOrchStore(cfg orchConfig) (*orchStore, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateMasterKey(filepath.Join(cfg.StateDir, "master.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(cfg.StateDir, "orchestrator.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &orchStore{db: db, aead: aead, tokenLookupKey: deriveTokenLookupKey(key)}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketWorkers, bucketTokens, bucketDevices, bucketTelemetry, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	migrated, err := s.migrateSealedRecords()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sealed records: %w", err)
	}
	if migrated > 0 {
		log.Printf("store: bound %d legacy sealed records to their keys", migrated)
	}
	return s, nil
}

func (s *orchStore) close() error {
	return s.db.Close()
}

func loadOrCreateMasterKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, err
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("master key has %d bytes", len(key))
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func workerID(staticPub string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(staticPub)))
	return hex.EncodeToString(sum[:8])
}

func deviceID(identityPub, noisePub string) string {
	key := strings.TrimSpace(identityPub)
	if key == "" {
		key = strings.TrimSpace(noisePub)
	}
	sum := sha256.Sum256([]byte(key))
	return "twpk_" + hex.EncodeToString(sum[:])[:32]
}

func randomTokenSecret() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func copyRawJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}

func parseDeviceLimitsRaw(raw json.RawMessage) (deviceLimits, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return deviceLimits{}, nil
	}
	var limits deviceLimits
	if err := json.Unmarshal(raw, &limits); err != nil {
		return deviceLimits{}, err
	}
	if limits.ExpiresAt != nil {
		trimmed := strings.TrimSpace(*limits.ExpiresAt)
		if trimmed == "" {
			limits.ExpiresAt = nil
		} else {
			if _, err := time.Parse(time.RFC3339, trimmed); err != nil {
				return deviceLimits{}, fmt.Errorf("expires_at: %w", err)
			}
			limits.ExpiresAt = &trimmed
		}
	}
	limits.RateLimit = strings.TrimSpace(limits.RateLimit)
	return limits, nil
}

func deviceLimitsEmpty(limits deviceLimits) bool {
	return limits.TrafficQuotaBytes == 0 && strings.TrimSpace(limits.RateLimit) == "" && limits.ExpiresAt == nil
}

func deviceLimitsExpired(limits deviceLimits, now time.Time) bool {
	if limits.ExpiresAt == nil {
		return false
	}
	value := strings.TrimSpace(*limits.ExpiresAt)
	if value == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}
	return !now.Before(expiresAt.UTC())
}

func (s *orchStore) setAdminPassword(secret string) error {
	return s.setAdminPasswordWithMustChange(secret, false)
}

func (s *orchStore) setAdminPasswordWithMustChange(secret string, mustChange bool) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return errors.New("admin secret is required")
	}
	hash, err := protocol.HashSecret(secret)
	if err != nil {
		return err
	}
	rec := adminSecretRecord{Hash: hash, UpdatedAt: time.Now().UTC(), MustChange: mustChange}
	sealed, err := s.sealJSON(bucketMeta, metaAdminSecret, rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaAdminSecret, sealed)
	})
}

func (s *orchStore) ensureAdminPassword(secret string) (string, bool, error) {
	secret = strings.TrimSpace(secret)
	configured, err := s.adminPasswordConfigured()
	if err != nil {
		return "", false, err
	}
	if configured {
		return "", false, nil
	}
	if secret != "" {
		return "", false, s.setAdminPassword(secret)
	}
	initial, err := randomTokenSecret()
	if err != nil {
		return "", false, err
	}
	return initial, true, s.setAdminPasswordWithMustChange(initial, true)
}

func (s *orchStore) adminPasswordConfigured() (bool, error) {
	configured := false
	err := s.db.View(func(tx *bolt.Tx) error {
		configured = tx.Bucket(bucketMeta).Get(metaAdminSecret) != nil
		return nil
	})
	return configured, err
}

func (s *orchStore) verifyAdminPassword(secret string) (bool, bool, error) {
	var rec adminSecretRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaAdminSecret)
		if raw == nil {
			return errors.New("admin password is not configured")
		}
		return s.openJSON(bucketMeta, metaAdminSecret, raw, &rec)
	})
	if err != nil {
		return false, false, err
	}
	ok := protocol.VerifySecret(rec.Hash, strings.TrimSpace(secret))
	return ok, rec.MustChange, nil
}

func (s *orchStore) adminTOTP() (adminTOTPRecord, bool, error) {
	var rec adminTOTPRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaAdminTOTP)
		if raw == nil {
			return nil
		}
		return s.openJSON(bucketMeta, metaAdminTOTP, raw, &rec)
	})
	if err != nil {
		return adminTOTPRecord{}, false, err
	}
	if strings.TrimSpace(rec.Secret) == "" {
		return adminTOTPRecord{}, false, nil
	}
	return rec, rec.Enabled, nil
}

func (s *orchStore) startAdminTOTPEnrollment() (adminTOTPRecord, error) {
	secret, err := generateTOTPSecret()
	if err != nil {
		return adminTOTPRecord{}, err
	}
	var out adminTOTPRecord
	err = s.db.Update(func(tx *bolt.Tx) error {
		var rec adminTOTPRecord
		if raw := tx.Bucket(bucketMeta).Get(metaAdminTOTP); raw != nil {
			if err := s.openJSON(bucketMeta, metaAdminTOTP, raw, &rec); err != nil {
				return err
			}
		}
		now := time.Now().UTC()
		if rec.Enabled && strings.TrimSpace(rec.Secret) != "" {
			rec.PendingSecret = secret
			rec.UpdatedAt = now
			out = adminTOTPRecord{Secret: secret, Enabled: false, UpdatedAt: now}
		} else {
			rec = adminTOTPRecord{Secret: secret, Enabled: false, UpdatedAt: now}
			out = rec
		}
		sealed, err := s.sealJSON(bucketMeta, metaAdminTOTP, rec)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put(metaAdminTOTP, sealed)
	})
	return out, err
}

func (s *orchStore) enableAdminTOTP(code string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var rec adminTOTPRecord
		raw := tx.Bucket(bucketMeta).Get(metaAdminTOTP)
		if raw == nil {
			return errors.New("totp enrollment is not started")
		}
		if err := s.openJSON(bucketMeta, metaAdminTOTP, raw, &rec); err != nil {
			return err
		}
		secret := rec.Secret
		lastCounter := rec.LastCounter
		if strings.TrimSpace(rec.PendingSecret) != "" {
			// The replay counter belongs to the old secret; codes of a new
			// secret cannot be replays of it.
			secret = rec.PendingSecret
			lastCounter = 0
		}
		counter, ok := verifyTOTPCode(secret, code, now, lastCounter)
		if !ok {
			return errors.New("invalid totp code")
		}
		rec.Secret = secret
		rec.PendingSecret = ""
		rec.Enabled = true
		rec.LastCounter = counter
		rec.UpdatedAt = now.UTC()
		sealed, err := s.sealJSON(bucketMeta, metaAdminTOTP, rec)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put(metaAdminTOTP, sealed)
	})
}

func (s *orchStore) disableAdminTOTP() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Delete(metaAdminTOTP)
	})
}

func (s *orchStore) verifyAdminTOTP(code string, now time.Time) (bool, bool, error) {
	enabled := false
	ok := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		var rec adminTOTPRecord
		raw := tx.Bucket(bucketMeta).Get(metaAdminTOTP)
		if raw == nil {
			return nil
		}
		if err := s.openJSON(bucketMeta, metaAdminTOTP, raw, &rec); err != nil {
			return err
		}
		if strings.TrimSpace(rec.Secret) == "" || !rec.Enabled {
			return nil
		}
		enabled = true
		counter, verified := verifyTOTPCode(rec.Secret, code, now, rec.LastCounter)
		if !verified {
			return nil
		}
		rec.LastCounter = counter
		rec.UpdatedAt = now.UTC()
		sealed, err := s.sealJSON(bucketMeta, metaAdminTOTP, rec)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketMeta).Put(metaAdminTOTP, sealed); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return enabled, ok, err
}

func (s *orchStore) setBotSettings(token string, ownerID int64) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("bot token is required")
	}
	if ownerID <= 0 {
		return errors.New("owner telegram id is required")
	}
	rec := botSettingsRecord{Token: token, OwnerID: ownerID, UpdatedAt: time.Now().UTC()}
	sealed, err := s.sealJSON(bucketMeta, metaBotSettings, rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaBotSettings, sealed)
	})
}

func (s *orchStore) botSettings() (botSettingsRecord, bool, error) {
	var rec botSettingsRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaBotSettings)
		if raw == nil {
			return nil
		}
		return s.openJSON(bucketMeta, metaBotSettings, raw, &rec)
	})
	if err != nil {
		return botSettingsRecord{}, false, err
	}
	if strings.TrimSpace(rec.Token) == "" || rec.OwnerID <= 0 {
		return botSettingsRecord{}, false, nil
	}
	return rec, true, nil
}

func (s *orchStore) getBotProblemState() (botProblemState, bool, error) {
	var rec botProblemState
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaBotProblems)
		if raw == nil {
			return nil
		}
		return s.openJSON(bucketMeta, metaBotProblems, raw, &rec)
	})
	if err != nil {
		return botProblemState{}, false, err
	}
	if rec.Version == 0 {
		return botProblemState{}, false, nil
	}
	return rec, true, nil
}

func (s *orchStore) putBotProblemState(rec botProblemState) error {
	rec.Version = 1
	rec.UpdatedAt = rec.UpdatedAt.UTC()
	sealed, err := s.sealJSON(bucketMeta, metaBotProblems, rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaBotProblems, sealed)
	})
}

func (s *orchStore) botPendingWorkerNotified(workerID string) (bool, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return false, nil
	}
	key := []byte("bot_pending_worker_notified:" + workerID)
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(bucketMeta).Get(key) != nil
		return nil
	})
	return found, err
}

func (s *orchStore) markBotPendingWorkerNotified(workerID string) error {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil
	}
	key := []byte("bot_pending_worker_notified:" + workerID)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(key, []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	})
}

func (s *orchStore) createToken(id, secret string, ttl time.Duration, maxUses int, workerStaticPub string) error {
	hash, err := protocol.HashSecret(secret)
	if err != nil {
		return err
	}
	rec := tokenRecord{
		ID:              strings.TrimSpace(id),
		Hash:            hash,
		Lookup:          s.tokenLookup(secret),
		ExpiresAt:       time.Now().UTC().Add(ttl),
		MaxUses:         maxUses,
		CreatedAt:       time.Now().UTC(),
		WorkerStaticPub: strings.TrimSpace(workerStaticPub),
	}
	if rec.ID == "" {
		return errors.New("token id is required")
	}
	raw, _ := json.Marshal(rec)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Put([]byte(rec.ID), raw)
	})
}

func (s *orchStore) createBootstrapToken(secret string, expiresAt time.Time, limits json.RawMessage, seedWorkers []string) (tokenRecord, error) {
	hash, err := protocol.HashSecret(secret)
	if err != nil {
		return tokenRecord{}, err
	}
	rec := tokenRecord{
		ID:          randID(),
		Hash:        hash,
		Lookup:      s.tokenLookup(secret),
		Kind:        "bootstrap",
		ExpiresAt:   expiresAt.UTC(),
		MaxUses:     1,
		CreatedAt:   time.Now().UTC(),
		Limits:      copyRawJSON(limits),
		SeedWorkers: append([]string(nil), seedWorkers...),
	}
	if !time.Now().UTC().Before(rec.ExpiresAt) {
		return tokenRecord{}, errors.New("bootstrap token expiry must be in the future")
	}
	raw, _ := json.Marshal(rec)
	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Put([]byte(rec.ID), raw)
	})
	return rec, err
}

func (s *orchStore) consumeToken(secret string, workerStaticPub string) (string, error) {
	now := time.Now().UTC()
	workerStaticPub = strings.TrimSpace(workerStaticPub)

	matched, err := s.findTokenID(secret, workerStaticPub, now)
	if err != nil {
		return "", err
	}
	if matched == "" {
		return "", errors.New("invalid or exhausted enroll token")
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		raw := b.Get([]byte(matched))
		if raw == nil {
			return errors.New("invalid or exhausted enroll token")
		}
		var rec tokenRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if !tokenRecordConsumable(rec, now, workerStaticPub) {
			return errors.New("invalid or exhausted enroll token")
		}
		rec.Uses++
		raw, _ = json.Marshal(rec)
		return b.Put([]byte(rec.ID), raw)
	})
	if err != nil {
		return "", err
	}
	return matched, nil
}

func (s *orchStore) consumeBootstrapToken(secret string, device deviceRecord, profiles []awgProfile) (tokenRecord, deviceRecord, error) {
	now := time.Now().UTC()
	var matched tokenRecord
	matchedID, err := s.findBootstrapTokenID(secret, now)
	if err != nil {
		return tokenRecord{}, deviceRecord{}, err
	}
	if matchedID == "" {
		return tokenRecord{}, deviceRecord{}, errors.New("invalid, expired, or exhausted bootstrap token")
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		tb := tx.Bucket(bucketTokens)
		db := tx.Bucket(bucketDevices)
		// Re-check inside the write tx: a concurrent enroll of the same
		// identity would otherwise overwrite the first device record (new
		// PSK/IP) and burn both tokens. Aborting here keeps this token.
		if db.Get([]byte(device.ID)) != nil {
			return errors.New("device already enrolled; retry enrollment")
		}
		raw := tb.Get([]byte(matchedID))
		if raw == nil {
			return errors.New("invalid, expired, or exhausted bootstrap token")
		}
		var rec tokenRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.Kind != "bootstrap" || !now.Before(rec.ExpiresAt) || rec.Uses >= rec.MaxUses {
			return errors.New("invalid, expired, or exhausted bootstrap token")
		}
		rec.Uses++
		raw, _ = json.Marshal(rec)
		if err := tb.Put([]byte(rec.ID), raw); err != nil {
			return err
		}
		device.Status = "approved"
		device.BootstrapToken = rec.ID
		limits, err := parseDeviceLimitsRaw(rec.Limits)
		if err != nil {
			return err
		}
		device.Limits = limits
		device.CreatedAt = now
		if device.RealityUUID == "" {
			device.RealityUUID = uuidV4()
		}
		if device.InternalIP == "" {
			ip, err := s.allocateDeviceIP(tx, baseAWGSubnet(profiles))
			if err != nil {
				return err
			}
			device.InternalIP = ip
		}
		if device.PSK2 == "" {
			psk, err := randomBase64Key()
			if err != nil {
				return err
			}
			device.PSK2 = psk
		}
		if device.ConfigSeq < 1 {
			device.ConfigSeq = 1
		}
		if err := s.ensureDeviceAWGProfilesTx(tx, &device, profiles, device.AWGPublicKey); err != nil {
			return err
		}
		sealed, err := s.sealJSON(bucketDevices, []byte(device.ID), device)
		if err != nil {
			return err
		}
		if err := db.Put([]byte(device.ID), sealed); err != nil {
			return err
		}
		if err := s.bumpWorkerSeqsTx(tx); err != nil {
			return err
		}
		matched = rec
		return nil
	})
	if err != nil {
		return tokenRecord{}, deviceRecord{}, err
	}
	if matched.ID == "" {
		return tokenRecord{}, deviceRecord{}, errors.New("invalid, expired, or exhausted bootstrap token")
	}
	return matched, device, nil
}

func (s *orchStore) findTokenID(secret, workerStaticPub string, now time.Time) (string, error) {
	return s.findTokenIDMatching(secret, func(rec tokenRecord) bool {
		return tokenRecordConsumable(rec, now, workerStaticPub)
	})
}

func (s *orchStore) findBootstrapTokenID(secret string, now time.Time) (string, error) {
	return s.findTokenIDMatching(secret, func(rec tokenRecord) bool {
		return rec.Kind == "bootstrap" && now.Before(rec.ExpiresAt) && rec.Uses < rec.MaxUses
	})
}

// findTokenIDMatching locates a usable token by its keyed lookup HMAC inside a
// short read transaction and runs the expensive PBKDF2 verification outside
// it, so unauthenticated guesses cost one hash instead of one per token and
// never hold a bbolt read transaction open.
func (s *orchStore) findTokenIDMatching(secret string, usable func(tokenRecord) bool) (string, error) {
	if secret == "" {
		return "", nil
	}
	lookup := s.tokenLookup(secret)
	var exact *tokenRecord
	var legacy []tokenRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			if exact != nil {
				return nil
			}
			var rec tokenRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if !usable(rec) {
				return nil
			}
			rec.ID = string(k)
			if rec.Lookup == "" {
				legacy = append(legacy, rec)
				return nil
			}
			if hmac.Equal([]byte(rec.Lookup), []byte(lookup)) {
				exact = &rec
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	if exact != nil {
		if protocol.VerifySecret(exact.Hash, secret) {
			return exact.ID, nil
		}
		return "", nil
	}
	for _, rec := range legacy {
		if protocol.VerifySecret(rec.Hash, secret) {
			return rec.ID, nil
		}
	}
	return "", nil
}

func deriveTokenLookupKey(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("TrafficWrapper token lookup v1"))
	return mac.Sum(nil)
}

func (s *orchStore) tokenLookup(secret string) string {
	mac := hmac.New(sha256.New, s.tokenLookupKey)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// tokenRetentionAfterUse keeps spent or expired tokens briefly for audit and
// troubleshooting before pruneDeadTokens drops them; every live token is
// scanned on each enroll attempt, so dead ones must not pile up forever.
const tokenRetentionAfterUse = 7 * 24 * time.Hour

func (s *orchStore) pruneDeadTokens(now time.Time) (int, error) {
	var dead [][]byte
	// Scan read-only: the janitor runs every 30s and an empty write
	// transaction still costs an fsync.
	if err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			var rec tokenRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil
			}
			expiredLongAgo := now.Sub(rec.ExpiresAt) > tokenRetentionAfterUse
			exhaustedLongAgo := rec.MaxUses > 0 && rec.Uses >= rec.MaxUses && now.Sub(rec.CreatedAt) > tokenRetentionAfterUse
			if expiredLongAgo || exhaustedLongAgo {
				dead = append(dead, append([]byte(nil), k...))
			}
			return nil
		})
	}); err != nil || len(dead) == 0 {
		return 0, err
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return len(dead), err
}

func tokenRecordConsumable(rec tokenRecord, now time.Time, workerStaticPub string) bool {
	if rec.Kind == "bootstrap" || !now.Before(rec.ExpiresAt) || rec.Uses >= rec.MaxUses {
		return false
	}
	pinned := strings.TrimSpace(rec.WorkerStaticPub)
	return pinned == "" || pinned == strings.TrimSpace(workerStaticPub)
}

func (s *orchStore) ensureDeviceAWGProfiles(id string, profiles []awgProfile, awgPublic string) (deviceRecord, error) {
	var out deviceRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		before, _ := json.Marshal(rec.AWGProfiles)
		if err := s.ensureDeviceAWGProfilesTx(tx, &rec, profiles, awgPublic); err != nil {
			return err
		}
		after, _ := json.Marshal(rec.AWGProfiles)
		if string(before) == string(after) {
			out = rec
			return nil
		}
		sealed, err := s.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		if err := s.bumpWorkerSeqsTx(tx); err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

func (s *orchStore) ensureDeviceAWGProfilesTx(tx *bolt.Tx, device *deviceRecord, profiles []awgProfile, awgPublic string) error {
	awgPublic = strings.TrimSpace(awgPublic)
	if awgPublic == "" {
		awgPublic = strings.TrimSpace(device.AWGPublicKey)
	}
	if awgPublic == "" {
		return errors.New("awg public key is required")
	}
	if strings.TrimSpace(device.AWGPublicKey) == "" {
		device.AWGPublicKey = awgPublic
	} else if strings.TrimSpace(device.AWGPublicKey) != awgPublic {
		return errors.New("device awg public key mismatch")
	}
	if len(profiles) == 0 {
		profiles = []awgProfile{{Name: "awg", Subnet: "10.13.13.0/24"}}
	}
	if device.AWGProfiles == nil {
		device.AWGProfiles = map[string]deviceAWGProfile{}
	}
	for _, profile := range profiles {
		name := normalizeAWGProfileName(profile.Name)
		if name == "" {
			name = "awg"
		}
		creds := device.AWGProfiles[name]
		if name == "awg" {
			creds.AWGPublicKey = device.AWGPublicKey
			if creds.InternalIP == "" {
				creds.InternalIP = device.InternalIP
			}
			if creds.PSK2 == "" {
				creds.PSK2 = device.PSK2
			}
		}
		if strings.TrimSpace(creds.AWGPublicKey) == "" {
			creds.AWGPublicKey = awgPublic
		}
		if strings.TrimSpace(creds.AWGPublicKey) != awgPublic {
			return fmt.Errorf("device awg public key mismatch for profile %s", name)
		}
		if strings.TrimSpace(creds.InternalIP) == "" {
			ip, err := s.allocateDeviceIPForProfile(tx, name, profile.Subnet)
			if err != nil {
				return err
			}
			creds.InternalIP = ip
		}
		if strings.TrimSpace(creds.PSK2) == "" {
			psk, err := randomBase64Key()
			if err != nil {
				return err
			}
			creds.PSK2 = psk
		}
		device.AWGProfiles[name] = creds
		if name == "awg" {
			device.InternalIP = creds.InternalIP
			device.PSK2 = creds.PSK2
		}
	}
	return nil
}

func baseAWGSubnet(profiles []awgProfile) string {
	for _, profile := range profiles {
		if normalizeAWGProfileName(profile.Name) == "awg" && strings.TrimSpace(profile.Subnet) != "" {
			return profile.Subnet
		}
	}
	if len(profiles) > 0 && strings.TrimSpace(profiles[0].Subnet) != "" {
		return profiles[0].Subnet
	}
	return "10.13.13.0/24"
}

func (s *orchStore) devices() ([]deviceRecord, error) {
	var out []deviceRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).ForEach(func(k, raw []byte) error {
			var rec deviceRecord
			if err := s.openJSON(bucketDevices, k, raw, &rec); err != nil {
				return err
			}
			out = append(out, rec)
			return nil
		})
	})
	return out, err
}

func (s *orchStore) device(id string) (deviceRecord, error) {
	var rec deviceRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketDevices).Get([]byte(strings.TrimSpace(id)))
		if raw == nil {
			return errors.New("device not found")
		}
		return s.openJSON(bucketDevices, []byte(strings.TrimSpace(id)), raw, &rec)
	})
	return rec, err
}

func (s *orchStore) setDeviceLimits(id string, limits deviceLimits) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("device id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		applyDeviceLimitsChange(&rec, limits, time.Now().UTC())
		if rec.ConfigSeq < 1 {
			rec.ConfigSeq = 1
		}
		sealed, err := s.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		return s.bumpWorkerSeqsTx(tx)
	})
}

func (s *orchStore) setTelemetrySnapshot(rec telemetrySnapshotRecord) error {
	if strings.TrimSpace(rec.DeviceID) == "" {
		return errors.New("telemetry device_id is required")
	}
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}
	sealed, err := s.sealJSON(bucketTelemetry, []byte(rec.DeviceID), rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTelemetry).Put([]byte(rec.DeviceID), sealed)
	})
}

// recordTelemetry stores a device's telemetry snapshot and, when it reports a
// newer client version, the device's version, in one batched transaction.
func (s *orchStore) recordTelemetry(rec telemetrySnapshotRecord) error {
	if strings.TrimSpace(rec.DeviceID) == "" {
		return errors.New("telemetry device_id is required")
	}
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}
	sealed, err := s.sealJSON(bucketTelemetry, []byte(rec.DeviceID), rec)
	if err != nil {
		return err
	}
	version := strings.TrimSpace(rec.ClientVersion)
	return s.db.Batch(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketTelemetry).Put([]byte(rec.DeviceID), sealed); err != nil {
			return err
		}
		if version == "" {
			return nil
		}
		b := tx.Bucket(bucketDevices)
		raw := b.Get([]byte(rec.DeviceID))
		if raw == nil {
			return errors.New("device not found")
		}
		var device deviceRecord
		if err := s.openJSON(bucketDevices, []byte(rec.DeviceID), raw, &device); err != nil {
			return err
		}
		if strings.TrimSpace(device.ClientVersion) == version || clientVersionWouldRollback(device.ClientVersion, version) {
			return nil
		}
		device.ClientVersion = version
		out, err := s.sealJSON(bucketDevices, []byte(rec.DeviceID), device)
		if err != nil {
			return err
		}
		return b.Put([]byte(rec.DeviceID), out)
	})
}

func (s *orchStore) updateDeviceClientVersionFromTelemetry(id, version string) (bool, error) {
	id = strings.TrimSpace(id)
	version = strings.TrimSpace(version)
	if id == "" {
		return false, errors.New("device id is required")
	}
	if version == "" {
		return false, nil
	}
	changed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		if strings.TrimSpace(rec.ClientVersion) == version {
			return nil
		}
		if clientVersionWouldRollback(rec.ClientVersion, version) {
			return nil
		}
		rec.ClientVersion = version
		sealed, err := s.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}

func clientVersionWouldRollback(current, next string) bool {
	current = strings.TrimSpace(current)
	next = strings.TrimSpace(next)
	if next == "" {
		return current != ""
	}
	if current == "" {
		return false
	}
	if clientVersionCode(current) == 0 {
		return false
	}
	if len(clientVersionParts(current)) == 1 || len(clientVersionParts(next)) == 1 {
		// A bare version code on either side: only the code space compares.
		nextCode := clientVersionCode(next)
		return nextCode == 0 || nextCode < clientVersionCode(current)
	}
	cmp, ok := compareClientVersions(next, current)
	return !ok || cmp < 0
}

// applyDeviceLimitsChange sets new limits. A cleared limit set or a changed
// traffic quota restarts usage accounting, so the quota counts from the moment
// it is set instead of blocking immediately on lifetime usage. A device that
// was blocked automatically (quota or expiry) is restored when the new limits
// no longer trip; a manual revoke is never undone here.
func applyDeviceLimitsChange(rec *deviceRecord, limits deviceLimits, now time.Time) {
	if limits == (deviceLimits{}) || limits.TrafficQuotaBytes != rec.Limits.TrafficQuotaBytes {
		rec.UsageRxBytes = 0
		rec.UsageTxBytes = 0
	}
	rec.Limits = limits
	if rec.Status != "revoked" || !deviceAutoBlockReason(rec.BlockedReason) {
		return
	}
	if deviceLimitsExpired(rec.Limits, now) {
		return
	}
	if rec.Limits.TrafficQuotaBytes > 0 && saturatingAddUint64(rec.UsageRxBytes, rec.UsageTxBytes) >= rec.Limits.TrafficQuotaBytes {
		return
	}
	rec.Status = "approved"
	rec.BlockedReason = ""
	rec.BlockedAt = nil
}

func deviceAutoBlockReason(reason string) bool {
	switch strings.TrimSpace(reason) {
	case "traffic_quota_bytes", "expires_at":
		return true
	}
	return false
}

type deviceUsageReports struct {
	byID  map[string][]deviceUsage
	byAWG map[string]deviceUsage
}

func groupDeviceUsageReports(reports []deviceUsage) deviceUsageReports {
	out := deviceUsageReports{
		byID:  make(map[string][]deviceUsage, len(reports)),
		byAWG: make(map[string]deviceUsage, len(reports)),
	}
	for _, report := range reports {
		report.DeviceID = strings.TrimSpace(report.DeviceID)
		report.AWGPublicKey = strings.TrimSpace(report.AWGPublicKey)
		rawSource := report.Source
		report.Source = normalizeDeviceUsageSource(report.Source)
		if strings.TrimSpace(rawSource) != "" && report.Source == "" {
			continue
		}
		if report.Source != "" && report.DeviceID == "" {
			continue
		}
		if report.DeviceID != "" {
			out.byID[report.DeviceID] = append(out.byID[report.DeviceID], report)
		}
		if report.Source == "" && report.AWGPublicKey != "" {
			out.byAWG[report.AWGPublicKey] = report
		}
	}
	return out
}

// deviceAWGKeys lists every AWG public key a device may report usage under.
func deviceAWGKeys(rec deviceRecord) []string {
	keys := []string{strings.TrimSpace(rec.AWGPublicKey)}
	for _, profile := range rec.AWGProfiles {
		keys = append(keys, strings.TrimSpace(profile.AWGPublicKey))
	}
	return keys
}

// deviceBlockReason names why an approved device must be blocked now, or "".
func deviceBlockReason(rec deviceRecord, now time.Time) string {
	if rec.Status != "approved" {
		return ""
	}
	if deviceLimitsExpired(rec.Limits, now) {
		return "expires_at"
	}
	if rec.Limits.TrafficQuotaBytes > 0 && saturatingAddUint64(rec.UsageRxBytes, rec.UsageTxBytes) >= rec.Limits.TrafficQuotaBytes {
		return "traffic_quota_bytes"
	}
	return ""
}

// applyUsageToDevice folds the reports that belong to rec into its counters
// and applies quota/expiry blocking. It reports whether rec changed and
// whether it was newly blocked.
func applyUsageToDevice(rec *deviceRecord, workerID string, grouped deviceUsageReports, now time.Time) (changed, blocked bool) {
	if deviceReports := grouped.byID[rec.ID]; len(deviceReports) > 0 {
		for _, report := range deviceReports {
			changed = applyDeviceUsageReport(rec, workerID, report, now) || changed
		}
	} else if report, ok := grouped.byAWG[strings.TrimSpace(rec.AWGPublicKey)]; ok {
		changed = applyDeviceUsageReport(rec, workerID, report, now) || changed
	} else {
		for _, profile := range rec.AWGProfiles {
			if report, ok := grouped.byAWG[strings.TrimSpace(profile.AWGPublicKey)]; ok {
				changed = applyDeviceUsageReport(rec, workerID, report, now) || changed
				break
			}
		}
	}
	reason := deviceBlockReason(*rec, now)
	if reason != "" {
		rec.Status = "revoked"
		rec.BlockedReason = reason
		blockedAt := now.UTC()
		rec.BlockedAt = &blockedAt
		if rec.ConfigSeq < 1 {
			rec.ConfigSeq = 1
		}
		log.Printf("device quota block id=%s reason=%s usage_rx=%d usage_tx=%d quota=%d", rec.ID, reason, rec.UsageRxBytes, rec.UsageTxBytes, rec.Limits.TrafficQuotaBytes)
		return true, true
	}
	return changed, false
}

// applyDeviceUsageAndBlocks applies usage reports and quota/expiry blocks by
// scanning every device. It is the periodic sweep (expiry needs no report);
// acks use applyReportedDeviceUsage, which touches only reported devices.
func (s *orchStore) applyDeviceUsageAndBlocks(workerID string, reports []deviceUsage, now time.Time) (int, error) {
	grouped := groupDeviceUsageReports(reports)
	if len(grouped.byID) == 0 && len(grouped.byAWG) == 0 {
		// Periodic sweep: find devices to block read-only first so the
		// writer lock is not held across a full decrypt when there are none.
		pending := false
		if err := s.db.View(func(tx *bolt.Tx) error {
			return tx.Bucket(bucketDevices).ForEach(func(k, raw []byte) error {
				if pending {
					return nil
				}
				var rec deviceRecord
				if err := s.openJSON(bucketDevices, k, raw, &rec); err != nil {
					return err
				}
				pending = deviceBlockReason(rec, now) != ""
				return nil
			})
		}); err != nil || !pending {
			return 0, err
		}
	}
	blocked := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		n, err := s.sweepDeviceUsageTx(tx, workerID, grouped, now, nil)
		blocked = n
		return err
	})
	if err != nil {
		return 0, err
	}
	return blocked, nil
}

// sweepDeviceUsageTx scans all devices except those in skip. Updates are
// collected during ForEach and written afterwards: bbolt forbids modifying a
// bucket while iterating it.
func (s *orchStore) sweepDeviceUsageTx(tx *bolt.Tx, workerID string, grouped deviceUsageReports, now time.Time, skip map[string]bool) (int, error) {
	b := tx.Bucket(bucketDevices)
	type pendingPut struct {
		key []byte
		rec deviceRecord
	}
	var puts []pendingPut
	blocked := 0
	err := b.ForEach(func(k, raw []byte) error {
		if skip[string(k)] {
			return nil
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, k, raw, &rec); err != nil {
			return err
		}
		changed, newlyBlocked := applyUsageToDevice(&rec, workerID, grouped, now)
		if newlyBlocked {
			blocked++
		}
		if changed {
			puts = append(puts, pendingPut{key: append([]byte(nil), k...), rec: rec})
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, p := range puts {
		sealed, err := s.sealJSON(bucketDevices, p.key, p.rec)
		if err != nil {
			return 0, err
		}
		if err := b.Put(p.key, sealed); err != nil {
			return 0, err
		}
	}
	if blocked > 0 {
		if err := s.bumpWorkerSeqsTx(tx); err != nil {
			return 0, err
		}
	}
	return blocked, nil
}

// applyReportedDeviceUsage is the ack hot path: devices are loaded by id, and
// the full scan only runs when a report cannot be attributed that way (legacy
// reports keyed solely by AWG public key).
func (s *orchStore) applyReportedDeviceUsage(workerID string, reports []deviceUsage, now time.Time) (int, error) {
	blocked := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		blocked, err = s.applyReportedDeviceUsageTx(tx, workerID, reports, now)
		return err
	})
	if err != nil {
		return 0, err
	}
	return blocked, nil
}

func (s *orchStore) applyReportedDeviceUsageTx(tx *bolt.Tx, workerID string, reports []deviceUsage, now time.Time) (int, error) {
	grouped := groupDeviceUsageReports(reports)
	if len(grouped.byID) == 0 && len(grouped.byAWG) == 0 {
		return 0, nil
	}
	blocked := 0
	err := func() error {
		b := tx.Bucket(bucketDevices)
		resolved := map[string]bool{}
		coveredAWG := map[string]bool{}
		needScan := false
		for id := range grouped.byID {
			raw := b.Get([]byte(id))
			if raw == nil {
				needScan = true
				continue
			}
			var rec deviceRecord
			if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
				return err
			}
			resolved[id] = true
			for _, key := range deviceAWGKeys(rec) {
				coveredAWG[key] = true
			}
			changed, newlyBlocked := applyUsageToDevice(&rec, workerID, grouped, now)
			if newlyBlocked {
				blocked++
			}
			if changed {
				sealed, err := s.sealJSON(bucketDevices, []byte(id), rec)
				if err != nil {
					return err
				}
				if err := b.Put([]byte(id), sealed); err != nil {
					return err
				}
			}
		}
		for key := range grouped.byAWG {
			if !coveredAWG[key] {
				needScan = true
				break
			}
		}
		if needScan {
			n, err := s.sweepDeviceUsageTx(tx, workerID, grouped, now, resolved)
			if err != nil {
				return err
			}
			blocked += n
			// sweepDeviceUsageTx bumps seqs for its own blocks only.
			if n > 0 {
				return nil
			}
		}
		if blocked > 0 {
			return s.bumpWorkerSeqsTx(tx)
		}
		return nil
	}()
	if err != nil {
		return 0, err
	}
	return blocked, nil
}

func applyDeviceUsageReport(rec *deviceRecord, workerID string, report deviceUsage, now time.Time) bool {
	stateKey := deviceUsageStateKey(workerID, report)
	if stateKey == "" {
		return false
	}
	if rec.UsageCounters == nil {
		rec.UsageCounters = map[string]deviceUsageCounter{}
	}
	next := deviceUsageCounter{RxBytes: report.RxBytes, TxBytes: report.TxBytes}
	prev, ok := rec.UsageCounters[stateKey]
	if !ok {
		rec.UsageCounters[stateKey] = next
		if report.Source != "" {
			rec.UsageRxBytes = saturatingAddUint64(rec.UsageRxBytes, report.RxBytes)
			rec.UsageTxBytes = saturatingAddUint64(rec.UsageTxBytes, report.TxBytes)
		}
		updatedAt := now.UTC()
		rec.UsageUpdatedAt = &updatedAt
		return true
	}
	deltaRx := usageCounterDelta(prev.RxBytes, report.RxBytes)
	deltaTx := usageCounterDelta(prev.TxBytes, report.TxBytes)
	changed := false
	if deltaRx > 0 {
		rec.UsageRxBytes = saturatingAddUint64(rec.UsageRxBytes, deltaRx)
		changed = true
	}
	if deltaTx > 0 {
		rec.UsageTxBytes = saturatingAddUint64(rec.UsageTxBytes, deltaTx)
		changed = true
	}
	if prev != next {
		rec.UsageCounters[stateKey] = next
		changed = true
	}
	if changed {
		updatedAt := now.UTC()
		rec.UsageUpdatedAt = &updatedAt
	}
	return changed
}

func deviceUsageStateKey(workerID string, report deviceUsage) string {
	if source := normalizeDeviceUsageSource(report.Source); source != "" {
		deviceID := strings.TrimSpace(report.DeviceID)
		if deviceID == "" {
			return ""
		}
		workerID = strings.TrimSpace(workerID)
		if workerID == "" {
			workerID = "unknown-worker"
		}
		return workerID + "\x00" + source + "\x00" + deviceID
	}
	key := strings.TrimSpace(report.AWGPublicKey)
	if key == "" {
		key = strings.TrimSpace(report.DeviceID)
	}
	if key == "" {
		return ""
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		workerID = "unknown-worker"
	}
	return workerID + "\x00" + key
}

func normalizeDeviceUsageSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "reality":
		return "reality"
	default:
		return ""
	}
}

func usageCounterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func saturatingAddUint64(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

func (s *orchStore) telemetrySnapshots() (map[string]telemetrySnapshotRecord, error) {
	out := map[string]telemetrySnapshotRecord{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTelemetry).ForEach(func(k, raw []byte) error {
			var rec telemetrySnapshotRecord
			if err := s.openJSON(bucketTelemetry, k, raw, &rec); err != nil {
				return err
			}
			out[string(k)] = rec
			return nil
		})
	})
	return out, err
}

// approvedDevices returns approved, fully provisioned devices for worker
// config. Every pull needs it and a seq bump sends all workers to pull at
// once, so the decrypted list is cached per device-config revision: the
// devices bucket sequence, advanced by bumpWorkerSeqsTx in the same
// transaction as any config change and read here in the same snapshot as the
// data. Usage counters and client versions (not part of worker config) do not
// advance it and may be stale in the result. Treat records as read-only.
func (s *orchStore) approvedDevices() ([]deviceRecord, error) {
	var out []deviceRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		rev := tx.Bucket(bucketDevices).Sequence()
		s.approvedCacheMu.Lock()
		if s.approvedCacheSet && s.approvedCacheRev == rev {
			out = append([]deviceRecord(nil), s.approvedCache...)
			s.approvedCacheMu.Unlock()
			return nil
		}
		s.approvedCacheMu.Unlock()
		fresh := []deviceRecord{}
		if err := tx.Bucket(bucketDevices).ForEach(func(k, raw []byte) error {
			var device deviceRecord
			if err := s.openJSON(bucketDevices, k, raw, &device); err != nil {
				return err
			}
			if device.Status == "approved" &&
				strings.TrimSpace(device.RealityUUID) != "" &&
				strings.TrimSpace(device.AWGPublicKey) != "" &&
				strings.TrimSpace(device.InternalIP) != "" {
				fresh = append(fresh, device)
			}
			return nil
		}); err != nil {
			return err
		}
		s.approvedCacheMu.Lock()
		if !s.approvedCacheSet || rev >= s.approvedCacheRev {
			s.approvedCacheRev = rev
			s.approvedCache = fresh
			s.approvedCacheSet = true
		}
		s.approvedCacheMu.Unlock()
		out = append([]deviceRecord(nil), fresh...)
		return nil
	})
	return out, err
}

func (s *orchStore) revokeDevice(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		db := tx.Bucket(bucketDevices)
		raw := db.Get([]byte(strings.TrimSpace(id)))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(strings.TrimSpace(id)), raw, &rec); err != nil {
			return err
		}
		rec.Status = "revoked"
		// A manual revoke overrides any automatic block so that later limit
		// changes cannot silently restore the device.
		rec.BlockedReason = "manual"
		now := time.Now().UTC()
		rec.BlockedAt = &now
		sealed, err := s.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := db.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		return s.bumpWorkerSeqsTx(tx)
	})
}

func (s *orchStore) setDeviceAlias(id, alias string) (deviceRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return deviceRecord{}, errors.New("device id is required")
	}
	alias, err := sanitizeDeviceAlias(alias)
	if err != nil {
		return deviceRecord{}, err
	}
	var out deviceRecord
	err = s.db.Update(func(tx *bolt.Tx) error {
		db := tx.Bucket(bucketDevices)
		raw := db.Get([]byte(id))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		rec.Alias = alias
		sealed, err := s.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := db.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

func sanitizeDeviceAlias(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	var b strings.Builder
	count := 0
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		count++
		if count > 64 {
			return "", errors.New("alias must be 64 characters or less")
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String()), nil
}

func (s *orchStore) deleteDevice(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("device id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		db := tx.Bucket(bucketDevices)
		raw := db.Get([]byte(id))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		needsRevoke := rec.Status != "revoked"
		if err := db.Delete([]byte(rec.ID)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketTelemetry).Delete([]byte(rec.ID)); err != nil {
			return err
		}
		if needsRevoke {
			return s.bumpWorkerSeqsTx(tx)
		}
		return nil
	})
}

func (s *orchStore) upsertPendingWorker(staticPub string, self map[string]any) (workerRecord, error) {
	id := workerID(staticPub)
	var rec workerRecord
	changed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		var before [sha256.Size]byte
		if raw := b.Get([]byte(id)); raw != nil {
			if err := s.openJSON(bucketWorkers, []byte(id), raw, &rec); err != nil {
				return err
			}
			before = workerDiscoveryFingerprint(rec, time.Now().UTC())
			rec.SelfDescribe = self
		} else {
			rec = workerRecord{
				ID:              id,
				Status:          "pending",
				StaticPublicKey: staticPub,
				SelfDescribe:    self,
				CreatedAt:       time.Now().UTC(),
			}
		}
		sealed, err := s.sealJSON(bucketWorkers, []byte(id), rec)
		if err != nil {
			return err
		}
		changed = before != workerDiscoveryFingerprint(rec, time.Now().UTC())
		return b.Put([]byte(id), sealed)
	})
	if err == nil && changed {
		s.touchDiscoveryWorkerRevision()
	}
	return rec, err
}

func (s *orchStore) approveWorker(id string) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		if rec.Status == "pending" || rec.Status == "approved" || rec.Status == "active" {
			now := time.Now().UTC()
			rec.Status = "approved"
			rec.ApprovedAt = &now
			if rec.DesiredSeq < 1 {
				rec.DesiredSeq = 1
			}
			return nil
		}
		return fmt.Errorf("cannot approve status %q", rec.Status)
	})
}

type workerPolicyPatch struct {
	Enabled   *bool
	Priority  *int
	Weight    *int
	Protocols map[string]*bool
}

func (s *orchStore) updateWorkerPolicy(id string, patch workerPolicyPatch) error {
	changed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		raw := b.Get([]byte(strings.TrimSpace(id)))
		if raw == nil {
			return errors.New("worker not found")
		}
		var rec workerRecord
		if err := s.openJSON(bucketWorkers, []byte(strings.TrimSpace(id)), raw, &rec); err != nil {
			return err
		}
		before := workerDiscoveryFingerprint(rec, time.Now().UTC())
		if patch.Enabled != nil {
			rec.Disabled = !*patch.Enabled
		}
		if patch.Priority != nil {
			value := *patch.Priority
			if value < 0 {
				return errors.New("priority must be >= 0")
			}
			rec.ConfigPriority = &value
		}
		if patch.Weight != nil {
			value := *patch.Weight
			if value < 0 || value > 100 {
				return errors.New("weight must be 0..100")
			}
			rec.ConfigWeight = &value
		}
		if len(patch.Protocols) > 0 {
			if rec.ProtocolEnabled == nil {
				rec.ProtocolEnabled = map[string]bool{}
			}
			for key, enabled := range patch.Protocols {
				normalized := normalizeProtocolName(key)
				if normalized == "" {
					return fmt.Errorf("unsupported protocol %q", key)
				}
				if enabled == nil {
					delete(rec.ProtocolEnabled, normalized)
				} else {
					rec.ProtocolEnabled[normalized] = *enabled
				}
			}
		}
		sealed, err := s.sealJSON(bucketWorkers, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		changed = before != workerDiscoveryFingerprint(rec, time.Now().UTC())
		return s.bumpWorkerSeqsTx(tx)
	})
	if err == nil && changed {
		s.touchDiscoveryWorkerRevision()
	}
	return err
}

func (s *orchStore) currentAPKRelease() (apkReleaseRecord, bool, error) {
	var rec apkReleaseRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaAPKRelease)
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &rec)
	})
	if err != nil {
		return apkReleaseRecord{}, false, err
	}
	return rec, rec.Seq > 0, nil
}

func (s *orchStore) nextAPKSeq() (int64, error) {
	rec, ok, err := s.currentAPKRelease()
	if err != nil {
		return 0, err
	}
	if !ok {
		return 1, nil
	}
	return rec.Seq + 1, nil
}

func (s *orchStore) setAPKRelease(rec apkReleaseRecord) error {
	if rec.Seq <= 0 {
		return errors.New("apk seq must be positive")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if raw := meta.Get(metaAPKRelease); raw != nil {
			var current apkReleaseRecord
			if err := json.Unmarshal(raw, &current); err != nil {
				return err
			}
			if rec.Seq <= current.Seq {
				return fmt.Errorf("apk release rollback: seq=%d current=%d", rec.Seq, current.Seq)
			}
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := meta.Put(metaAPKRelease, raw); err != nil {
			return err
		}
		return s.bumpWorkerSeqsTx(tx)
	})
}

func (s *orchStore) worker(id string) (workerRecord, error) {
	var rec workerRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketWorkers).Get([]byte(id))
		if raw == nil {
			return errors.New("worker not found")
		}
		return s.openJSON(bucketWorkers, []byte(id), raw, &rec)
	})
	return rec, err
}

func (s *orchStore) workers() ([]workerRecord, error) {
	var out []workerRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketWorkers).ForEach(func(k, raw []byte) error {
			var rec workerRecord
			if err := s.openJSON(bucketWorkers, k, raw, &rec); err != nil {
				return err
			}
			out = append(out, rec)
			return nil
		})
	})
	return out, err
}

func (s *orchStore) updateAck(id string, applied int64, observed string, self map[string]any) error {
	return s.updateAckWithProbe(id, applied, observed, self, nil)
}

// updateAckWithProbe records an ack and, when probe is non-nil, the egress
// probe result (possibly empty) in one write transaction.
// recordAck stores a worker ack (and egress probe) together with the usage it
// reports in one batched write transaction, returning the worker's desired
// seq and the number of devices newly blocked by quota.
func (s *orchStore) recordAck(id string, applied int64, observed string, self map[string]any, probe *string, usage []deviceUsage, now time.Time) (int64, int, error) {
	var desired int64
	var blocked int
	var discoveryChanged bool
	err := s.db.Batch(func(tx *bolt.Tx) error {
		rec, changed, err := s.mutateWorkerTx(tx, id, func(rec *workerRecord) (bool, error) {
			applyAck(rec, applied, observed, self, probe)
			return true, nil
		})
		if err != nil {
			return err
		}
		n, err := s.applyReportedDeviceUsageTx(tx, id, usage, now)
		if err != nil {
			return err
		}
		// Usage may bump every worker's seq; report the post-bump value.
		if n > 0 {
			var bumped workerRecord
			if raw := tx.Bucket(bucketWorkers).Get([]byte(id)); raw != nil {
				if err := s.openJSON(bucketWorkers, []byte(id), raw, &bumped); err != nil {
					return err
				}
				rec = bumped
			}
		}
		// Batch may re-run this function: assign, never accumulate.
		desired, blocked, discoveryChanged = rec.DesiredSeq, n, changed
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if discoveryChanged {
		s.touchDiscoveryWorkerRevision()
	}
	return desired, blocked, nil
}

func (s *orchStore) updateAckWithProbe(id string, applied int64, observed string, self map[string]any, probe *string) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		applyAck(rec, applied, observed, self, probe)
		return nil
	})
}

func applyAck(rec *workerRecord, applied int64, observed string, self map[string]any, probe *string) {
	{
		if probe != nil {
			rec.EgressIPProbe = *probe
		}
		now := time.Now().UTC()
		rec.AppliedSeq = applied
		rec.LastAckAt = &now
		if rec.APKSentSeq > 0 && applied >= rec.APKSentAtSeq {
			rec.APKAppliedSeq = rec.APKSentSeq
		}
		rec.EgressIPObserved = observed
		if len(self) > 0 {
			rec.SelfDescribe = self
		}
		wasInactive := rec.Status == "inactive"
		if (rec.Status == "approved" || rec.Status == "inactive") && rec.DesiredSeq == applied {
			rec.Status = "active"
			if wasInactive {
				forceWorkerResync(rec, applied)
			}
		}
	}
}

func workerStale(rec workerRecord, cutoff time.Time) bool {
	if rec.Status != "approved" && rec.Status != "active" {
		return false
	}
	lastSeen := rec.CreatedAt
	if rec.ApprovedAt != nil {
		lastSeen = *rec.ApprovedAt
	}
	if rec.LastAckAt != nil {
		lastSeen = *rec.LastAckAt
	}
	return !lastSeen.After(cutoff)
}

func (s *orchStore) markStaleWorkersInactive(cutoff time.Time) (int, error) {
	any := false
	if err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketWorkers).ForEach(func(k, raw []byte) error {
			var rec workerRecord
			if err := s.openJSON(bucketWorkers, k, raw, &rec); err != nil {
				return err
			}
			any = any || workerStale(rec, cutoff)
			return nil
		})
	}); err != nil || !any {
		return 0, err
	}
	updated := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		return rewriteBucket(tx.Bucket(bucketWorkers), func(k, raw []byte) ([]byte, error) {
			var rec workerRecord
			if err := s.openJSON(bucketWorkers, k, raw, &rec); err != nil {
				return nil, err
			}
			if !workerStale(rec, cutoff) {
				return nil, nil
			}
			rec.Status = "inactive"
			updated++
			return s.sealJSON(bucketWorkers, k, rec)
		})
	})
	if err == nil && updated > 0 {
		s.touchDiscoveryWorkerRevision()
	}
	return updated, err
}

func (s *orchStore) updateWorkerSelfDescribe(id string, self map[string]any) error {
	if len(self) == 0 {
		return nil
	}
	return s.updateWorker(id, func(rec *workerRecord) error {
		rec.SelfDescribe = self
		return nil
	})
}

// heartbeatWriteInterval lets a nudge skip rewriting the worker record when
// only LastAckAt would move; it is well inside workerFreshTTL.
const heartbeatWriteInterval = 45 * time.Second

func (s *orchStore) updateWorkerHeartbeat(id string, haveSeq int64, self map[string]any) error {
	// Decide in a read transaction first: bbolt commits (and fsyncs) every
	// write transaction even when nothing was Put.
	needed := true
	if err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketWorkers).Get([]byte(id))
		if raw == nil {
			return errors.New("worker not found")
		}
		var rec workerRecord
		if err := s.openJSON(bucketWorkers, []byte(id), raw, &rec); err != nil {
			return err
		}
		needed = applyHeartbeat(&rec, haveSeq, self, time.Now().UTC())
		return nil
	}); err != nil {
		return err
	}
	if !needed {
		return nil
	}
	changed := false
	err := s.db.Batch(func(tx *bolt.Tx) error {
		var err error
		_, changed, err = s.mutateWorkerTx(tx, id, func(rec *workerRecord) (bool, error) {
			return applyHeartbeat(rec, haveSeq, self, time.Now().UTC()), nil
		})
		return err
	})
	if err == nil && changed {
		s.touchDiscoveryWorkerRevision()
	}
	return err
}

// applyHeartbeat updates rec for a nudge and reports whether it must be
// stored: a status or self-description change, or LastAckAt older than
// heartbeatWriteInterval.
func applyHeartbeat(rec *workerRecord, haveSeq int64, self map[string]any, now time.Time) bool {
	beforeStatus := rec.Status
	selfChanged := len(self) > 0 && !reflect.DeepEqual(rec.SelfDescribe, self)
	if len(self) > 0 {
		rec.SelfDescribe = self
	}
	wasInactive := rec.Status == "inactive"
	if (rec.Status == "approved" || rec.Status == "inactive") && rec.DesiredSeq <= haveSeq {
		rec.Status = "active"
		if wasInactive {
			forceWorkerResync(rec, haveSeq)
		}
	}
	recent := rec.LastAckAt != nil && now.Sub(*rec.LastAckAt) < heartbeatWriteInterval
	if recent && !selfChanged && rec.Status == beforeStatus {
		return false
	}
	rec.LastAckAt = &now
	return true
}

func forceWorkerResync(rec *workerRecord, haveSeq int64) {
	// A resync may follow lost worker state; ship the APK again with it. The
	// sent markers are cleared too, or a stale ack could re-mark it applied.
	rec.APKAppliedSeq = 0
	rec.APKSentSeq = 0
	rec.APKSentAtSeq = 0
	target := rec.DesiredSeq
	if rec.AppliedSeq > target {
		target = rec.AppliedSeq
	}
	if haveSeq > target {
		target = haveSeq
	}
	if target < 0 {
		target = 0
	}
	const maxInt64 = int64(1<<63 - 1)
	if target < maxInt64 {
		target++
	}
	if target < rec.DesiredSeq {
		target = rec.DesiredSeq
	}
	if target < 1 {
		target = 1
	}
	rec.DesiredSeq = target
}

func (s *orchStore) markWorkerAPKSent(id string, apkSeq, atSeq int64) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		rec.APKSentSeq = apkSeq
		rec.APKSentAtSeq = atSeq
		return nil
	})
}

func (s *orchStore) updateWorker(id string, fn func(*workerRecord) error) error {
	changed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		_, changed, err = s.mutateWorkerTx(tx, id, func(rec *workerRecord) (bool, error) {
			return true, fn(rec)
		})
		return err
	})
	if err == nil && changed {
		s.touchDiscoveryWorkerRevision()
	}
	return err
}

// mutateWorkerTx loads worker id, applies fn and stores the record when fn
// asks for a write. It returns the resulting record and whether fields that
// feed the discovery bundle changed.
func (s *orchStore) mutateWorkerTx(tx *bolt.Tx, id string, fn func(*workerRecord) (bool, error)) (workerRecord, bool, error) {
	b := tx.Bucket(bucketWorkers)
	raw := b.Get([]byte(id))
	if raw == nil {
		return workerRecord{}, false, errors.New("worker not found")
	}
	var rec workerRecord
	if err := s.openJSON(bucketWorkers, []byte(id), raw, &rec); err != nil {
		return workerRecord{}, false, err
	}
	now := time.Now().UTC()
	before := workerDiscoveryFingerprint(rec, now)
	beforeSeq := rec.DesiredSeq
	write, err := fn(&rec)
	if err != nil || !write {
		return rec, false, err
	}
	if rec.DesiredSeq != beforeSeq {
		tx.OnCommit(s.signalWorkerSeqChange)
	}
	sealed, err := s.sealJSON(bucketWorkers, []byte(id), rec)
	if err != nil {
		return workerRecord{}, false, err
	}
	if err := b.Put([]byte(id), sealed); err != nil {
		return workerRecord{}, false, err
	}
	return rec, before != workerDiscoveryFingerprint(rec, now), nil
}

func (s *orchStore) discoveryRevision() uint64 {
	return s.discoveryWorkerRevision.Load()
}

func (s *orchStore) touchDiscoveryWorkerRevision() {
	s.discoveryWorkerRevision.Add(1)
}

func workerDiscoveryFingerprint(rec workerRecord, now time.Time) [sha256.Size]byte {
	if rec.Disabled || (rec.Status != "approved" && rec.Status != "active") || !workerFreshForClients(rec, now) {
		return [sha256.Size]byte{}
	}
	payload := struct {
		SelfDescribe    map[string]any  `json:"self_describe"`
		EgressIP        string          `json:"egress_ip"`
		ConfigPriority  *int            `json:"config_priority"`
		ConfigWeight    *int            `json:"config_weight"`
		ProtocolEnabled map[string]bool `json:"protocol_enabled"`
	}{
		SelfDescribe:    rec.SelfDescribe,
		EgressIP:        rec.EgressIPObserved,
		ConfigPriority:  rec.ConfigPriority,
		ConfigWeight:    rec.ConfigWeight,
		ProtocolEnabled: rec.ProtocolEnabled,
	}
	raw, _ := json.Marshal(payload)
	return sha256.Sum256(raw)
}

// rewriteBucket calls fn for every key and stores the non-nil values it
// returns once iteration finishes; bbolt forbids modifying a bucket from
// inside ForEach.
func rewriteBucket(b *bolt.Bucket, fn func(k, v []byte) ([]byte, error)) error {
	type pendingPut struct{ key, value []byte }
	var puts []pendingPut
	if err := b.ForEach(func(k, v []byte) error {
		next, err := fn(k, v)
		if err != nil || next == nil {
			return err
		}
		puts = append(puts, pendingPut{key: append([]byte(nil), k...), value: next})
		return nil
	}); err != nil {
		return err
	}
	for _, p := range puts {
		if err := b.Put(p.key, p.value); err != nil {
			return err
		}
	}
	return nil
}

// workerSeqChanged returns a channel closed by the next commit that changes
// any worker's DesiredSeq. Take it before reading the record you wait on.
func (s *orchStore) workerSeqChanged() <-chan struct{} {
	s.seqSignalMu.Lock()
	defer s.seqSignalMu.Unlock()
	if s.seqSignal == nil {
		s.seqSignal = make(chan struct{})
	}
	return s.seqSignal
}

func (s *orchStore) signalWorkerSeqChange() {
	s.seqSignalMu.Lock()
	defer s.seqSignalMu.Unlock()
	if s.seqSignal != nil {
		close(s.seqSignal)
	}
	s.seqSignal = make(chan struct{})
}

func (s *orchStore) bumpWorkerSeqsTx(tx *bolt.Tx) error {
	tx.OnCommit(s.signalWorkerSeqChange)
	// Every change to device config that workers must see goes through a
	// seq bump; advancing the devices bucket sequence here versions the
	// approvedDevices cache without counting usage/heartbeat writes.
	if _, err := tx.Bucket(bucketDevices).NextSequence(); err != nil {
		return err
	}
	return rewriteBucket(tx.Bucket(bucketWorkers), func(k, raw []byte) ([]byte, error) {
		var rec workerRecord
		if err := s.openJSON(bucketWorkers, k, raw, &rec); err != nil {
			return nil, err
		}
		if rec.Status != "approved" && rec.Status != "active" {
			return nil, nil
		}
		if rec.DesiredSeq < 1 {
			rec.DesiredSeq = 1
		} else {
			rec.DesiredSeq++
		}
		return s.sealJSON(bucketWorkers, k, rec)
	})
}

func (s *orchStore) allocateDeviceIP(tx *bolt.Tx, cidr string) (string, error) {
	return s.allocateDeviceIPFrom(tx, cidr, func(rec deviceRecord) string { return rec.InternalIP })
}

// deviceIPPoolReserved is the number of low host addresses kept for the
// worker gateway and infrastructure.
const deviceIPPoolReserved = 10

// allocateDeviceIPFrom returns the first free /32 in cidr (IPv4), skipping the
// reserved low addresses and the broadcast address. usedIP extracts the
// address a device already holds in this pool.
func (s *orchStore) allocateDeviceIPFrom(tx *bolt.Tx, cidr string, usedIP func(deviceRecord) string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		prefix = netip.MustParsePrefix("10.13.13.0/24")
	}
	used := map[netip.Addr]struct{}{}
	// Workers derive the gateway and smoke-test peer as the configured
	// (unmasked) address +1 and +2; never hand those out to devices.
	for a, i := prefix.Addr(), 0; i < 3 && a.IsValid(); a, i = a.Next(), i+1 {
		used[a] = struct{}{}
	}
	prefix = prefix.Masked()
	if err := tx.Bucket(bucketDevices).ForEach(func(k, raw []byte) error {
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, k, raw, &rec); err != nil {
			return err
		}
		addrText := strings.TrimSuffix(strings.TrimSpace(usedIP(rec)), "/32")
		if addr, err := netip.ParseAddr(addrText); err == nil {
			used[addr] = struct{}{}
		}
		return nil
	}); err != nil {
		return "", err
	}
	next := prefix.Addr()
	for i := 0; i < deviceIPPoolReserved; i++ {
		next = next.Next()
	}
	for ; next.IsValid() && prefix.Contains(next); next = next.Next() {
		if after := next.Next(); !after.IsValid() || !prefix.Contains(after) {
			break // broadcast address
		}
		if _, ok := used[next]; ok {
			continue
		}
		return next.String() + "/32", nil
	}
	return "", errors.New("device IP pool exhausted")
}

func (s *orchStore) allocateDeviceIPForProfile(tx *bolt.Tx, profileName, cidr string) (string, error) {
	profileName = normalizeAWGProfileName(profileName)
	if profileName == "" || profileName == "awg" {
		return s.allocateDeviceIP(tx, cidr)
	}
	return s.allocateDeviceIPFrom(tx, cidr, func(rec deviceRecord) string {
		return rec.AWGProfiles[profileName].InternalIP
	})
}

func randomBase64Key() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func uuidV4() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:])
}

func normalizeProtocolName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "reality", "reality2", "rl", "rl2":
		return "reality"
	case "awg", "awg_ru", "awgru":
		return "awg"
	default:
		return ""
	}
}

// Sealed record format. v2 binds each ciphertext to its location by passing
// "bucket\x00key" as AEAD associated data, so a record copied or swapped to
// another key or bucket fails to decrypt. Legacy records (no prefix, no AD)
// remain readable and are rewritten by migrateSealedRecords.
const sealedRecordV2Prefix = "v2."

func sealedRecordAD(bucket, key []byte) []byte {
	ad := make([]byte, 0, len(bucket)+1+len(key))
	ad = append(ad, bucket...)
	ad = append(ad, 0)
	return append(ad, key...)
}

func (s *orchStore) sealJSON(bucket, key []byte, v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return s.sealBytes(bucket, key, plain)
}

func (s *orchStore) sealBytes(bucket, key, plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := s.aead.Seal(nil, nonce, plain, sealedRecordAD(bucket, key))
	return []byte(sealedRecordV2Prefix + base64.RawStdEncoding.EncodeToString(nonce) + "." + base64.RawStdEncoding.EncodeToString(ciphertext)), nil
}

func (s *orchStore) openJSON(bucket, key, raw []byte, v any) error {
	plain, err := s.openSealed(bucket, key, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// migrateSealedRecords rewrites legacy sealed records (no associated data)
// into the bound v2 format. Values that are not legacy ciphertexts (v2
// records, plain JSON such as tokens or the APK release) are left untouched.
func (s *orchStore) migrateSealedRecords() (int, error) {
	migrated := 0
	done := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		// Once every record is bound, never accept (and rebind) legacy
		// ciphertexts again: one planted from an old backup while the service
		// was stopped would otherwise be re-sealed under the wrong key.
		if tx.Bucket(bucketMeta).Get(metaSealedFormat) != nil {
			done = true
			return nil
		}
		for _, name := range [][]byte{bucketWorkers, bucketDevices, bucketTelemetry, bucketMeta} {
			err := rewriteBucket(tx.Bucket(name), func(k, v []byte) ([]byte, error) {
				if strings.HasPrefix(string(v), sealedRecordV2Prefix) {
					return nil, nil
				}
				plain, err := s.openSealed(name, k, v)
				if err != nil {
					return nil, nil
				}
				migrated++
				return s.sealBytes(name, k, plain)
			})
			if err != nil {
				return err
			}
		}
		return tx.Bucket(bucketMeta).Put(metaSealedFormat, []byte("2"))
	})
	if err == nil || done {
		s.rejectLegacySealed.Store(true)
	}
	return migrated, err
}

// openSealed decrypts a v2 record bound to bucket/key, or a legacy record.
func (s *orchStore) openSealed(bucket, key, raw []byte) ([]byte, error) {
	text := string(raw)
	var ad []byte
	if rest, ok := strings.CutPrefix(text, sealedRecordV2Prefix); ok {
		text = rest
		ad = sealedRecordAD(bucket, key)
	} else if s.rejectLegacySealed.Load() {
		return nil, errors.New("unbound legacy sealed record rejected")
	}
	nonceText, ciphertextText, ok := strings.Cut(text, ".")
	if !ok {
		return nil, errors.New("bad sealed record")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(nonceText)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(ciphertextText)
	if err != nil {
		return nil, err
	}
	if len(nonce) != s.aead.NonceSize() {
		return nil, errors.New("bad sealed record nonce")
	}
	return s.aead.Open(nil, nonce, ciphertext, ad)
}
