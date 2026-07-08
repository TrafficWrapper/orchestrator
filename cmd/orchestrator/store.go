package main

import (
	"crypto/aes"
	"crypto/cipher"
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
	"strings"
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
)

type orchStore struct {
	db   *bolt.DB
	aead cipher.AEAD
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
}

type adminTOTPRecord struct {
	Secret      string    `json:"secret"`
	Enabled     bool      `json:"enabled"`
	LastCounter int64     `json:"last_counter"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	s := &orchStore{db: db, aead: aead}
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
	sealed, err := s.sealJSON(rec)
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
		return s.openJSON(raw, &rec)
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
		return s.openJSON(raw, &rec)
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
	rec := adminTOTPRecord{Secret: secret, Enabled: false, UpdatedAt: time.Now().UTC()}
	return rec, s.putAdminTOTPLocked(rec)
}

func (s *orchStore) enableAdminTOTP(code string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var rec adminTOTPRecord
		raw := tx.Bucket(bucketMeta).Get(metaAdminTOTP)
		if raw == nil {
			return errors.New("totp enrollment is not started")
		}
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		counter, ok := verifyTOTPCode(rec.Secret, code, now, rec.LastCounter)
		if !ok {
			return errors.New("invalid totp code")
		}
		rec.Enabled = true
		rec.LastCounter = counter
		rec.UpdatedAt = now.UTC()
		sealed, err := s.sealJSON(rec)
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
		if err := s.openJSON(raw, &rec); err != nil {
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
		sealed, err := s.sealJSON(rec)
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

func (s *orchStore) putAdminTOTPLocked(rec adminTOTPRecord) error {
	sealed, err := s.sealJSON(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaAdminTOTP, sealed)
	})
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
	sealed, err := s.sealJSON(rec)
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
		return s.openJSON(raw, &rec)
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
		return s.openJSON(raw, &rec)
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
	sealed, err := s.sealJSON(rec)
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
		sealed, err := s.sealJSON(device)
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
	var matched string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			if matched != "" {
				return nil
			}
			var rec tokenRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if !tokenRecordConsumable(rec, now, workerStaticPub) {
				return nil
			}
			if protocol.VerifySecret(rec.Hash, secret) {
				matched = string(k)
			}
			return nil
		})
	})
	return matched, err
}

func (s *orchStore) findBootstrapTokenID(secret string, now time.Time) (string, error) {
	var matched string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			if matched != "" {
				return nil
			}
			var rec tokenRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Kind != "bootstrap" || !now.Before(rec.ExpiresAt) || rec.Uses >= rec.MaxUses {
				return nil
			}
			if protocol.VerifySecret(rec.Hash, secret) {
				matched = string(k)
			}
			return nil
		})
	})
	return matched, err
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
		if err := s.openJSON(raw, &rec); err != nil {
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
		sealed, err := s.sealJSON(rec)
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
		return tx.Bucket(bucketDevices).ForEach(func(_, raw []byte) error {
			var rec deviceRecord
			if err := s.openJSON(raw, &rec); err != nil {
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
		return s.openJSON(raw, &rec)
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
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		rec.Limits = limits
		if rec.ConfigSeq < 1 {
			rec.ConfigSeq = 1
		}
		sealed, err := s.sealJSON(rec)
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
	sealed, err := s.sealJSON(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTelemetry).Put([]byte(rec.DeviceID), sealed)
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
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		if strings.TrimSpace(rec.ClientVersion) == version {
			return nil
		}
		if clientVersionWouldRollback(rec.ClientVersion, version) {
			return nil
		}
		rec.ClientVersion = version
		sealed, err := s.sealJSON(rec)
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
	currentCode := clientVersionCode(current)
	nextCode := clientVersionCode(next)
	if currentCode == 0 {
		return false
	}
	return nextCode == 0 || nextCode < currentCode
}

func (s *orchStore) applyDeviceUsageAndBlocks(workerID string, reports []deviceUsage, now time.Time) (int, error) {
	byID := make(map[string]deviceUsage, len(reports))
	byAWG := make(map[string]deviceUsage, len(reports))
	for _, report := range reports {
		report.DeviceID = strings.TrimSpace(report.DeviceID)
		report.AWGPublicKey = strings.TrimSpace(report.AWGPublicKey)
		if report.DeviceID != "" {
			byID[report.DeviceID] = report
		}
		if report.AWGPublicKey != "" {
			byAWG[report.AWGPublicKey] = report
		}
	}
	blocked := 0
	changedAny := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		err := b.ForEach(func(k, raw []byte) error {
			var rec deviceRecord
			if err := s.openJSON(raw, &rec); err != nil {
				return err
			}
			changed := false
			if report, ok := byID[rec.ID]; ok {
				changed = applyDeviceUsageReport(&rec, workerID, report, now) || changed
			} else if report, ok := byAWG[strings.TrimSpace(rec.AWGPublicKey)]; ok {
				changed = applyDeviceUsageReport(&rec, workerID, report, now) || changed
			} else {
				for _, profile := range rec.AWGProfiles {
					if report, ok := byAWG[strings.TrimSpace(profile.AWGPublicKey)]; ok {
						changed = applyDeviceUsageReport(&rec, workerID, report, now) || changed
						break
					}
				}
			}
			reason := ""
			if deviceLimitsExpired(rec.Limits, now) {
				reason = "expires_at"
			} else if rec.Limits.TrafficQuotaBytes > 0 && rec.UsageRxBytes+rec.UsageTxBytes >= rec.Limits.TrafficQuotaBytes {
				reason = "traffic_quota_bytes"
			}
			if reason != "" && rec.Status == "approved" {
				rec.Status = "revoked"
				rec.BlockedReason = reason
				blockedAt := now.UTC()
				rec.BlockedAt = &blockedAt
				if rec.ConfigSeq < 1 {
					rec.ConfigSeq = 1
				}
				log.Printf("device quota block id=%s reason=%s usage_rx=%d usage_tx=%d quota=%d", rec.ID, reason, rec.UsageRxBytes, rec.UsageTxBytes, rec.Limits.TrafficQuotaBytes)
				blocked++
				changed = true
			}
			if !changed {
				return nil
			}
			sealed, err := s.sealJSON(rec)
			if err != nil {
				return err
			}
			if err := b.Put(k, sealed); err != nil {
				return err
			}
			changedAny = true
			return nil
		})
		if err != nil {
			return err
		}
		if blocked > 0 {
			return s.bumpWorkerSeqsTx(tx)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if !changedAny {
		return 0, nil
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
			if err := s.openJSON(raw, &rec); err != nil {
				return err
			}
			out[string(k)] = rec
			return nil
		})
	})
	return out, err
}

func (s *orchStore) approvedDevices() ([]deviceRecord, error) {
	devices, err := s.devices()
	if err != nil {
		return nil, err
	}
	out := make([]deviceRecord, 0, len(devices))
	for _, device := range devices {
		if device.Status == "approved" &&
			strings.TrimSpace(device.RealityUUID) != "" &&
			strings.TrimSpace(device.AWGPublicKey) != "" &&
			strings.TrimSpace(device.InternalIP) != "" {
			out = append(out, device)
		}
	}
	return out, nil
}

func (s *orchStore) revokeDevice(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		db := tx.Bucket(bucketDevices)
		raw := db.Get([]byte(strings.TrimSpace(id)))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		rec.Status = "revoked"
		sealed, err := s.sealJSON(rec)
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
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		rec.Alias = alias
		sealed, err := s.sealJSON(rec)
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
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		needsRevoke := rec.Status != "revoked"
		if err := db.Delete([]byte(rec.ID)); err != nil {
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
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		if raw := b.Get([]byte(id)); raw != nil {
			if err := s.openJSON(raw, &rec); err != nil {
				return err
			}
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
		sealed, err := s.sealJSON(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), sealed)
	})
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
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		raw := b.Get([]byte(strings.TrimSpace(id)))
		if raw == nil {
			return errors.New("worker not found")
		}
		var rec workerRecord
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
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
		sealed, err := s.sealJSON(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		return s.bumpWorkerSeqsTx(tx)
	})
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
		return s.openJSON(raw, &rec)
	})
	return rec, err
}

func (s *orchStore) workers() ([]workerRecord, error) {
	var out []workerRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketWorkers).ForEach(func(_, raw []byte) error {
			var rec workerRecord
			if err := s.openJSON(raw, &rec); err != nil {
				return err
			}
			out = append(out, rec)
			return nil
		})
	})
	return out, err
}

func (s *orchStore) updateAck(id string, applied int64, observed string, self map[string]any) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		now := time.Now().UTC()
		rec.AppliedSeq = applied
		rec.LastAckAt = &now
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
		return nil
	})
}

func (s *orchStore) markStaleWorkersInactive(cutoff time.Time) (int, error) {
	updated := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		return b.ForEach(func(k, raw []byte) error {
			var rec workerRecord
			if err := s.openJSON(raw, &rec); err != nil {
				return err
			}
			if rec.Status != "approved" && rec.Status != "active" {
				return nil
			}
			lastSeen := rec.CreatedAt
			if rec.ApprovedAt != nil {
				lastSeen = *rec.ApprovedAt
			}
			if rec.LastAckAt != nil {
				lastSeen = *rec.LastAckAt
			}
			if lastSeen.After(cutoff) {
				return nil
			}
			rec.Status = "inactive"
			sealed, err := s.sealJSON(rec)
			if err != nil {
				return err
			}
			if err := b.Put(k, sealed); err != nil {
				return err
			}
			updated++
			return nil
		})
	})
	return updated, err
}

func (s *orchStore) setProbe(id, ip string) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		rec.EgressIPProbe = ip
		return nil
	})
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

func (s *orchStore) updateWorkerHeartbeat(id string, haveSeq int64, self map[string]any) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		now := time.Now().UTC()
		rec.LastAckAt = &now
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
		return nil
	})
}

func forceWorkerResync(rec *workerRecord, haveSeq int64) {
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

func (s *orchStore) updateWorker(id string, fn func(*workerRecord) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("worker not found")
		}
		var rec workerRecord
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		if err := fn(&rec); err != nil {
			return err
		}
		sealed, err := s.sealJSON(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), sealed)
	})
}

func (s *orchStore) bumpWorkerSeqsTx(tx *bolt.Tx) error {
	b := tx.Bucket(bucketWorkers)
	return b.ForEach(func(k, raw []byte) error {
		var rec workerRecord
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		if rec.Status != "approved" && rec.Status != "active" {
			return nil
		}
		if rec.DesiredSeq < 1 {
			rec.DesiredSeq = 1
		} else {
			rec.DesiredSeq++
		}
		sealed, err := s.sealJSON(rec)
		if err != nil {
			return err
		}
		return b.Put(k, sealed)
	})
}

func (s *orchStore) allocateDeviceIP(tx *bolt.Tx, cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		prefix = netip.MustParsePrefix("10.13.13.0/24")
	}
	used := map[netip.Addr]struct{}{}
	db := tx.Bucket(bucketDevices)
	if err := db.ForEach(func(_, raw []byte) error {
		var rec deviceRecord
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		addrText := strings.TrimSuffix(strings.TrimSpace(rec.InternalIP), "/32")
		if addr, err := netip.ParseAddr(addrText); err == nil {
			used[addr] = struct{}{}
		}
		return nil
	}); err != nil {
		return "", err
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", errors.New("device IP pool must be IPv4")
	}
	raw := addr.As4()
	for i := 10; i < 255; i++ {
		raw[3] = byte(i)
		next := netip.AddrFrom4(raw)
		if !prefix.Contains(next) {
			break
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
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		prefix = netip.MustParsePrefix("10.13.13.0/24")
	}
	used := map[netip.Addr]struct{}{}
	db := tx.Bucket(bucketDevices)
	if err := db.ForEach(func(_, raw []byte) error {
		var rec deviceRecord
		if err := s.openJSON(raw, &rec); err != nil {
			return err
		}
		if rec.AWGProfiles == nil {
			return nil
		}
		creds, ok := rec.AWGProfiles[profileName]
		if !ok {
			return nil
		}
		addrText := strings.TrimSuffix(strings.TrimSpace(creds.InternalIP), "/32")
		if addr, err := netip.ParseAddr(addrText); err == nil {
			used[addr] = struct{}{}
		}
		return nil
	}); err != nil {
		return "", err
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", errors.New("device IP pool must be IPv4")
	}
	raw := addr.As4()
	for i := 10; i < 255; i++ {
		raw[3] = byte(i)
		next := netip.AddrFrom4(raw)
		if !prefix.Contains(next) {
			break
		}
		if _, ok := used[next]; ok {
			continue
		}
		return next.String() + "/32", nil
	}
	return "", errors.New("device IP pool exhausted")
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

func (s *orchStore) sealJSON(v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := s.aead.Seal(nil, nonce, plain, nil)
	return []byte(base64.RawStdEncoding.EncodeToString(nonce) + "." + base64.RawStdEncoding.EncodeToString(ciphertext)), nil
}

func (s *orchStore) openJSON(raw []byte, v any) error {
	nonceText, ciphertextText, ok := strings.Cut(string(raw), ".")
	if !ok {
		return errors.New("bad sealed record")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(nonceText)
	if err != nil {
		return err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(ciphertextText)
	if err != nil {
		return err
	}
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}
