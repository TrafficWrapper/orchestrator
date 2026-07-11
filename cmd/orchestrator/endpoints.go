package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"
)

const (
	discoveryBundleCacheTTL = 30 * time.Second
	discoveryRateWindow     = time.Minute
	discoveryRateLimit      = 1200
	maxDiscoveryRateKeys    = 16 * 1024
)

type discoveryRateAsset uint8

const (
	discoveryRateAssetJSON discoveryRateAsset = iota
	discoveryRateAssetMinisig
)

type discoveryBundleCache struct {
	JSON           string
	Minisig        string
	PublicKey      string
	GeneratedAt    time.Time
	WorkerRevision uint64
}

type discoveryRequestRate struct {
	WindowStart  time.Time
	JSONCount    int
	MinisigCount int
}

func (s *server) handleDiscoveryEndpointsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.reserveDiscoveryRequest(r, discoveryRateAssetJSON) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "discovery request rate exceeded", http.StatusTooManyRequests)
		return
	}
	jsonText, _, _, err := s.signedDiscoveryBundle()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(jsonText))
}

func (s *server) handleDiscoveryEndpointsMinisig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.reserveDiscoveryRequest(r, discoveryRateAssetMinisig) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "discovery request rate exceeded", http.StatusTooManyRequests)
		return
	}
	_, minisigText, _, err := s.signedDiscoveryBundle()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(minisigText))
}

func (s *server) handleAdminDiscoveryBump(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	seq, err := s.bumpDiscoverySeq()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "seq": seq})
}

func (s *server) signedDiscoveryBundle() (string, string, string, error) {
	now := time.Now().UTC()
	revision := s.store.discoveryRevision()
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	age := now.Sub(s.discoveryCache.GeneratedAt)
	if s.discoveryCache.JSON != "" &&
		s.discoveryCache.WorkerRevision == revision &&
		age >= 0 && age < discoveryBundleCacheTTL {
		return s.discoveryCache.JSON, s.discoveryCache.Minisig, s.discoveryCache.PublicKey, nil
	}
	priv, pubText, err := s.loadServerUpdateSigningKey()
	if err != nil {
		return "", "", "", err
	}
	jsonText, err := s.discoveryBundleJSON(now)
	if err != nil {
		return "", "", "", err
	}
	minisigText := string(minisign.Sign(priv, []byte(jsonText)))
	s.discoveryCache = discoveryBundleCache{
		JSON:           jsonText,
		Minisig:        minisigText,
		PublicKey:      pubText,
		GeneratedAt:    now,
		WorkerRevision: revision,
	}
	s.discoveryBuilds.Add(1)
	return jsonText, minisigText, pubText, nil
}

func (s *server) invalidateDiscoveryCache() {
	s.discoveryCacheMu.Lock()
	s.discoveryCache = discoveryBundleCache{}
	s.discoveryCacheMu.Unlock()
}

func (s *server) reserveDiscoveryRequest(r *http.Request, asset discoveryRateAsset) bool {
	return s.reserveDiscoveryRequestForKey(rateLimitKey(clientIP(r)), asset, time.Now().UTC())
}

func (s *server) reserveDiscoveryRequestForKey(key string, asset discoveryRateAsset, now time.Time) bool {
	s.discoveryRateMu.Lock()
	defer s.discoveryRateMu.Unlock()
	if s.discoveryRates == nil {
		s.discoveryRates = make(map[string]discoveryRequestRate)
	}
	rate, exists := s.discoveryRates[key]
	if exists && now.Sub(rate.WindowStart) >= discoveryRateWindow {
		rate = discoveryRequestRate{WindowStart: now}
	}
	if !exists {
		if len(s.discoveryRates) >= maxDiscoveryRateKeys {
			for staleKey := range s.discoveryRates {
				delete(s.discoveryRates, staleKey)
				break
			}
		}
		rate = discoveryRequestRate{WindowStart: now}
	}
	switch asset {
	case discoveryRateAssetJSON:
		if rate.JSONCount >= discoveryRateLimit {
			return false
		}
		rate.JSONCount++
	case discoveryRateAssetMinisig:
		if rate.MinisigCount >= discoveryRateLimit {
			return false
		}
		rate.MinisigCount++
	default:
		return false
	}
	s.discoveryRates[key] = rate
	return true
}

func (s *server) discoveryPublicKey() string {
	_, pubText, err := s.loadServerUpdateSigningKey()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(pubText)
}

func (s *server) discoveryBundleJSON(now time.Time) (string, error) {
	workers, err := s.store.workers()
	if err != nil {
		return "", err
	}
	var awg []any
	var reality []any
	for _, rec := range workers {
		if rec.Status != "approved" && rec.Status != "active" {
			continue
		}
		if rec.Disabled || !workerFreshForClients(rec, now) {
			continue
		}
		if item, ok := discoveryAWGEndpoint(rec); ok {
			awg = append(awg, item)
		}
		if item, ok := discoveryRealityEndpoint(rec); ok {
			reality = append(reality, item)
		}
	}
	endpoints := map[string]any{
		"awg":     awg,
		"reality": reality,
	}
	nextSinks := discoveryConfiguredURLs(s.cfg.DiscoveryNextSinks)
	hashInput := map[string]any{"endpoints": endpoints}
	if len(nextSinks) > 0 {
		hashInput["next_sinks"] = nextSinks
	}
	endpointsJSON, err := canonicalJSON(hashInput)
	if err != nil {
		return "", err
	}
	seq, err := s.discoverySeqForHash(discoveryHash(endpointsJSON))
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"schema":     2,
		"ns":         "rendezvous-v1",
		"seq":        seq,
		"issued_at":  now.Format(time.RFC3339),
		"expires_at": now.Add(12 * time.Hour).Format(time.RFC3339),
		"endpoints":  endpoints,
	}
	if len(nextSinks) > 0 {
		payload["next_sinks"] = nextSinks
	}
	jsonText, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	if err := rejectForbiddenKeys([]byte(jsonText)); err != nil {
		return "", err
	}
	return jsonText, nil
}

func discoveryConfiguredURLs(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func (s *server) discoverySeq() (int64, error) {
	s.discoverySeqMu.Lock()
	defer s.discoverySeqMu.Unlock()
	return s.readDiscoverySeqLocked()
}

func (s *server) discoverySeqForHash(hash string) (int64, error) {
	s.discoverySeqMu.Lock()
	defer s.discoverySeqMu.Unlock()
	current, err := s.readDiscoverySeqLocked()
	if err != nil {
		return 0, err
	}
	if current < 1 {
		current = 1
	}
	storedHash, err := s.readDiscoveryHashLocked()
	if err != nil {
		return 0, err
	}
	next := current
	if storedHash != "" && storedHash != hash {
		next++
	}
	if storedHash != hash || next != current {
		if err := s.writeDiscoverySeqStateLocked(next, hash); err != nil {
			return 0, err
		}
	}
	return next, nil
}

func (s *server) bumpDiscoverySeq() (int64, error) {
	s.discoverySeqMu.Lock()
	next, err := func() (int64, error) {
		current, err := s.readDiscoverySeqLocked()
		if err != nil {
			return 0, err
		}
		if current < 1 {
			current = 1
		}
		next := current + 1
		hash, err := s.readDiscoveryHashLocked()
		if err != nil {
			return 0, err
		}
		if err := s.writeDiscoverySeqStateLocked(next, hash); err != nil {
			return 0, err
		}
		return next, nil
	}()
	s.discoverySeqMu.Unlock()
	if err == nil {
		s.invalidateDiscoveryCache()
	}
	return next, err
}

func (s *server) readDiscoverySeqLocked() (int64, error) {
	raw, err := os.ReadFile(s.discoverySeqPath())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, nil
	}
	return value, nil
}

func (s *server) readDiscoveryHashLocked() (string, error) {
	raw, err := os.ReadFile(s.discoveryHashPath())
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (s *server) writeDiscoverySeqStateLocked(seq int64, hash string) error {
	if err := os.MkdirAll(s.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(s.discoverySeqPath(), []byte(strconv.FormatInt(seq, 10)+"\n"), 0o600); err != nil {
		return err
	}
	if hash != "" {
		if err := os.WriteFile(s.discoveryHashPath(), []byte(hash+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) discoverySeqPath() string {
	return filepath.Join(s.cfg.StateDir, "discovery.seq")
}

func (s *server) discoveryHashPath() string {
	return filepath.Join(s.cfg.StateDir, "discovery.hash")
}

func discoveryHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func discoveryAWGEndpoint(rec workerRecord) (map[string]any, bool) {
	params, ok := rec.SelfDescribe["awg"].(map[string]any)
	if !ok {
		return nil, false
	}
	endpoint := firstStringFromMap(params, "endpoint")
	serverPublic := firstStringFromMap(params, "public_key", "server_public", "server_public_key")
	preset, ok := firstRawMapValue(params, "awg_preset", "dialect")
	if strings.TrimSpace(endpoint) == "" || strings.TrimSpace(serverPublic) == "" || !ok {
		return nil, false
	}
	out := map[string]any{
		"priority":          effectiveWorkerPriority(rec),
		"endpoint":          endpoint,
		"server_public_key": serverPublic,
		"awg_preset":        preset,
	}
	if expected := workerEgressIP(rec); expected != "" {
		out["egress_ip"] = expected
	}
	return out, true
}

func discoveryRealityEndpoint(rec workerRecord) (map[string]any, bool) {
	params, ok := rec.SelfDescribe["reality"].(map[string]any)
	if !ok || len(params) == 0 {
		return nil, false
	}
	out := canonicalClientRouteParamsForClient("reality", params, "")
	out["priority"] = effectiveWorkerPriority(rec)
	if expected := workerEgressIP(rec); expected != "" {
		out["egress_ip"] = expected
	}
	return out, true
}

func workerEgressIP(rec workerRecord) string {
	if expected := stringFromMap(rec.SelfDescribe, "egress_ip"); expected != "" {
		return expected
	}
	return strings.TrimSpace(rec.EgressIPObserved)
}

func firstRawMapValue(params map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := params[key]; ok && value != nil {
			return value, true
		}
	}
	return nil, false
}
