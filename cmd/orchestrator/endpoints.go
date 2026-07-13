package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"
)

const (
	discoveryBundleCacheTTL = 30 * time.Second
	discoveryBundleHistory  = 8
	discoveryPairTTL        = 2 * discoveryBundleCacheTTL
	discoveryRateWindow     = time.Minute
	discoveryRateLimit      = 1200
	maxDiscoveryRateKeys    = 16 * 1024
)

type discoveryBundleSnapshot struct {
	JSON           string
	Minisig        string
	PublicKey      string
	Revision       string
	GeneratedAt    time.Time
	WorkerRevision uint64
}

type discoveryBundleCache struct {
	Current     *discoveryBundleSnapshot
	History     []*discoveryBundleSnapshot
	Invalidated bool
}

type discoveryRequestRate struct {
	WindowStart     time.Time
	PairCount       int
	PendingPairs    int
	PendingUntil    time.Time
	PendingRevision string
}

func (s *server) handleDiscoveryEndpointsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := s.signedDiscoverySnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	revision, retryAfter, ok := s.reserveDiscoveryJSONForKey(
		discoveryRateKey(clientIP(r)),
		bundle.Revision,
		time.Now(),
	)
	if !ok {
		writeDiscoveryRateExceeded(w, retryAfter)
		return
	}
	if revision != bundle.Revision {
		bundle = s.cachedDiscoverySnapshot(revision)
		if bundle == nil {
			http.Error(w, "discovery revision unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	setDiscoveryBundleHeaders(w, bundle)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(bundle.JSON))
}

func (s *server) handleDiscoveryEndpointsMinisig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestedRevision := requestedDiscoveryRevision(r)
	revision, retryAfter, ok, revisionMatches := s.reserveDiscoveryMinisigForKey(
		discoveryRateKey(clientIP(r)),
		requestedRevision,
		time.Now(),
	)
	if !revisionMatches {
		http.Error(w, "discovery revision precondition failed", http.StatusPreconditionFailed)
		return
	}
	if !ok {
		writeDiscoveryRateExceeded(w, retryAfter)
		return
	}
	var bundle *discoveryBundleSnapshot
	if revision != "" {
		bundle = s.cachedDiscoverySnapshot(revision)
		if bundle == nil {
			http.Error(w, "discovery revision unavailable", http.StatusPreconditionFailed)
			return
		}
	}
	if bundle == nil {
		var err error
		bundle, err = s.signedDiscoverySnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	setDiscoveryBundleHeaders(w, bundle)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(bundle.Minisig))
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

func (s *server) signedDiscoverySnapshot() (*discoveryBundleSnapshot, error) {
	now := time.Now().UTC()
	revision := s.store.discoveryRevision()
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	current := s.discoveryCache.Current
	age := time.Duration(-1)
	if current != nil {
		age = now.Sub(current.GeneratedAt)
	}
	if current != nil && !s.discoveryCache.Invalidated &&
		current.WorkerRevision == revision &&
		age >= 0 && age < discoveryBundleCacheTTL {
		return current, nil
	}
	priv, pubText, err := s.loadServerUpdateSigningKey()
	if err != nil {
		return nil, err
	}
	jsonText, err := s.discoveryBundleJSON(now)
	if err != nil {
		return nil, err
	}
	next := &discoveryBundleSnapshot{
		JSON:           jsonText,
		Minisig:        string(minisign.Sign(priv, []byte(jsonText))),
		PublicKey:      pubText,
		Revision:       discoveryHash(jsonText),
		GeneratedAt:    now,
		WorkerRevision: revision,
	}
	s.rememberDiscoverySnapshotLocked(current)
	s.discoveryCache.Current = next
	s.discoveryCache.Invalidated = false
	s.discoveryBuilds.Add(1)
	return next, nil
}

func (s *server) signedDiscoveryBundle() (string, string, string, error) {
	bundle, err := s.signedDiscoverySnapshot()
	if err != nil {
		return "", "", "", err
	}
	return bundle.JSON, bundle.Minisig, bundle.PublicKey, nil
}

func (s *server) rememberDiscoverySnapshotLocked(bundle *discoveryBundleSnapshot) {
	if bundle == nil {
		return
	}
	for _, previous := range s.discoveryCache.History {
		if previous.Revision == bundle.Revision {
			return
		}
	}
	s.discoveryCache.History = append([]*discoveryBundleSnapshot{bundle}, s.discoveryCache.History...)
	// Pending pairs keep only a revision string; this bounded history supplies
	// the exact immutable JSON+minisig snapshot after a cache rebuild.
	if len(s.discoveryCache.History) > discoveryBundleHistory {
		s.discoveryCache.History = s.discoveryCache.History[:discoveryBundleHistory]
	}
}

func (s *server) cachedDiscoverySnapshot(revision string) *discoveryBundleSnapshot {
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	if current := s.discoveryCache.Current; current != nil && current.Revision == revision {
		return current
	}
	for _, previous := range s.discoveryCache.History {
		if previous.Revision == revision {
			return previous
		}
	}
	return nil
}

func (s *server) invalidateDiscoveryCache() {
	s.discoveryCacheMu.Lock()
	s.discoveryCache.Invalidated = true
	s.discoveryCacheMu.Unlock()
}

func (s *server) reserveDiscoveryJSONForKey(
	key string,
	revision string,
	now time.Time,
) (string, int, bool) {
	s.discoveryRateMu.Lock()
	defer s.discoveryRateMu.Unlock()
	rate, ok, retryAfter := s.discoveryRateForKeyLocked(key, now)
	if !ok {
		return "", retryAfter, false
	}
	if rate.PairCount >= discoveryRateLimit {
		return "", discoveryRetryAfterSeconds(rate.WindowStart.Add(discoveryRateWindow), now), false
	}
	rate.PairCount++
	// Old clients issue two independent GETs without carrying an ETag back.
	// Pin all outstanding pairs for this source to one immutable revision.
	if rate.PendingPairs == 0 || rate.PendingRevision == "" {
		rate.PendingRevision = revision
		rate.PendingUntil = now.Add(discoveryPairTTL)
	}
	rate.PendingPairs++
	s.discoveryRates[key] = rate
	return rate.PendingRevision, 0, true
}

func (s *server) reserveDiscoveryMinisigForKey(
	key string,
	requestedRevision string,
	now time.Time,
) (string, int, bool, bool) {
	s.discoveryRateMu.Lock()
	defer s.discoveryRateMu.Unlock()
	rate, ok, retryAfter := s.discoveryRateForKeyLocked(key, now)
	if !ok {
		return "", retryAfter, false, true
	}
	if rate.PendingPairs > 0 && rate.PendingRevision != "" {
		if requestedRevision != "" && requestedRevision != rate.PendingRevision {
			return "", 0, true, false
		}
		revision := rate.PendingRevision
		rate.PendingPairs--
		if rate.PendingPairs == 0 {
			rate.PendingRevision = ""
			rate.PendingUntil = time.Time{}
		}
		s.discoveryRates[key] = rate
		return revision, 0, true, true
	}
	if rate.PairCount >= discoveryRateLimit {
		return "", discoveryRetryAfterSeconds(rate.WindowStart.Add(discoveryRateWindow), now), false, true
	}
	rate.PairCount++
	s.discoveryRates[key] = rate
	return requestedRevision, 0, true, true
}

func (s *server) discoveryRateForKeyLocked(key string, now time.Time) (discoveryRequestRate, bool, int) {
	if s.discoveryRates == nil {
		s.discoveryRates = make(map[string]discoveryRequestRate)
	}
	if rate, exists := s.discoveryRates[key]; exists {
		rate = normalizeDiscoveryRequestRate(rate, now)
		return rate, true, 0
	}
	if len(s.discoveryRates) >= maxDiscoveryRateKeys {
		retryAfter := int(discoveryRateWindow / time.Second)
		for existingKey, rate := range s.discoveryRates {
			if discoveryRequestRateExpired(rate, now) {
				delete(s.discoveryRates, existingKey)
				continue
			}
			candidate := discoveryRequestRateRetryAfter(rate, now)
			if candidate < retryAfter {
				retryAfter = candidate
			}
		}
		if len(s.discoveryRates) >= maxDiscoveryRateKeys {
			return discoveryRequestRate{}, false, retryAfter
		}
	}
	return discoveryRequestRate{WindowStart: now}, true, 0
}

func normalizeDiscoveryRequestRate(rate discoveryRequestRate, now time.Time) discoveryRequestRate {
	if rate.WindowStart.IsZero() {
		return discoveryRequestRate{WindowStart: now}
	}
	if now.Before(rate.WindowStart) {
		rate.WindowStart = now
		rate.PairCount = 0
		if rate.PendingPairs > 0 && rate.PendingRevision != "" {
			rate.PendingUntil = now.Add(discoveryPairTTL)
		}
		return rate
	}
	if !rate.PendingUntil.IsZero() && !now.Before(rate.PendingUntil) {
		rate.PendingPairs = 0
		rate.PendingRevision = ""
		rate.PendingUntil = time.Time{}
	}
	if now.Sub(rate.WindowStart) >= discoveryRateWindow {
		rate.WindowStart = now
		rate.PairCount = 0
	}
	return rate
}

func discoveryRequestRateExpired(rate discoveryRequestRate, now time.Time) bool {
	if rate.WindowStart.IsZero() || now.Before(rate.WindowStart) {
		return true
	}
	pending := rate.PendingPairs > 0 && !rate.PendingUntil.IsZero() && now.Before(rate.PendingUntil)
	return now.Sub(rate.WindowStart) >= discoveryRateWindow && !pending
}

func discoveryRequestRateRetryAfter(rate discoveryRequestRate, now time.Time) int {
	deadline := rate.WindowStart.Add(discoveryRateWindow)
	if rate.PendingPairs > 0 && now.Before(rate.PendingUntil) && deadline.Before(rate.PendingUntil) {
		deadline = rate.PendingUntil
	}
	return discoveryRetryAfterSeconds(deadline, now)
}

func discoveryRetryAfterSeconds(deadline time.Time, now time.Time) int {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return 1
	}
	seconds := int(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}

func discoveryRateKey(value string) string {
	value = strings.TrimSpace(value)
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return rateLimitKey(value)
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String()
	}
	// Discovery is a CGNAT-scale public endpoint; /48 aggregation prevents one
	// routed IPv6 allocation from rotating through 65,536 independent /64 keys.
	addr = addr.WithZone("")
	return netip.PrefixFrom(addr, 48).Masked().String()
}

func requestedDiscoveryRevision(r *http.Request) string {
	if revision := strings.TrimSpace(r.URL.Query().Get("revision")); revision != "" {
		return revision
	}
	value := strings.TrimSpace(r.Header.Get("If-Match"))
	if value == "" || value == "*" {
		return ""
	}
	value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	return strings.Trim(strings.TrimSpace(value), `"`)
}

func setDiscoveryBundleHeaders(w http.ResponseWriter, bundle *discoveryBundleSnapshot) {
	w.Header().Set("ETag", `"`+bundle.Revision+`"`)
	w.Header().Set("X-Discovery-Revision", bundle.Revision)
	w.Header().Set("Cache-Control", "no-store")
}

func writeDiscoveryRateExceeded(w http.ResponseWriter, retryAfter int) {
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	http.Error(w, "discovery request rate exceeded", http.StatusTooManyRequests)
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
