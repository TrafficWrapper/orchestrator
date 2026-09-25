package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	discoveryRateEvictBatch = maxDiscoveryRateKeys / 64
	// discoveryIPv6AggregateBits and discoveryAggregateRateLimit bound one
	// IPv6 provider allocation as a whole. The limit is generous because a
	// mobile carrier can place many subscribers inside one /32.
	discoveryIPv6AggregateBits  = 32
	discoveryAggregateRateLimit = 16 * discoveryRateLimit
)

type discoveryBundleSnapshot struct {
	JSON           string
	Minisig        string
	PublicKey      string
	Revision       string
	GeneratedAt    time.Time
	WorkerRevision uint64
	// Gen is the invalidation generation the build started under; the
	// snapshot is stale once the generation moves on (ORC-L28).
	Gen uint64
}

type discoveryBundleCache struct {
	Current *discoveryBundleSnapshot
	History []*discoveryBundleSnapshot
}

type discoveryRequestRate struct {
	WindowStart     time.Time
	PairCount       int
	PendingUntil    time.Time
	PendingRevision string
	// LastSeen orders eviction when the table is full.
	LastSeen time.Time
}

func (s *server) handleDiscoveryEndpointsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.discoveryMode() == discoveryModeOff {
		http.NotFound(w, r)
		return
	}
	bundle, err := s.signedDiscoverySnapshot()
	if err != nil {
		writeDiscoveryUnavailable(w, err)
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
	if s.discoveryMode() == discoveryModeOff {
		http.NotFound(w, r)
		return
	}
	requestedRevision := requestedDiscoveryRevision(r)
	revision, revisionMatches := s.discoveryMinisigRevisionForKey(
		discoveryRateKey(clientIP(r)),
		requestedRevision,
		time.Now(),
	)
	if !revisionMatches {
		http.Error(w, "discovery revision precondition failed", http.StatusPreconditionFailed)
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
			writeDiscoveryUnavailable(w, err)
			return
		}
	}
	setDiscoveryBundleHeaders(w, bundle)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(bundle.Minisig))
}

func (s *server) handleAdminDiscoveryBump(w http.ResponseWriter, r *http.Request) {
	seq, err := s.bumpDiscoverySeq()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "seq": seq})
}

func writeDiscoveryUnavailable(w http.ResponseWriter, err error) {
	log.Printf("discovery bundle unavailable: %v", err)
	http.Error(w, "discovery temporarily unavailable", http.StatusServiceUnavailable)
}

// discoveryBuildErrorTTL caches a failed build (e.g. a missing update key) so
// every request does not re-read disk and rescan workers while it persists.
const discoveryBuildErrorTTL = 5 * time.Second

func (s *server) freshDiscoverySnapshotLocked(now time.Time, revision uint64) *discoveryBundleSnapshot {
	current := s.discoveryCache.Current
	if current == nil || current.Gen != s.discoveryInvalidGen.Load() || current.WorkerRevision != revision {
		return nil
	}
	if age := now.Sub(current.GeneratedAt); age < 0 || age >= discoveryBundleCacheTTL {
		return nil
	}
	return current
}

// signedDiscoverySnapshot returns the cached bundle or rebuilds it. Builds are
// serialized by discoveryBuildMu and run without discoveryCacheMu, so lookups
// of cached revisions (the .minisig path) never wait on disk I/O or signing.
func (s *server) signedDiscoverySnapshot() (*discoveryBundleSnapshot, error) {
	revision := s.store.discoveryRevision()
	s.discoveryCacheMu.Lock()
	fresh := s.freshDiscoverySnapshotLocked(time.Now().UTC(), revision)
	s.discoveryCacheMu.Unlock()
	if fresh != nil {
		return fresh, nil
	}

	s.discoveryBuildMu.Lock()
	defer s.discoveryBuildMu.Unlock()
	now := time.Now().UTC()
	revision = s.store.discoveryRevision()
	s.discoveryCacheMu.Lock()
	fresh = s.freshDiscoverySnapshotLocked(now, revision)
	s.discoveryCacheMu.Unlock()
	if fresh != nil {
		return fresh, nil
	}
	gen := s.discoveryInvalidGen.Load()
	if s.discoveryBuildErr != nil && s.discoveryBuildErrGn == gen && now.Sub(s.discoveryBuildErrAt) < discoveryBuildErrorTTL {
		return nil, s.discoveryBuildErr
	}
	next, err := s.buildDiscoverySnapshot(now, revision)
	if next != nil {
		next.Gen = gen
	}
	if err != nil {
		s.discoveryBuildErr = err
		s.discoveryBuildErrAt = now
		s.discoveryBuildErrGn = gen
		return nil, err
	}
	s.discoveryBuildErr = nil
	s.discoveryCacheMu.Lock()
	s.rememberDiscoverySnapshotLocked(s.discoveryCache.Current)
	// An invalidation (e.g. a seq bump) that landed while this build ran
	// leaves next.Gen behind the current generation, so it is not served as
	// fresh.
	s.discoveryCache.Current = next
	s.discoveryCacheMu.Unlock()
	s.discoveryBuilds.Add(1)
	return next, nil
}

func (s *server) buildDiscoverySnapshot(now time.Time, revision uint64) (*discoveryBundleSnapshot, error) {
	priv, pubText, err := s.loadServerUpdateSigningKey()
	if err != nil {
		return nil, err
	}
	jsonText, err := s.discoveryBundleJSON(now)
	if err != nil {
		return nil, err
	}
	return &discoveryBundleSnapshot{
		JSON:           jsonText,
		Minisig:        string(minisign.Sign(priv, []byte(jsonText))),
		PublicKey:      pubText,
		Revision:       discoveryHash(jsonText),
		GeneratedAt:    now,
		WorkerRevision: revision,
	}, nil
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
	// Pending sources keep only a revision string; this bounded history supplies
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
	s.discoveryInvalidGen.Add(1)
}

func (s *server) reserveDiscoveryJSONForKey(
	key string,
	revision string,
	now time.Time,
) (string, int, bool) {
	s.discoveryRateMu.Lock()
	defer s.discoveryRateMu.Unlock()
	aggregateKey := discoveryRateAggregateKey(key)
	var aggregate discoveryRequestRate
	if aggregateKey != "" {
		aggregate = s.discoveryRateForKeyLocked(aggregateKey, now)
		if aggregate.PairCount >= discoveryAggregateRateLimit {
			return "", discoveryRetryAfterSeconds(aggregate.WindowStart.Add(discoveryRateWindow), now), false
		}
	}
	rate := s.discoveryRateForKeyLocked(key, now)
	if rate.PairCount >= discoveryRateLimit {
		return "", discoveryRetryAfterSeconds(rate.WindowStart.Add(discoveryRateWindow), now), false
	}
	rate.PairCount++
	rate.LastSeen = now
	// Old clients issue two independent GETs without carrying an ETag back.
	// Pin this source to one immutable revision for a grace window. Minisig
	// requests cannot consume the pin because a CGNAT key represents many
	// independent clients.
	if rate.PendingRevision == "" {
		rate.PendingRevision = revision
		rate.PendingUntil = now.Add(discoveryPairTTL)
	}
	s.storeDiscoveryRateLocked(key, rate, now)
	if aggregateKey != "" {
		aggregate.PairCount++
		aggregate.LastSeen = now
		s.storeDiscoveryRateLocked(aggregateKey, aggregate, now)
	}
	return rate.PendingRevision, 0, true
}

func (s *server) discoveryMinisigRevisionForKey(
	key string,
	requestedRevision string,
	now time.Time,
) (string, bool) {
	s.discoveryRateMu.Lock()
	defer s.discoveryRateMu.Unlock()
	rate, exists := s.discoveryRates[key]
	if !exists {
		// A minisig without a preceding JSON fetch is not a useful discovery
		// pair. It neither consumes JSON-pair budget nor creates rate-map state.
		return requestedRevision, true
	}
	rate = normalizeDiscoveryRequestRate(rate, now)
	rate.LastSeen = now
	s.discoveryRates[key] = rate
	if rate.PendingRevision != "" && !rate.PendingUntil.IsZero() && now.Before(rate.PendingUntil) {
		if requestedRevision != "" && requestedRevision != rate.PendingRevision {
			return "", false
		}
		return rate.PendingRevision, true
	}
	return requestedRevision, true
}

// discoveryRateForKeyLocked returns the current window for key without
// storing it. A new source always gets a fresh window: capacity is made by
// storeDiscoveryRateLocked, never by refusing unknown sources.
func (s *server) discoveryRateForKeyLocked(key string, now time.Time) discoveryRequestRate {
	if rate, exists := s.discoveryRates[key]; exists {
		return normalizeDiscoveryRequestRate(rate, now)
	}
	return discoveryRequestRate{WindowStart: now, LastSeen: now}
}

// storeDiscoveryRateLocked saves rate under key. When a new key would exceed
// the table bound, expired windows are dropped first; if the table is still
// full, the least valuable live entries are evicted: the lowest pair count
// first, then the least recently seen. A busy source's counter is therefore
// the last thing to go, while a stream of one-off sources recycles its own
// slots instead of locking every new source out.
func (s *server) storeDiscoveryRateLocked(key string, rate discoveryRequestRate, now time.Time) {
	if s.discoveryRates == nil {
		s.discoveryRates = make(map[string]discoveryRequestRate)
	}
	if _, exists := s.discoveryRates[key]; !exists && len(s.discoveryRates) >= maxDiscoveryRateKeys {
		s.evictDiscoveryRatesLocked(now)
	}
	s.discoveryRates[key] = rate
}

func (s *server) evictDiscoveryRatesLocked(now time.Time) {
	for existingKey, rate := range s.discoveryRates {
		if discoveryRequestRateExpired(rate, now) {
			delete(s.discoveryRates, existingKey)
		}
	}
	if len(s.discoveryRates) < maxDiscoveryRateKeys {
		return
	}
	type candidate struct {
		key      string
		pairs    int
		lastSeen time.Time
	}
	candidates := make([]candidate, 0, len(s.discoveryRates))
	for existingKey, rate := range s.discoveryRates {
		lastSeen := rate.LastSeen
		if lastSeen.IsZero() {
			lastSeen = rate.WindowStart
		}
		candidates = append(candidates, candidate{key: existingKey, pairs: rate.PairCount, lastSeen: lastSeen})
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		if a.pairs != b.pairs {
			return cmp.Compare(a.pairs, b.pairs)
		}
		return a.lastSeen.Compare(b.lastSeen)
	})
	// Evict a batch so a flood of new sources pays for the sort once per
	// batch rather than once per request.
	evict := len(s.discoveryRates) - maxDiscoveryRateKeys + discoveryRateEvictBatch
	if evict > len(candidates) {
		evict = len(candidates)
	}
	for _, c := range candidates[:evict] {
		delete(s.discoveryRates, c.key)
	}
}

func normalizeDiscoveryRequestRate(rate discoveryRequestRate, now time.Time) discoveryRequestRate {
	if rate.WindowStart.IsZero() {
		return discoveryRequestRate{WindowStart: now}
	}
	if now.Before(rate.WindowStart) {
		rate.WindowStart = now
		rate.PairCount = 0
		if rate.PendingRevision != "" {
			rate.PendingUntil = now.Add(discoveryPairTTL)
		}
		return rate
	}
	if rate.PendingRevision != "" && (rate.PendingUntil.IsZero() || !now.Before(rate.PendingUntil)) {
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
	pending := rate.PendingRevision != "" && !rate.PendingUntil.IsZero() && now.Before(rate.PendingUntil)
	return now.Sub(rate.WindowStart) >= discoveryRateWindow && !pending
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

// discoveryRateAggregateKey returns the second-level bucket for an IPv6 /48
// source key, or "" when the key has no parent bucket. A single provider
// allocation (/32) holds 65,536 /48 keys; the parent bucket bounds the
// combined rate of one allocation without shrinking the per-/48 budget.
func discoveryRateAggregateKey(key string) string {
	prefix, err := netip.ParsePrefix(key)
	if err != nil || !prefix.Addr().Is6() || prefix.Bits() < discoveryIPv6AggregateBits {
		return ""
	}
	return "agg6:" + netip.PrefixFrom(prefix.Addr(), discoveryIPv6AggregateBits).Masked().String()
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
	reality := []any{}
	full := s.discoveryMode() == discoveryModeFull
	for _, rec := range workers {
		if rec.Status != "approved" && rec.Status != "active" {
			continue
		}
		if rec.Disabled || rec.SelfDescribeForbidden || !workerFreshForClients(rec, now) {
			continue
		}
		// Validate per worker so one bad worker never takes the feed down.
		if item, ok := discoveryAWGEndpoint(rec); ok {
			if _, bad := findForbiddenKey(item); !bad {
				item["worker_id"] = rec.ID
				awg = append(awg, item)
			}
		}
		// REALITY entries (with their short IDs) are published only in
		// full mode (X-M1); the app core needs just the AWG entry.
		if !full {
			continue
		}
		if item, ok := discoveryRealityEndpoint(rec); ok {
			if _, bad := findForbiddenKey(item); !bad {
				item["worker_id"] = rec.ID
				reality = append(reality, item)
			}
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
	// Atomic replace: a crash or full disk must not leave a truncated seq file
	// that fails every discovery request until fixed by hand. Seq goes first;
	// a lost hash write only causes one extra (harmless) seq bump.
	if err := writeFileAtomic(s.discoverySeqPath(), []byte(strconv.FormatInt(seq, 10)+"\n"), 0o600); err != nil {
		return err
	}
	if hash != "" {
		if err := writeFileAtomic(s.discoveryHashPath(), []byte(hash+"\n"), 0o600); err != nil {
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
	if !workerProtocolEnabled(rec, "awg") {
		return nil, false
	}
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
	if !workerProtocolEnabled(rec, "reality") {
		return nil, false
	}
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
