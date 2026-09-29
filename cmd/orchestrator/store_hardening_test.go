package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// enrollWithIdentityForTest enrolls a device with its own identity key.
func enrollWithIdentityForTest(t *testing.T, s *server, token, identity, awgPublic string) deviceEnrollResponse {
	t.Helper()
	raw, _ := json.Marshal(deviceEnrollRequest{
		BootstrapToken:  token,
		IdentityPubKey:  identity,
		IdentityKeyType: "ed25519",
		AWGPublicKey:    awgPublic,
		ClientVersion:   "0.1.31",
	})
	resp, err := s.handleDeviceEnroll(make([]byte, 32), raw)
	if err != nil {
		t.Fatal(err)
	}
	typed, ok := resp.(deviceEnrollResponse)
	if !ok {
		t.Fatalf("unexpected response type %T", resp)
	}
	return typed
}

// ORC-L2: an AWG public key held by one device cannot be enrolled by another,
// and the refused enrollment does not spend its token.
func TestEnrollRefusesAWGKeyOfAnotherDevice(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	if _, err := s.store.createBootstrapToken("boot-first", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	second, err := s.store.createBootstrapToken("boot-second", time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := enrollWithIdentityForTest(t, s, "boot-first", "identity-one", "shared-awg-key")
	if !first.OK {
		t.Fatalf("first enroll: %+v", first)
	}
	dup := enrollWithIdentityForTest(t, s, "boot-second", "identity-two", "shared-awg-key")
	if dup.OK || dup.Code != "awg_key_in_use" {
		t.Fatalf("duplicate awg key accepted: %+v", dup)
	}
	if rec := bootstrapTokenForTest(t, s, second.ID); rec.Uses != 0 {
		t.Fatalf("refused enrollment spent the token: uses=%d", rec.Uses)
	}
	devices, err := s.store.devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("duplicate device stored: %d devices", len(devices))
	}
	// The same token still enrolls a device with its own key.
	if own := enrollWithIdentityForTest(t, s, "boot-second", "identity-two", "own-awg-key"); !own.OK {
		t.Fatalf("enroll with own key: %+v", own)
	}
	// Re-enrollment of the key's owner is unaffected.
	if again := enrollWithIdentityForTest(t, s, "boot-first", "identity-one", "shared-awg-key"); !again.OK {
		t.Fatalf("owner re-enroll: %+v", again)
	}
}

// ORC-L10: bootstrap limits are checked against the schema at creation.
func TestBootstrapLimitsValidatedAtCreation(t *testing.T) {
	for _, ok := range []string{
		"",
		"{}",
		`{"note":"for Anna"}`,
		`{"traffic_quota_bytes":1073741824,"rate_limit":"20mbit","expires_at":"2030-01-01T00:00:00Z"}`,
	} {
		if _, err := parseBootstrapLimits(ok); err != nil {
			t.Fatalf("valid limits %q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"devices":1}`,
		`{"expires_at":"tomorrow"}`,
		`{"traffic_quota_bytes":-1}`,
		`{"traffic_quota_bytes":"10GB"}`,
		`{"rate_limit":"20 mbit"}`,
		`{"note":"` + strings.Repeat("x", bootstrapLimitsNoteMaxRunes+1) + `"}`,
		`[]`,
		`null`,
		`{} {}`,
	} {
		if _, err := parseBootstrapLimits(bad); err == nil {
			t.Fatalf("invalid limits %q accepted", bad)
		}
	}
	raw, err := parseBootstrapLimits(` {"note":"x"} `)
	if err != nil || string(raw) != `{"note":"x"}` {
		t.Fatalf("limits not kept as given: %q %v", raw, err)
	}

	s := newTestServer(t)
	if _, err := s.store.createBootstrapToken("boot-bad-limits", time.Now().Add(time.Hour), json.RawMessage(`{"expires_at":"soon"}`), nil); err == nil {
		t.Fatal("store issued a token whose limits enrollment cannot parse")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/bootstrap-token/create", strings.NewReader(`{"limits":{"devices":1},"expires":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`))
	s.handleAdminBootstrapTokenCreate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown limits field: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// ORC-L14: a config edit is validated as a whole and applied atomically
// with a single seq bump.
func TestAdminConfigEditIsAtomicWithOneSeqBump(t *testing.T) {
	s := newTestServer(t)
	a := addApprovedWorkerWithStatic(t, s, "worker-static-a")
	b := addApprovedWorkerWithStatic(t, s, "worker-static-b")
	seqs := func() (int64, int64) {
		t.Helper()
		wa, err := s.store.worker(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		wb, err := s.store.worker(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		return wa.DesiredSeq, wb.DesiredSeq
	}
	edit := func(body string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		s.handleAdminConfigEdit(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/config/edit", strings.NewReader(body)))
		return rec.Code
	}
	beforeA, beforeB := seqs()

	for _, body := range []string{
		fmt.Sprintf(`{"workers":[{"worker_id":%q,"weight":30},{"worker_id":%q,"weight":500}]}`, a.ID, b.ID),
		fmt.Sprintf(`{"workers":[{"worker_id":%q,"weight":30},{"worker_id":"no-such-worker","weight":10}]}`, a.ID),
		fmt.Sprintf(`{"workers":[{"worker_id":%q,"weight":30},{"worker_id":%q,"protocols":{"bogus":true}}]}`, a.ID, b.ID),
	} {
		// 400 for a bad value, 404 for an unknown worker.
		if code := edit(body); code != http.StatusBadRequest && code != http.StatusNotFound {
			t.Fatalf("invalid batch status=%d", code)
		}
		wa, err := s.store.worker(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if wa.ConfigWeight != nil {
			t.Fatalf("partial edit committed: weight=%d", *wa.ConfigWeight)
		}
		if gotA, gotB := seqs(); gotA != beforeA || gotB != beforeB {
			t.Fatalf("refused edit bumped seq: a %d->%d b %d->%d", beforeA, gotA, beforeB, gotB)
		}
	}

	// The store applies a valid batch with one seq bump (the handler then
	// publishes the client bundle, which moves seqs on its own).
	weight, priority := 30, 2
	if err := s.store.updateWorkerPolicies([]workerPolicyUpdate{
		{ID: a.ID, Patch: workerPolicyPatch{Weight: &weight}},
		{ID: b.ID, Patch: workerPolicyPatch{Priority: &priority}},
	}); err != nil {
		t.Fatal(err)
	}
	gotA, gotB := seqs()
	if gotA != beforeA+1 || gotB != beforeB+1 {
		t.Fatalf("batch must bump seq once: a %d->%d b %d->%d", beforeA, gotA, beforeB, gotB)
	}
	wa, _ := s.store.worker(a.ID)
	wb, _ := s.store.worker(b.ID)
	if wa.ConfigWeight == nil || *wa.ConfigWeight != 30 || wb.ConfigPriority == nil || *wb.ConfigPriority != 2 {
		t.Fatalf("batch not applied: a=%+v b=%+v", wa.ConfigWeight, wb.ConfigPriority)
	}
	if code := edit(fmt.Sprintf(`{"workers":[{"worker_id":%q,"weight":40},{"worker_id":%q,"priority":3}]}`, a.ID, b.ID)); code != http.StatusOK {
		t.Fatalf("valid batch status=%d", code)
	}
	wa, _ = s.store.worker(a.ID)
	wb, _ = s.store.worker(b.ID)
	if *wa.ConfigWeight != 40 || *wb.ConfigPriority != 3 {
		t.Fatalf("handler batch not applied: a=%d b=%d", *wa.ConfigWeight, *wb.ConfigPriority)
	}
}

func TestWallClockGuardPausesAfterJump(t *testing.T) {
	var g wallClockGuard
	t0 := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if !g.stable(t0, 0) {
		t.Fatal("first observation must pass")
	}
	if !g.stable(t0.Add(30*time.Second), 30*time.Second) {
		t.Fatal("steady clock must pass")
	}
	// Wall clock leaps two days ahead within 30s of monotonic time.
	jumped := t0.Add(60*time.Second + 48*time.Hour)
	if g.stable(jumped, 60*time.Second) {
		t.Fatal("forward jump not detected")
	}
	mono := 60 * time.Second
	for mono < 60*time.Second+wallClockSettle-30*time.Second {
		mono += 30 * time.Second
		jumped = jumped.Add(30 * time.Second)
		if g.stable(jumped, mono) {
			t.Fatalf("pass allowed %s after the jump, before the settle time", mono-60*time.Second)
		}
	}
	mono += 30 * time.Second
	jumped = jumped.Add(30 * time.Second)
	if !g.stable(jumped, mono) {
		t.Fatal("steady clock did not resume after the settle time")
	}
	// A backward jump pauses as well.
	if g.stable(jumped.Add(-time.Hour), mono+30*time.Second) {
		t.Fatal("backward jump not detected")
	}
}

// ORC-L33: a pass right after a wall-clock jump neither prunes tokens nor
// applies expiry blocks.
func TestExpiryJanitorSkipsPassAfterClockJump(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	now := time.Now().UTC()
	tok, err := s.store.createBootstrapToken("boot-jump", now.Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(24 * time.Hour).Format(time.RFC3339)
	putQuotaDevice(t, s, deviceRecord{ID: "twpk_jump", Status: "approved", Limits: deviceLimits{ExpiresAt: &expires}, AWGPublicKey: "awg-jump", InternalIP: "10.13.13.20/32", RealityUUID: "uuid-jump"})

	s.expiryJanitorPass(now, 0)
	s.expiryJanitorPass(now.Add(30*24*time.Hour), 30*time.Second)

	if rec := bootstrapTokenForTest(t, s, tok.ID); rec.ID != tok.ID {
		t.Fatal("token pruned on a jumped clock")
	}
	device, err := s.store.device("twpk_jump")
	if err != nil {
		t.Fatal(err)
	}
	if device.Status != "approved" {
		t.Fatalf("device blocked on a jumped clock: %+v", device.BlockedReason)
	}
}

// ORC-L33: automatic expiry blocks are reviewed and lifted when the expiry
// has not been reached; manual, unverified and quota blocks stay.
func TestExpiryJanitorLiftsBlockWhenExpiryNotReached(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour).Format(time.RFC3339)
	blockedAt := now.Add(-time.Minute)
	base := func(id string) deviceRecord {
		return deviceRecord{ID: id, Status: "revoked", BlockedAt: &blockedAt, Limits: deviceLimits{ExpiresAt: &future}, AWGPublicKey: "awg-" + id, InternalIP: "10.13.13.30/32", RealityUUID: "uuid-" + id}
	}
	auto := base("twpk_auto")
	auto.BlockedReason, auto.BlockOrigin = "expires_at", deviceBlockOriginAuto
	manual := base("twpk_manual")
	manual.BlockedReason = "manual"
	unverified := base("twpk_unverified")
	unverified.BlockedReason, unverified.BlockOrigin = "expires_at", deviceBlockOriginUnverified
	quota := base("twpk_quota")
	quota.BlockedReason, quota.BlockOrigin = "traffic_quota_bytes", deviceBlockOriginAuto
	quota.Limits.TrafficQuotaBytes, quota.UsageRxBytes = 10, 20
	for _, rec := range []deviceRecord{auto, manual, unverified, quota} {
		putQuotaDevice(t, s, rec)
	}
	workers, _ := s.store.workers()
	seqBefore := workers[0].DesiredSeq

	s.expiryJanitorPass(now, 0)

	want := map[string]string{"twpk_auto": "approved", "twpk_manual": "revoked", "twpk_unverified": "revoked", "twpk_quota": "revoked"}
	for id, status := range want {
		rec, err := s.store.device(id)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status != status {
			t.Fatalf("%s status=%s want %s", id, rec.Status, status)
		}
	}
	if rec, _ := s.store.device("twpk_auto"); rec.BlockedReason != "" || rec.BlockOrigin != "" || rec.BlockedAt != nil {
		t.Fatalf("lifted block left markers: %+v", rec)
	}
	workers, _ = s.store.workers()
	if workers[0].DesiredSeq <= seqBefore {
		t.Fatal("lifting a block must reach workers (seq bump)")
	}
}

// ORC-I6: a revoked record with an automatic reason from older code may hide
// a manual revoke; it is marked at open and never lifted automatically.
func TestAmbiguousLegacyBlockIsMarkedAndKept(t *testing.T) {
	cfg := orchConfig{StateDir: t.TempDir()}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: cfg, store: st}
	putQuotaDevice(t, s, deviceRecord{ID: "twpk_legacy", Status: "revoked", BlockedReason: "traffic_quota_bytes", Limits: deviceLimits{TrafficQuotaBytes: 10}, UsageRxBytes: 20})
	putQuotaDevice(t, s, deviceRecord{ID: "twpk_new_auto", Status: "revoked", BlockedReason: "traffic_quota_bytes", BlockOrigin: deviceBlockOriginAuto, Limits: deviceLimits{TrafficQuotaBytes: 10}, UsageRxBytes: 20})
	if err := st.close(); err != nil {
		t.Fatal(err)
	}
	st, err = openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.close() })
	legacy, err := st.device("twpk_legacy")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.BlockOrigin != deviceBlockOriginUnverified {
		t.Fatalf("ambiguous block not marked: %q", legacy.BlockOrigin)
	}
	if err := st.setDeviceLimits("twpk_legacy", deviceLimits{TrafficQuotaBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if legacy, _ = st.device("twpk_legacy"); legacy.Status != "revoked" {
		t.Fatal("limit change reactivated a device whose block may be a manual revoke")
	}
	if err := st.setDeviceLimits("twpk_new_auto", deviceLimits{TrafficQuotaBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if rec, _ := st.device("twpk_new_auto"); rec.Status != "approved" {
		t.Fatal("known automatic block not lifted by a limit change")
	}
}

// ORC-I6: blocks set by usage accounting carry the auto origin; a manual
// revoke clears it.
func TestBlockOriginSetByAutoBlockAndClearedByRevoke(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{ID: "twpk_origin", Status: "approved", Limits: deviceLimits{TrafficQuotaBytes: 10}, UsageRxBytes: 20})
	if _, err := s.store.applyDeviceUsageAndBlocks("", nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.store.device("twpk_origin")
	if rec.Status != "revoked" || rec.BlockOrigin != deviceBlockOriginAuto {
		t.Fatalf("auto block origin missing: %+v", rec)
	}
	if err := s.store.revokeDevice("twpk_origin"); err != nil {
		t.Fatal(err)
	}
	if rec, _ = s.store.device("twpk_origin"); rec.BlockedReason != "manual" || rec.BlockOrigin != "" {
		t.Fatalf("manual revoke kept auto origin: %+v", rec)
	}
}

// ORC-I2: an exhausted token is retained for the full period after its use;
// records without UsedAt keep counting from creation.
func TestExhaustedTokenRetentionCountsFromUse(t *testing.T) {
	now := time.Now().UTC()
	usedAt := now.Add(-time.Hour)
	rec := tokenRecord{MaxUses: 1, Uses: 1, CreatedAt: now.Add(-10 * 24 * time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour), UsedAt: &usedAt}
	if tokenDead(rec, now) {
		t.Fatal("token used an hour ago pruned")
	}
	old := now.Add(-tokenRetentionAfterUse - time.Hour)
	rec.UsedAt = &old
	if !tokenDead(rec, now) {
		t.Fatal("token used beyond retention kept")
	}
	rec.UsedAt = nil
	if !tokenDead(rec, now) {
		t.Fatal("legacy record without used_at must count from creation")
	}

	s := newTestServer(t)
	addApprovedWorker(t, s)
	tok, err := s.store.createBootstrapToken("boot-used", now.Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp := enrollDeviceForTestWithVersion(t, s, "boot-used", "0.1.31"); !resp.OK {
		t.Fatalf("enroll: %+v", resp)
	}
	if stored := bootstrapTokenForTest(t, s, tok.ID); stored.UsedAt == nil || stored.UsedAt.IsZero() {
		t.Fatal("consuming a bootstrap token did not record used_at")
	}
	if err := s.store.createToken("worker-tok", "worker-secret", time.Hour, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.consumeToken("worker-secret", "any"); err != nil {
		t.Fatal(err)
	}
	if stored := bootstrapTokenForTest(t, s, "worker-tok"); stored.UsedAt == nil {
		t.Fatal("consuming a worker token did not record used_at")
	}
	raw, _ := json.Marshal(tokenRecord{ID: "x"})
	if strings.Contains(string(raw), "used_at") {
		t.Fatalf("used_at must be omitted when unset: %s", raw)
	}
}

// ORC-I7: telemetry for a device deleted meanwhile leaves no snapshot.
func TestRecordTelemetryForDeletedDeviceLeavesNoOrphan(t *testing.T) {
	s := newTestServer(t)
	for _, version := range []string{"", "0.1.31"} {
		err := s.store.recordTelemetry(telemetrySnapshotRecord{DeviceID: "twpk_gone", ClientVersion: version})
		if !errors.Is(err, errDeviceNotFound) {
			t.Fatalf("version %q: err=%v", version, err)
		}
	}
	snapshots, err := s.store.telemetrySnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshots["twpk_gone"]; ok {
		t.Fatal("orphan telemetry snapshot written")
	}
}

// ORC-L19: nonces expire after 2x the skew and the cache is swept.
func TestTelemetryNonceCacheExpiresByAge(t *testing.T) {
	s := &server{}
	t0 := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if !s.consumeTelemetryNonce("dev-a", "n1", t0) {
		t.Fatal("new nonce refused")
	}
	if s.consumeTelemetryNonce("dev-a", "n1", t0.Add(time.Second)) {
		t.Fatal("replayed nonce accepted")
	}
	later := t0.Add(telemetryNonceTTL + time.Second)
	if !s.consumeTelemetryNonce("dev-b", "m1", later) {
		t.Fatal("new nonce refused")
	}
	s.telemetryNonceMu.Lock()
	_, stale := s.telemetryNonces["dev-a"]
	s.telemetryNonceMu.Unlock()
	if stale {
		t.Fatal("expired device nonces not swept")
	}
}

// ORC-L19: on overflow the oldest nonce and the least recent device go.
func TestTelemetryNonceCacheEvictsOldest(t *testing.T) {
	s := &server{}
	t0 := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for i := 0; i <= telemetryNonceLRUMax; i++ {
		if !s.consumeTelemetryNonce("dev", fmt.Sprintf("n%d", i), t0.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("nonce %d refused", i)
		}
	}
	set := s.telemetryNonces["dev"]
	if len(set.seen) != telemetryNonceLRUMax {
		t.Fatalf("nonce set size=%d", len(set.seen))
	}
	if _, ok := set.seen["n0"]; ok {
		t.Fatal("oldest nonce not evicted")
	}
	if _, ok := set.seen["n1"]; !ok {
		t.Fatal("a newer nonce was evicted instead of the oldest")
	}

	s = &server{}
	for i := 0; i < telemetryNonceDeviceMax; i++ {
		s.consumeTelemetryNonce(fmt.Sprintf("dev-%d", i), "n", t0.Add(time.Duration(i)*time.Millisecond))
	}
	s.consumeTelemetryNonce("dev-new", "n", t0.Add(time.Minute))
	if len(s.telemetryNonces) != telemetryNonceDeviceMax {
		t.Fatalf("device count=%d", len(s.telemetryNonces))
	}
	if _, ok := s.telemetryNonces["dev-0"]; ok {
		t.Fatal("least recent device not evicted")
	}
	if _, ok := s.telemetryNonces["dev-1"]; !ok {
		t.Fatal("a more recent device was evicted instead of the least recent")
	}
}

// ORC-I4: poll counters are clamped.
func TestBotProblemPollCountersClamped(t *testing.T) {
	if got := clampedBotPollCount(math.MaxInt, botProblemPollsBeforeAlert); got != botProblemPollsBeforeAlert {
		t.Fatalf("clamp high=%d", got)
	}
	if got := clampedBotPollCount(-7, botProblemPollsBeforeAlert); got != 1 {
		t.Fatalf("clamp low=%d", got)
	}
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	entry := botProblemEntry{Scope: "worker", ID: "w", Kind: "worker_down", Label: "w"}
	key := botProblemKey(entry)
	state := botProblemState{}
	for i := 0; i < 10; i++ {
		state = buildBotProblemState(state, map[string]botProblemEntry{key: entry}, now.Add(time.Duration(i)*time.Minute))
	}
	if state.PendingPolls[key] != botProblemPollsBeforeAlert {
		t.Fatalf("pending polls grew past the threshold: %d", state.PendingPolls[key])
	}
	for i := 0; i < botProblemRecoveryMaxPolls+5; i++ {
		state = buildBotProblemState(state, nil, now.Add(time.Hour+time.Duration(i)*time.Minute))
	}
	if n, ok := state.RecoveryPolls[key]; ok && n > botProblemRecoveryMaxPolls {
		t.Fatalf("recovery polls grew past the limit: %d", n)
	}
}

// ORC-I4: an offline device is announced once per episode, not every
// cooldown; a new episode after a recovery is announced again.
func TestBotProblemOfflineAlertOncePerEpisode(t *testing.T) {
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	entry := botProblemEntry{Scope: "device", ID: "twpk_a", Kind: "device_offline", Label: "twpk_a"}
	key := botProblemKey(entry)
	prev := botProblemState{
		Active:       map[string]botProblemEntry{key: entry},
		PendingPolls: map[string]int{key: botProblemPollsBeforeAlert},
		LastNotified: map[string]time.Time{key: now.Add(-botProblemRepeatCooldown - time.Minute)},
	}
	current := buildBotProblemState(prev, map[string]botProblemEntry{key: entry}, now)
	if notices := botProblemNotices(prev, current, true); len(notices) != 0 {
		t.Fatalf("offline alert repeated within one episode: %+v", notices)
	}
	// Recovery (announced after the debounce) ends the episode.
	state := current
	for i := 1; i <= botProblemRecoveryPollsBeforeNote; i++ {
		prev = state
		state = buildBotProblemState(prev, nil, now.Add(time.Duration(i)*time.Minute))
		if notices := botProblemNotices(prev, state, true); len(notices) > 0 {
			markBotProblemNoticesSent(&state, notices)
		}
	}
	if _, ok := state.LastNotified[key]; ok {
		t.Fatal("recovery did not end the episode")
	}
	var sent []botProblemNotice
	for i := 1; i <= botProblemPollsBeforeAlert; i++ {
		prev = state
		state = buildBotProblemState(prev, map[string]botProblemEntry{key: entry}, now.Add(time.Hour+time.Duration(i)*time.Minute))
		notices := botProblemNotices(prev, state, true)
		markBotProblemNoticesSent(&state, notices)
		sent = append(sent, notices...)
	}
	if len(sent) != 1 || sent[0].Key != key {
		t.Fatalf("new offline episode not announced once: %+v", sent)
	}
}

// ORC-I4: a steady problem set does not rewrite the stored state each poll.
func TestBotProblemStateNotRewrittenWhenSteady(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{ID: "twpk_steady", Status: "approved", AWGPublicKey: "awg", InternalIP: "10.13.13.9/32", RealityUUID: "uuid"})
	if err := s.store.setTelemetrySnapshot(telemetrySnapshotRecord{DeviceID: "twpk_steady", ReceivedAt: time.Now().UTC().Add(-botProblemDeviceOfflineAfter - time.Minute)}); err != nil {
		t.Fatal(err)
	}
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	for i := 0; i < 3; i++ {
		bot.notifyProblemTransitions(context.Background())
	}
	if mock.sentCount() != 1 {
		t.Fatalf("expected one alert, got %d", mock.sentCount())
	}
	stored, _, err := s.store.getBotProblemState()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		bot.notifyProblemTransitions(context.Background())
	}
	again, _, err := s.store.getBotProblemState()
	if err != nil {
		t.Fatal(err)
	}
	if !again.UpdatedAt.Equal(stored.UpdatedAt) {
		t.Fatalf("steady state rewritten: %s -> %s", stored.UpdatedAt, again.UpdatedAt)
	}
	if mock.sentCount() != 1 {
		t.Fatalf("steady problem re-announced: %d", mock.sentCount())
	}
}
