package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func (s *server) handleAdminBotStatus(w http.ResponseWriter, r *http.Request) {
	rec, ok, err := s.store.botSettings()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeJSON(w, map[string]any{"ok": true, "configured": false})
		return
	}
	writeJSON(w, map[string]any{
		"ok":         true,
		"configured": true,
		"owner_id":   rec.OwnerID,
		"updated_at": rec.UpdatedAt.Format(time.RFC3339),
	})
}

// handleAdminBotSetToken changes the bot, which is the owner's out-of-band
// approval channel: it needs step-up (approved by the current owner when a
// bot is set up), and the previous owner is told (ORC-L3).
func (s *server) handleAdminBotSetToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token   string `json:"token"`
		OwnerID int64  `json:"owner_id"`
		stepUpProof
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.stepUp(w, r, "bot_token_set", fmt.Sprintf("change the Telegram bot (new owner id %d)", req.OwnerID), req.stepUpProof) {
		return
	}
	s.notifyBotOwner(fmt.Sprintf("Telegram bot settings are being changed from the admin API (addr %s, new owner id %d). If this was not you, rotate the admin password.", clientIP(r), req.OwnerID))
	if err := s.store.setBotSettings(req.Token, req.OwnerID); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	if s.hasBotFactory() {
		if err := s.restartOptionalBot(s.baseContext()); err != nil {
			writeStoreError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.auditEvent(auditEntry{Event: "bot_token_set", IP: clientIP(r), Result: "ok", Fields: map[string]string{"owner_id": strconv.FormatInt(req.OwnerID, 10)}})
	writeJSON(w, map[string]any{"ok": true, "configured": true, "owner_id": req.OwnerID})
}

func (s *server) handleAdminTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID              string `json:"id"`
		Value           string `json:"value"`
		TTL             string `json:"ttl"`
		WorkerStaticPub string `json:"worker_static_pub"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.createToken(req.ID, req.Value, ttl, 1, req.WorkerStaticPub); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "enroll_token_create", IP: clientIP(r), Result: "ok", Fields: map[string]string{"id": req.ID, "ttl": ttl.String(), "pinned_worker": strconv.FormatBool(strings.TrimSpace(req.WorkerStaticPub) != "")}})
	fmt.Fprintf(w, "token_created id=%s ttl=%s max_uses=1\n", req.ID, ttl)
}

func (s *server) handleAdminBootstrapTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limits      json.RawMessage `json:"limits"`
		Expires     string          `json:"expires"`
		SeedWorkers []string        `json:"seed_workers"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	expiresAt, err := parseRFC3339Required(req.Expires)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	limits, err := parseBootstrapLimits(string(req.Limits))
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	pub, err := s.signerPublicKey()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	secret, err := randomTokenSecret()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	seedWorkers := req.SeedWorkers
	if len(seedWorkers) == 0 {
		seedWorkers = s.defaultSeedWorkers()
	}
	rec, err := s.store.createBootstrapToken(secret, expiresAt, limits, seedWorkers)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "bootstrap_token_create", IP: clientIP(r), Result: "ok", Fields: map[string]string{"id": rec.ID, "expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339)}})
	writeJSON(w, makeBootstrapPayload(s.cfg, pub, protocol.KeyToBase64(s.static.Public), secret, rec))
}

func (s *server) handleAdminBootstrapTokenQR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data string `json:"data"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	data := strings.TrimSpace(req.Data)
	if data == "" {
		writeError(w, "data is required", http.StatusBadRequest)
		return
	}
	if len(data) > 4096 {
		writeError(w, "data is too large for bootstrap QR", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(data, qrcode.Medium, 288)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{
		"ok":    true,
		"image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (s *server) defaultSeedWorkers() []string {
	workers, err := s.store.workers()
	if err != nil {
		return nil
	}
	return defaultSeedWorkersFromRecords(workers)
}

func defaultSeedWorkersFromRecords(workers []workerRecord) []string {
	seeds := make([]string, 0, len(workers))
	seen := map[string]bool{}
	now := time.Now().UTC()
	for _, rec := range workers {
		if rec.Disabled || (rec.Status != "approved" && rec.Status != "active") {
			continue
		}
		if !workerFreshForClients(rec, now) {
			continue
		}
		seed := seedWorkerURL(rec)
		if seed == "" || seen[seed] {
			continue
		}
		seen[seed] = true
		seeds = append(seeds, seed)
	}
	return seeds
}

func seedWorkerURL(rec workerRecord) string {
	if reality, ok := rec.SelfDescribe["reality"].(map[string]any); ok {
		address := stringFromMap(reality, "address")
		port := intFromMap(reality, "port", 0)
		if address != "" && port > 0 {
			return fmt.Sprintf("https://%s:%d/tw", address, port)
		}
	}
	if distributor := stringFromMap(rec.SelfDescribe, "distributor_url"); strings.HasPrefix(distributor, "https://") {
		return strings.TrimRight(distributor, "/")
	}
	return ""
}

func (s *server) handleAdminApproveWorker(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.approveWorker(req.ID); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_approve", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID}})
	fmt.Fprintf(w, "worker_approved id=%s\n", req.ID)
}

func (s *server) handleAdminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.revokeDevice(req.ID); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "device_revoke", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": req.ID}})
	fmt.Fprintf(w, "device_revoked id=%s\n", req.ID)
}

func (s *server) handleAdminDeleteDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.deleteDevice(req.ID); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "device_delete", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": req.ID}})
	fmt.Fprintf(w, "device_deleted id=%s\n", req.ID)
}

func (s *server) handleAdminDeviceAlias(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    string `json:"id"`
		Alias string `json:"alias"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	rec, err := s.store.setDeviceAlias(req.ID, req.Alias)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "device_alias", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": rec.ID}})
	writeJSON(w, map[string]any{"ok": true, "device_id": rec.ID, "alias": rec.Alias})
}

func (s *server) handleAdminWorkers(w http.ResponseWriter, r *http.Request) {
	workers, err := s.store.workers()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	items := make([]any, 0, len(workers))
	for _, worker := range workers {
		items = append(items, adminWorkerPayload(worker))
	}
	writeJSON(w, map[string]any{"ok": true, "workers": items})
}

func (s *server) handleAdminWorkerSetEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, "enabled is required", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{Enabled: req.Enabled}); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_set_enabled", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID, "enabled": strconv.FormatBool(*req.Enabled)}})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminWorkerProtocol(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
		Enabled  *bool  `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, "enabled is required", http.StatusBadRequest)
		return
	}
	protocol := normalizeProtocolName(req.Protocol)
	if protocol == "" {
		writeError(w, "unsupported protocol", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{Protocols: map[string]*bool{protocol: req.Enabled}}); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_protocol", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID, "protocol": protocol, "enabled": strconv.FormatBool(*req.Enabled)}})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.devices()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	telemetry, err := s.store.telemetrySnapshots()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	apkRelease, apkPublished, err := s.store.currentAPKRelease()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	items := make([]any, 0, len(devices))
	for _, device := range devices {
		live, hasLive := telemetry[device.ID]
		installedVersion, versionSource := resolveInstalledVersion(device, live, hasLive)
		updateAvailable, _ := computeUpdateAvailable(hasLive, live.ClientVC, apkPublished, apkRelease)
		items = append(items, map[string]any{
			"device_id":                device.ID,
			"alias":                    device.Alias,
			"status":                   device.Status,
			"client_version":           device.ClientVersion, // enroll-time snapshot kept for API compatibility
			"reality_flow":             device.RealityFlow,
			"reality_flow_pending":     device.RealityFlowPending,
			"client_version_code":      device.ClientVersionCode,
			"client_capabilities":      device.ClientCapabilities,
			"reality_cohort":           realityCohortIndex(device.ID, realityCohortSlots),
			"installed_version":        installedVersion,
			"installed_version_source": versionSource,
			"update_available":         updateAvailable,
			"model":                    device.Model,
			"android_id":               device.AndroidID,
			"enrolled_at":              device.CreatedAt.Format(time.RFC3339),
			"internal_ip":              device.InternalIP,
			"config_seq":               device.ConfigSeq,
			"telemetry":                adminTelemetryPayload(live, hasLive),
		})
	}
	writeJSON(w, map[string]any{"ok": true, "devices": items})
}

func (s *server) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	bundle, err := s.buildClientBundle()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	var parsed any
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &parsed); err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "bundle": bundle, "config": parsed})
}

func (s *server) handleAdminConfigEdit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Workers []struct {
			ID        string          `json:"id"`
			WorkerID  string          `json:"worker_id"`
			Enabled   *bool           `json:"enabled"`
			Priority  *int            `json:"priority"`
			Weight    *int            `json:"weight"`
			Protocols map[string]bool `json:"protocols"`
		} `json:"workers"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// The whole set is validated and applied in one transaction with one seq
	// bump: a bad entry leaves every worker unchanged (ORC-L14).
	updates := make([]workerPolicyUpdate, 0, len(req.Workers))
	for _, item := range req.Workers {
		id := item.WorkerID
		if id == "" {
			id = item.ID
		}
		protocols := map[string]*bool{}
		for key, value := range item.Protocols {
			enabled := value
			protocols[key] = &enabled
		}
		updates = append(updates, workerPolicyUpdate{ID: id, Patch: workerPolicyPatch{
			Enabled:   item.Enabled,
			Priority:  item.Priority,
			Weight:    item.Weight,
			Protocols: protocols,
		}})
	}
	if err := s.store.updateWorkerPolicies(updates); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	for _, update := range updates {
		s.auditEvent(auditEntry{Event: "worker_config_edit", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": update.ID}})
	}
	// An operator edit is published at once, without the confirmation delay.
	if _, err := s.refreshClientBundle(true); err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	bundle, err := s.buildClientBundle()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "bundle": bundle})
}

func (s *server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	workers, err := s.store.workers()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	if s.plaintextPublicListener() {
		// Added line; worker lines keep their format (P2).
		fmt.Fprintf(w, "warning=plaintext_public_listener listen=%s tls=false\n", s.cfg.Listen)
	}
	for _, worker := range workers {
		fmt.Fprintf(w, "worker=%s status=%s desired=%d applied=%d egress_ack=%s egress_probe=%s\n",
			worker.ID, worker.Status, worker.DesiredSeq, worker.AppliedSeq, worker.EgressIPObserved, worker.EgressIPProbe)
	}
}

func adminWorkerPayload(worker workerRecord) map[string]any {
	return map[string]any{
		"id":                      worker.ID,
		"status":                  worker.Status,
		"last_seen":               formatOptionalTime(worker.LastAckAt),
		"desired_seq":             worker.DesiredSeq,
		"applied_seq":             worker.AppliedSeq,
		"egress_ack":              worker.EgressIPObserved,
		"egress_probe":            worker.EgressIPProbe,
		"egress_seen":             worker.EgressIPSeen,
		"egress_check":            worker.EgressCheck,
		"enabled":                 !worker.Disabled,
		"priority":                effectiveWorkerPriority(worker),
		"weight":                  effectiveWorkerWeight(worker),
		"protocols":               map[string]bool{"reality": workerProtocolEnabled(worker, "reality"), "awg": workerProtocolEnabled(worker, "awg")},
		"self_describe":           worker.SelfDescribe,
		"self_check":              worker.SelfCheck,
		"self_describe_issues":    worker.SelfDescribeIssues,
		"self_describe_forbidden": worker.SelfDescribeForbidden,
		"self_check_at":           formatOptionalTime(worker.SelfCheckAt),
		"health":                  worker.SelfDescribe["health"],
		"revoked_short_ids":       normalizeShortIDs(worker.RevokedShortIDs),
		"draining_awg":            worker.DrainingAWGProfiles,
		"static_public_key8":      shortString(worker.StaticPublicKey, 8),
	}
}

func adminTelemetryPayload(rec telemetrySnapshotRecord, ok bool) map[string]any {
	if !ok || rec.DeviceID == "" {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled":        true,
		"device_id":      rec.DeviceID,
		"worker_id":      rec.WorkerID,
		"last_seen":      rec.ReceivedAt.UTC().Format(time.RFC3339),
		"client_version": rec.ClientVersion,
		"client_vc":      rec.ClientVC,
		"route":          rec.Route,
		"health":         rec.Health,
		"carry":          rec.Carry,
		"uptime_s":       rec.UptimeSeconds,
		"last_error":     rec.LastError,
		"recent":         rec.Recent,
	}
}
