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
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, ok, err := s.store.botSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

func (s *server) handleAdminBotSetToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token   string `json:"token"`
		OwnerID int64  `json:"owner_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.setBotSettings(req.Token, req.OwnerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.hasBotFactory() {
		if err := s.restartOptionalBot(s.baseContext()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.auditEvent(auditEntry{Event: "bot_token_set", IP: clientIP(r), Result: "ok", Fields: map[string]string{"owner_id": strconv.FormatInt(req.OwnerID, 10)}})
	writeJSON(w, map[string]any{"ok": true, "configured": true, "owner_id": req.OwnerID})
}

func (s *server) handleAdminTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID              string `json:"id"`
		Value           string `json:"value"`
		TTL             string `json:"ttl"`
		WorkerStaticPub string `json:"worker_static_pub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.createToken(req.ID, req.Value, ttl, 1, req.WorkerStaticPub); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "enroll_token_create", IP: clientIP(r), Result: "ok", Fields: map[string]string{"id": req.ID, "ttl": ttl.String(), "pinned_worker": strconv.FormatBool(strings.TrimSpace(req.WorkerStaticPub) != "")}})
	fmt.Fprintf(w, "token_created id=%s ttl=%s max_uses=1\n", req.ID, ttl)
}

func (s *server) handleAdminBootstrapTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Limits      json.RawMessage `json:"limits"`
		Expires     string          `json:"expires"`
		SeedWorkers []string        `json:"seed_workers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	expiresAt, err := parseRFC3339Required(req.Expires)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limits, err := parseJSONObjectRaw(string(req.Limits))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pub, err := s.signer.publicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secret, err := randomTokenSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	seedWorkers := req.SeedWorkers
	if len(seedWorkers) == 0 {
		seedWorkers = s.defaultSeedWorkers()
	}
	rec, err := s.store.createBootstrapToken(secret, expiresAt, limits, seedWorkers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "bootstrap_token_create", IP: clientIP(r), Result: "ok", Fields: map[string]string{"id": rec.ID, "expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339)}})
	writeJSON(w, makeBootstrapPayload(s.cfg, pub, protocol.KeyToBase64(s.static.Public), secret, rec))
}

func (s *server) handleAdminBootstrapTokenQR(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data := strings.TrimSpace(req.Data)
	if data == "" {
		http.Error(w, "data is required", http.StatusBadRequest)
		return
	}
	if len(data) > 4096 {
		http.Error(w, "data is too large for bootstrap QR", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(data, qrcode.Medium, 288)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.approveWorker(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_approve", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID}})
	fmt.Fprintf(w, "worker_approved id=%s\n", req.ID)
}

func (s *server) handleAdminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.revokeDevice(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "device_revoke", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": req.ID}})
	fmt.Fprintf(w, "device_revoked id=%s\n", req.ID)
}

func (s *server) handleAdminDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.deleteDevice(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditEvent(auditEntry{Event: "device_delete", IP: clientIP(r), Result: "ok", Fields: map[string]string{"device_id": req.ID}})
	fmt.Fprintf(w, "device_deleted id=%s\n", req.ID)
}

func (s *server) handleAdminDeviceAlias(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID    string `json:"id"`
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.store.setDeviceAlias(req.ID, req.Alias)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "device_id": rec.ID, "alias": rec.Alias})
}

func (s *server) handleAdminWorkers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	workers, err := s.store.workers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items := make([]any, 0, len(workers))
	for _, worker := range workers {
		items = append(items, adminWorkerPayload(worker))
	}
	writeJSON(w, map[string]any{"ok": true, "workers": items})
}

func (s *server) handleAdminWorkerSetEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "enabled is required", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{Enabled: req.Enabled}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminWorkerProtocol(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "enabled is required", http.StatusBadRequest)
		return
	}
	protocol := normalizeProtocolName(req.Protocol)
	if protocol == "" {
		http.Error(w, "unsupported protocol", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{Protocols: map[string]*bool{protocol: req.Enabled}}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices, err := s.store.devices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	telemetry, err := s.store.telemetrySnapshots()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	apkRelease, apkPublished, err := s.store.currentAPKRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := s.buildClientBundle(0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var parsed any
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &parsed); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "bundle": bundle, "config": parsed})
}

func (s *server) handleAdminConfigEdit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
		if err := s.store.updateWorkerPolicy(id, workerPolicyPatch{
			Enabled:   item.Enabled,
			Priority:  item.Priority,
			Weight:    item.Weight,
			Protocols: protocols,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	bundle, err := s.buildClientBundle(0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "bundle": bundle})
}

func (s *server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	workers, err := s.store.workers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, worker := range workers {
		fmt.Fprintf(w, "worker=%s status=%s desired=%d applied=%d egress_ack=%s egress_probe=%s\n",
			worker.ID, worker.Status, worker.DesiredSeq, worker.AppliedSeq, worker.EgressIPObserved, worker.EgressIPProbe)
	}
}

func adminWorkerPayload(worker workerRecord) map[string]any {
	return map[string]any{
		"id":                 worker.ID,
		"status":             worker.Status,
		"last_seen":          formatOptionalTime(worker.LastAckAt),
		"desired_seq":        worker.DesiredSeq,
		"applied_seq":        worker.AppliedSeq,
		"egress_ack":         worker.EgressIPObserved,
		"egress_probe":       worker.EgressIPProbe,
		"enabled":            !worker.Disabled,
		"priority":           effectiveWorkerPriority(worker),
		"weight":             effectiveWorkerWeight(worker),
		"protocols":          map[string]bool{"reality": workerProtocolEnabled(worker, "reality"), "awg": workerProtocolEnabled(worker, "awg")},
		"self_describe":      worker.SelfDescribe,
		"static_public_key8": shortString(worker.StaticPublicKey, 8),
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
