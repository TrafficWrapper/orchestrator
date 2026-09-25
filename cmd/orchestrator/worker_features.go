package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Worker capabilities negotiated with TrafficWrapper/worker (see its
// ARCHITECTURE.md, "REALITY profiles, Vision and short ID cohorts").

const (
	// realityFlowVision is the XTLS Vision flow. Xray rejects a client whose
	// flow differs from its account, so a device only gets it when its app
	// declared the capability at enrollment.
	realityFlowVision = "xtls-rprx-vision"
	// capabilityRealityVision is what the app sends in enroll capabilities.
	capabilityRealityVision = "reality_vision"
	// realityCohortSlots is the number of cohort short IDs a worker publishes.
	realityCohortSlots = 16
)

// deviceRealityFlow picks the REALITY flow for a device from the
// capabilities its app declared.
func deviceRealityFlow(capabilities []string) string {
	for _, c := range capabilities {
		if strings.EqualFold(strings.TrimSpace(c), capabilityRealityVision) {
			return realityFlowVision
		}
	}
	return ""
}

// realityCohortIndex is the device's short ID cohort slot: the first four
// bytes of sha256(device_id) modulo the number of cohort slots. The app
// computes the same index over the worker's cohort_short_ids list.
func realityCohortIndex(deviceID string, slots int) int {
	if slots <= 0 {
		return -1
	}
	sum := sha256.Sum256([]byte(deviceID))
	return int(binary.BigEndian.Uint32(sum[:4]) % uint32(slots))
}

// clientCohortShortIDs returns the worker's cohort short IDs for the client
// bundle with revoked entries blanked (""), keeping every slot's position so
// revoking one cohort never moves devices between the others. A client whose
// slot is blank falls back to the base short_id.
func clientCohortShortIDs(rec workerRecord) []string {
	reality, ok := mapFromAny(rec.SelfDescribe["reality"])
	if !ok {
		return nil
	}
	raw, ok := reality["cohort_short_ids"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		id, _ := v.(string)
		id = strings.TrimSpace(id)
		if slices.Contains(rec.RevokedShortIDs, id) {
			id = ""
		}
		out = append(out, id)
	}
	return out
}

// rateMbpsFromLimit converts the operator's rate limit text ("20mbit",
// "512kbit", "1gbit", "50mbps") to megabits per second.
func rateMbpsFromLimit(rate string) (float64, bool) {
	rate = strings.ToLower(strings.TrimSpace(rate))
	if rate == "" {
		return 0, false
	}
	units := []struct {
		suffix string
		factor float64
	}{
		{"gbit", 1000}, {"gbps", 1000}, {"mbit", 1}, {"mbps", 1}, {"kbit", 0.001}, {"kbps", 0.001},
	}
	for _, u := range units {
		if number, ok := strings.CutSuffix(rate, u.suffix); ok {
			value, err := strconv.ParseFloat(strings.TrimSpace(number), 64)
			if err != nil || value <= 0 {
				return 0, false
			}
			return value * u.factor, true
		}
	}
	return 0, false
}

// maxWorkerRateMbps is the largest per-device shaping rate a worker accepts.
const maxWorkerRateMbps = 100000

// workerRateMbps rounds a rate up to whole Mbit/s for the worker, which treats
// 0 as unlimited, so sub-megabit limits become 1 rather than disappearing.
func workerRateMbps(mbps float64) int {
	return int(min(max(math.Ceil(mbps), 1), maxWorkerRateMbps))
}

// deviceLimitsPayload is the limits object sent to workers: the stored limits
// plus download_mbps/upload_mbps (whole Mbit/s) derived from the rate text for
// per-device AWG shaping.
func deviceLimitsPayload(limits deviceLimits) map[string]any {
	out := map[string]any{}
	if limits.TrafficQuotaBytes > 0 {
		out["traffic_quota_bytes"] = limits.TrafficQuotaBytes
	}
	if limits.RateLimit != "" {
		out["rate_limit"] = limits.RateLimit
		if mbps, ok := rateMbpsFromLimit(limits.RateLimit); ok {
			out["download_mbps"] = workerRateMbps(mbps)
			out["upload_mbps"] = workerRateMbps(mbps)
		}
	}
	if limits.ExpiresAt != nil {
		out["expires_at"] = *limits.ExpiresAt
	}
	return out
}

// workerDegraded reports whether the worker's last self-check (from ack) is
// degraded, and which checks failed.
func workerDegraded(rec workerRecord) (bool, string) {
	check := strings.TrimSpace(rec.SelfCheck)
	if rest, ok := strings.CutPrefix(check, "degraded"); ok {
		return true, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
	}
	return false, ""
}

func toggleString(list []string, value string, on bool) []string {
	value = strings.TrimSpace(value)
	out := slices.DeleteFunc(slices.Clone(list), func(v string) bool { return v == value })
	if on && value != "" {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func (s *server) handleAdminWorkerShortID(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string `json:"id"`
		ShortID string `json:"short_id"`
		Revoked *bool  `json:"revoked"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ShortID) == "" || req.Revoked == nil {
		writeError(w, "short_id and revoked are required", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{ShortID: req.ShortID, ShortIDRevoked: req.Revoked}); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_short_id", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID, "short_id": req.ShortID, "revoked": strconv.FormatBool(*req.Revoked)}})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminWorkerAWGDrain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Profile  string `json:"profile"`
		Draining *bool  `json:"draining"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	profile := normalizeAWGProfileName(req.Profile)
	if profile == "" || req.Draining == nil {
		writeError(w, "profile and draining are required", http.StatusBadRequest)
		return
	}
	if err := s.store.updateWorkerPolicy(req.ID, workerPolicyPatch{AWGProfile: profile, AWGProfileDraining: req.Draining}); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_awg_drain", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": req.ID, "profile": profile, "draining": strconv.FormatBool(*req.Draining)}})
	writeJSON(w, map[string]any{"ok": true})
}
