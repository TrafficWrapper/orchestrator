package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type workerTelemetryRequest struct {
	WorkerID      string            `json:"worker_id"`
	PayloadBase64 string            `json:"payload_base64"`
	Headers       map[string]string `json:"headers,omitempty"`
	ReceivedAt    string            `json:"received_at,omitempty"`
}

func (s *server) handleWorkerTelemetry(peer []byte, raw []byte) (any, error) {
	var req workerTelemetryRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return map[string]any{"ok": false, "error": "worker identity mismatch"}, nil
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
	if err != nil || len(payload) == 0 || len(payload) > telemetryMaxPayloadBytes || !json.Valid(payload) {
		return map[string]any{"ok": false, "error": "invalid telemetry payload"}, nil
	}
	deviceID := strings.TrimSpace(req.Headers["X-TW-Device"])
	if deviceID == "" {
		var root map[string]any
		if err := json.Unmarshal(payload, &root); err == nil {
			deviceID, _ = root["did"].(string)
		}
	}
	device, err := s.store.device(deviceID)
	if err != nil {
		return map[string]any{"ok": false, "error": "unknown device"}, nil
	}
	if device.Status != "approved" {
		return map[string]any{"ok": false, "error": "device is not approved"}, nil
	}
	claims, err := verifyTelemetrySignature(device, payload, req.Headers)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	if err := verifyTelemetryFreshness(claims.Timestamp, time.Now().UTC()); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	if !s.consumeTelemetryNonce(device.ID, claims.Nonce) {
		return map[string]any{"ok": false, "error": "telemetry replay detected"}, nil
	}
	snapshot, err := summarizeTelemetryPayload(device.ID, rec.ID, payload, req.ReceivedAt)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	if err := s.store.setTelemetrySnapshot(snapshot); err != nil {
		return nil, err
	}
	if _, err := s.store.updateDeviceClientVersionFromTelemetry(device.ID, snapshot.ClientVersion); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

type telemetrySignatureClaims struct {
	Timestamp time.Time
	Nonce     string
}

func verifyTelemetrySignature(device deviceRecord, payload []byte, headers map[string]string) (telemetrySignatureClaims, error) {
	deviceID := strings.TrimSpace(headers["X-TW-Device"])
	if deviceID == "" || deviceID != device.ID {
		return telemetrySignatureClaims{}, errors.New("telemetry device mismatch")
	}
	if strings.TrimSpace(headers["X-TW-KeyType"]) != "ecdsa-p256-sha256" {
		return telemetrySignatureClaims{}, errors.New("telemetry key type mismatch")
	}
	if strings.TrimSpace(headers["X-TW-Pub"]) != strings.TrimSpace(device.IdentityPubKey) {
		return telemetrySignatureClaims{}, errors.New("telemetry public key mismatch")
	}
	ts := strings.TrimSpace(headers["X-TW-Ts"])
	nonce := strings.TrimSpace(headers["X-TW-Nonce"])
	sigText := strings.TrimSpace(headers["X-TW-Sig"])
	if ts == "" || nonce == "" || sigText == "" {
		return telemetrySignatureClaims{}, errors.New("telemetry signature headers missing")
	}
	tsTime, err := parseTelemetryTimestamp(ts)
	if err != nil {
		return telemetrySignatureClaims{}, err
	}
	pubRaw, err := base64.StdEncoding.DecodeString(device.IdentityPubKey)
	if err != nil {
		return telemetrySignatureClaims{}, err
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubRaw)
	if err != nil {
		return telemetrySignatureClaims{}, err
	}
	pub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		return telemetrySignatureClaims{}, errors.New("telemetry public key is not ecdsa")
	}
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		return telemetrySignatureClaims{}, err
	}
	sum := sha256.Sum256(payload)
	canonical := strings.Join([]string{
		telemetrySignatureDomain,
		deviceID,
		ts,
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonical))
	if !ecdsa.VerifyASN1(pub, canonicalHash[:], sig) {
		return telemetrySignatureClaims{}, errors.New("telemetry signature invalid")
	}
	return telemetrySignatureClaims{Timestamp: tsTime, Nonce: nonce}, nil
}

func parseTelemetryTimestamp(value string) (time.Time, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return time.Time{}, errors.New("telemetry timestamp invalid")
	}
	if n > 1_000_000_000_000 {
		return time.UnixMilli(n).UTC(), nil
	}
	return time.Unix(n, 0).UTC(), nil
}

func verifyTelemetryFreshness(ts, now time.Time) error {
	if ts.IsZero() {
		return errors.New("telemetry timestamp invalid")
	}
	delta := now.Sub(ts)
	if delta < 0 {
		delta = -delta
	}
	if delta > telemetryMaxClockSkew {
		return errors.New("telemetry timestamp outside freshness window")
	}
	return nil
}

func (s *server) consumeTelemetryNonce(deviceID, nonce string) bool {
	deviceID = strings.TrimSpace(deviceID)
	nonce = strings.TrimSpace(nonce)
	if deviceID == "" || nonce == "" {
		return false
	}
	now := time.Now().UTC()
	s.telemetryNonceMu.Lock()
	defer s.telemetryNonceMu.Unlock()
	if s.telemetryNonces == nil {
		s.telemetryNonces = map[string]map[string]time.Time{}
	}
	deviceNonces := s.telemetryNonces[deviceID]
	if deviceNonces == nil {
		if len(s.telemetryNonces) >= telemetryNonceDeviceMax {
			for key := range s.telemetryNonces {
				delete(s.telemetryNonces, key)
				break
			}
		}
		deviceNonces = map[string]time.Time{}
		s.telemetryNonces[deviceID] = deviceNonces
	}
	if seenAt, exists := deviceNonces[nonce]; exists {
		if now.Sub(seenAt) <= 2*telemetryMaxClockSkew {
			return false
		}
		delete(deviceNonces, nonce)
	}
	if len(deviceNonces) >= telemetryNonceLRUMax {
		for key := range deviceNonces {
			delete(deviceNonces, key)
			break
		}
	}
	deviceNonces[nonce] = now
	return true
}

func summarizeTelemetryPayload(deviceID, workerID string, payload []byte, receivedAtRaw string) (telemetrySnapshotRecord, error) {
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return telemetrySnapshotRecord{}, err
	}
	if did, _ := root["did"].(string); strings.TrimSpace(did) != "" && strings.TrimSpace(did) != deviceID {
		return telemetrySnapshotRecord{}, errors.New("telemetry payload device mismatch")
	}
	receivedAt := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(receivedAtRaw)); err == nil {
		receivedAt = parsed.UTC()
	}
	rec := telemetrySnapshotRecord{
		DeviceID:      deviceID,
		WorkerID:      workerID,
		ReceivedAt:    receivedAt,
		SentAtMs:      int64FromAny(root["sent_at"]),
		ClientVersion: stringFromAny(root["ver"]),
		ClientVC:      int64FromAny(root["vc"]),
		Health:        "unknown",
		Fields:        map[string]string{},
	}
	events, _ := root["events"].([]any)
	if len(events) > 0 {
		start := len(events) - 5
		if start < 0 {
			start = 0
		}
		for _, rawEvent := range events[start:] {
			event, _ := rawEvent.(map[string]any)
			if len(event) == 0 {
				continue
			}
			kind := stringFromAny(event["k"])
			route := publicRouteLabel(firstNotBlank(stringFromAny(event["active_route"]), stringFromAny(event["route"])))
			status := telemetryEventStatus(event)
			errText := firstNotBlank(stringFromAny(event["err_kind"]), stringFromAny(event["err_where"]))
			if msg := stringFromAny(event["err_msg"]); msg != "" {
				errText = strings.TrimSpace(firstNotBlank(errText, "error") + ":" + msg)
			}
			rec.Recent = append(rec.Recent, telemetryEvent{
				Kind:   kind,
				AtMs:   int64FromAny(event["t"]),
				Route:  route,
				Status: status,
				Error:  errText,
			})
			if route != "" {
				rec.Route = route
			}
			if status != "" {
				rec.Health = status
			}
			if carryFromTelemetryEvent(event, rec.Route) {
				rec.Carry = true
			}
			if errText != "" {
				rec.LastError = errText
			}
			if mono := int64FromAny(event["mono"]); mono > 0 {
				rec.UptimeSeconds = mono / 1000
			}
		}
	}
	if rec.Route == "" {
		rec.Route = "-"
	}
	if rec.Carry && rec.Health == "unknown" {
		rec.Health = "healthy"
	}
	rec.Fields["event_count"] = strconv.Itoa(len(events))
	return rec, nil
}

func telemetryEventStatus(event map[string]any) string {
	healthy, healthyOK := boolFromAny(event["healthy"])
	stable, stableOK := boolFromAny(event["stable"])
	switch {
	case stableOK && stable:
		return "stable"
	case healthyOK && healthy:
		return "healthy"
	case healthyOK && !healthy:
		return "degraded"
	default:
		return ""
	}
}

func carryFromTelemetryEvent(event map[string]any, route string) bool {
	if stable, ok := boolFromAny(event["stable"]); ok && stable {
		return true
	}
	keys := []string{"rl2_carry", "rl_carry", "awgru_carry", "awg_carry"}
	switch route {
	case "REALITY-RU":
		keys = []string{"rl2_carry"}
	case "REALITY-TW":
		keys = []string{"rl_carry"}
	case "AWG-RU":
		keys = []string{"awgru_carry"}
	case "AWG-NL":
		keys = []string{"awg_carry"}
	}
	for _, key := range keys {
		if value, ok := boolFromAny(event[key]); ok && value {
			return true
		}
	}
	return false
}

func publicRouteLabel(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "REALITY2", "REALITY_RU", "REALITY-RU":
		return "REALITY-RU"
	case "REALITY", "REALITY_TW", "REALITY-TW":
		return "REALITY-TW"
	case "AWG_RU", "AWG-RU", "AWGRU", "AWG_RU_UPSTREAM", "AWG-RU-UPSTREAM":
		return "AWG-RU"
	case "AWG", "AWG_NL", "AWG-NL":
		return "AWG-NL"
	default:
		return strings.TrimSpace(value)
	}
}
