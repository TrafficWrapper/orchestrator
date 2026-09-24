package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type signedConfig struct {
	ConfigJSON   string `json:"config_json,omitempty"`
	Minisig      string `json:"minisig,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

func (s *server) buildBundles(rec workerRecord) (signedConfig, signedConfig, error) {
	issued := time.Now().UTC()
	approvedDevices, err := s.store.approvedDevices()
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	workerPayload := map[string]any{
		"schema":    1,
		"ns":        "worker-config-v1",
		"seq":       rec.DesiredSeq,
		"worker_id": rec.ID,
		"issued_at": issued.Format(time.RFC3339),
		"desired_state": map[string]any{
			"reality":          map[string]any{"enabled": !rec.Disabled && workerProtocolEnabled(rec, "reality"), "public": rec.SelfDescribe["reality"]},
			"awg":              map[string]any{"enabled": !rec.Disabled && workerProtocolEnabled(rec, "awg"), "public": rec.SelfDescribe["awg"]},
			"egress_policy":    "direct",
			"approved_devices": approvedDevicePayloads(approvedDevices),
			"client_artifacts": map[string]any{"config_json_path": "/tw/config.json", "version_json_path": "/tw/version.json"},
		},
	}
	workerJSON, err := canonicalJSON(workerPayload)
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	workerSigned, err := s.signer.sign(workerJSON)
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	clientSigned, err := s.buildClientBundle(rec.DesiredSeq)
	if err != nil {
		return signedConfig{}, signedConfig{}, err
	}
	return workerSigned, clientSigned, nil
}

func (s *server) buildClientBundle(minSeq int64) (signedConfig, error) {
	return s.buildClientBundleForClient(minSeq, "")
}

func (s *server) buildClientBundleForClient(minSeq int64, clientVersion string) (signedConfig, error) {
	workers, err := s.store.workers()
	if err != nil {
		return signedConfig{}, err
	}
	issued := time.Now().UTC()
	seq := minSeq
	var items []any
	for _, rec := range workers {
		if rec.Status != "approved" && rec.Status != "active" {
			continue
		}
		if rec.DesiredSeq > seq {
			seq = rec.DesiredSeq
		}
		if rec.Disabled {
			continue
		}
		if !workerFreshForClients(rec, issued) {
			continue
		}
		item, ok := clientWorkerPayloadForClient(rec, clientVersion)
		if ok {
			items = append(items, item)
		}
	}
	if seq < 1 {
		seq = 1
	}
	clientPayload := map[string]any{
		"schema":     1,
		"ns":         "client-config-v1",
		"seq":        seq,
		"issued_at":  issued.Format(time.RFC3339),
		"expires_at": issued.Add(24 * time.Hour).Format(time.RFC3339),
		"workers":    items,
	}
	if strings.TrimSpace(s.cfg.UpdatePublicKey) != "" {
		clientPayload["update_pubkey"] = strings.TrimSpace(s.cfg.UpdatePublicKey)
	}
	if pub := s.discoveryPublicKey(); pub != "" {
		clientPayload["discovery_pubkey"] = pub
	}
	if len(s.cfg.DiscoveryRescuePointers) > 0 {
		clientPayload["discovery_rescue_pointers"] = append([]string(nil), s.cfg.DiscoveryRescuePointers...)
	}
	if len(s.cfg.DNSServers) > 0 {
		clientPayload["dns_servers"] = append([]string(nil), s.cfg.DNSServers...)
	}
	clientJSON, err := canonicalJSON(clientPayload)
	if err != nil {
		return signedConfig{}, err
	}
	if err := rejectForbiddenKeys([]byte(clientJSON)); err != nil {
		return signedConfig{}, err
	}
	return s.signer.sign(clientJSON)
}

func clientWorkerPayload(rec workerRecord) (map[string]any, bool) {
	return clientWorkerPayloadForClient(rec, "")
}

func clientWorkerPayloadForClient(rec workerRecord, clientVersion string) (map[string]any, bool) {
	expected := workerEgressIP(rec)
	configURL := stringFromMap(rec.SelfDescribe, "distributor_url")
	routes := make([]any, 0, 2)
	if workerProtocolEnabled(rec, "reality") {
		if route, ok := clientRoutePayloadForClient("reality", rec.SelfDescribe["reality"], expected, configURL, clientVersion); ok {
			routes = append(routes, route)
		}
	}
	if workerProtocolEnabled(rec, "awg") {
		if profile, ok := selectAWGProfileForClient(awgProfilesFromWorker(rec), clientVersion); ok {
			if route, ok := clientRoutePayload("awg", profile.Params, expected, configURL); ok {
				route["profile"] = profile.Name
				route["awg_profile"] = profile.Name
				routes = append(routes, route)
			}
		} else if route, ok := clientRoutePayload("awg", rec.SelfDescribe["awg"], expected, configURL); ok {
			routes = append(routes, route)
		}
	}
	if len(routes) == 0 {
		return nil, false
	}
	return map[string]any{
		"worker_id": rec.ID,
		"label":     stringFromMap(rec.SelfDescribe, "label"),
		"priority":  effectiveWorkerPriority(rec),
		"weight":    effectiveWorkerWeight(rec),
		"routes":    routes,
	}, true
}

func effectiveWorkerPriority(rec workerRecord) int {
	if rec.ConfigPriority != nil {
		return *rec.ConfigPriority
	}
	return intFromMap(rec.SelfDescribe, "priority", 10)
}

func effectiveWorkerWeight(rec workerRecord) int {
	if rec.ConfigWeight != nil {
		return *rec.ConfigWeight
	}
	return intFromMap(rec.SelfDescribe, "weight", 100)
}

func workerProtocolEnabled(rec workerRecord, protocolName string) bool {
	normalized := normalizeProtocolName(protocolName)
	if normalized == "" {
		return false
	}
	if rec.ProtocolEnabled == nil {
		return true
	}
	enabled, ok := rec.ProtocolEnabled[normalized]
	if !ok {
		return true
	}
	return enabled
}

func clientRoutePayload(routeType string, raw any, expected, configURL string) (map[string]any, bool) {
	return clientRoutePayloadForClient(routeType, raw, expected, configURL, "")
}

func clientRoutePayloadForClient(routeType string, raw any, expected, configURL, clientVersion string) (map[string]any, bool) {
	params, ok := raw.(map[string]any)
	if !ok || len(params) == 0 {
		return nil, false
	}
	routeParams := canonicalClientRouteParamsForClient(routeType, params, clientVersion)
	route := cloneMap(routeParams)
	route["type"] = routeType
	route["enabled"] = true
	route["egress_ip"] = expected
	route["expected_egress_ip"] = expected
	if configURL != "" {
		route["config_url"] = strings.TrimRight(configURL, "/")
	}
	if _, ok := route["address"].(string); !ok {
		if endpoint := stringFromMap(params, "endpoint"); endpoint != "" {
			host, _, _ := strings.Cut(endpoint, ":")
			route["address"] = host
		}
	}
	if _, ok := route["port"]; !ok {
		if endpoint := stringFromMap(params, "endpoint"); endpoint != "" {
			_, portText, _ := strings.Cut(endpoint, ":")
			if port, err := strconv.Atoi(portText); err == nil {
				route["port"] = port
			}
		}
	}
	if _, ok := route["dialect_id"].(string); !ok {
		route["dialect_id"] = dialectID(routeParams)
	}
	if region := firstStringFromMap(routeParams, "region"); region != "" {
		route["region"] = region
	}
	route["params"] = routeParams
	return route, true
}

func canonicalClientRouteParams(routeType string, params map[string]any) map[string]any {
	return canonicalClientRouteParamsForClient(routeType, params, "")
}

func canonicalClientRouteParamsForClient(routeType string, params map[string]any, clientVersion string) map[string]any {
	out := cloneMap(params)
	switch normalizeProtocolName(routeType) {
	case "reality":
		copyFirstString(out, "public_key", params, "public_key", "publicKey")
		copyFirstString(out, "publicKey", params, "publicKey", "public_key")
		copyFirstString(out, "short_id", params, "short_id", "shortId")
		copyFirstString(out, "shortId", params, "shortId", "short_id")
		copyFirstString(out, "server_name", params, "server_name", "serverName", "sni")
		copyFirstString(out, "serverName", params, "serverName", "server_name", "sni")
		if firstStringFromMap(params, "security") == "" {
			out["security"] = "reality"
		}
		if firstStringFromMap(params, "network") == "" {
			out["network"] = "tcp"
		}
		if strings.EqualFold(firstStringFromMap(out, "network"), "xhttp") {
			delete(out, "flow")
			normalizeClientXHTTPParams(out)
		}
		fingerprint := firstStringFromMap(params, "fingerprint")
		if fingerprint == "" {
			fingerprint = realityFingerprintForClientVersion(clientVersion)
		}
		out["fingerprint"] = clampRealityFingerprint(fingerprint)
		if firstStringFromMap(params, "spiderX") == "" {
			out["spiderX"] = "/"
		}
	case "awg":
		copyFirstString(out, "public_key", params, "public_key", "server_public", "server_public_key")
		copyFirstString(out, "server_public", params, "server_public", "public_key", "server_public_key")
		copyFirstString(out, "server_public_key", params, "server_public_key", "public_key", "server_public")
		if firstStringFromMap(params, "dialect_id") == "" {
			out["dialect_id"] = dialectID(out)
		}
	}
	return out
}

func normalizeClientXHTTPParams(params map[string]any) {
	raw, ok := params["xhttp"].(map[string]any)
	if !ok {
		return
	}
	xhttp := cloneMap(raw)
	delete(xhttp, "host")
	mode := firstStringFromMap(xhttp, "mode")
	if mode == "" || strings.EqualFold(mode, "auto") {
		xhttp["mode"] = "stream-up"
	}
	params["xhttp"] = xhttp
}

func approvedDevicePayloads(devices []deviceRecord) []any {
	out := make([]any, 0, len(devices))
	for _, device := range devices {
		payload := map[string]any{
			"device_id":      device.ID,
			"reality_uuid":   device.RealityUUID,
			"awg_public_key": device.AWGPublicKey,
			"internal_ip":    device.InternalIP,
			"psk2":           device.PSK2,
			"status":         device.Status,
		}
		if len(device.AWGProfiles) > 0 {
			payload["awg_profiles"] = device.AWGProfiles
		}
		if !deviceLimitsEmpty(device.Limits) {
			payload["limits"] = device.Limits
			if device.Limits.ExpiresAt != nil && strings.TrimSpace(*device.Limits.ExpiresAt) != "" {
				payload["expires_at"] = strings.TrimSpace(*device.Limits.ExpiresAt)
			}
		}
		out = append(out, payload)
	}
	return out
}

func workerAWGSubnet(workers []workerRecord) string {
	return baseAWGSubnet(workerAWGProfiles(workers))
}

func workerAWGPublicKey(workers []workerRecord) string {
	return workerAWGPublicKeyFromProfiles(workerAWGProfiles(workers))
}

func workerAWGPublicKeyFromProfiles(profiles []awgProfile) string {
	if profile, ok := selectAWGProfileForClient(profiles, ""); ok && profile.ServerPublicKey != "" {
		return profile.ServerPublicKey
	}
	for _, profile := range profiles {
		if profile.ServerPublicKey != "" {
			return profile.ServerPublicKey
		}
	}
	return ""
}

func rejectForbiddenKeys(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	forbidden := map[string]struct{}{"private_key": {}, "privatekey": {}, "psk2": {}, "internal_ip": {}, "internalip": {}, "server_private_key": {}}
	var walk func(any, string) error
	walk = func(v any, path string) error {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				n := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
				if _, ok := forbidden[n]; ok {
					return fmt.Errorf("forbidden config field: %s%s", path, k)
				}
				if err := walk(child, path+k+"."); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range x {
				if err := walk(child, fmt.Sprintf("%s[%d].", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, "")
}

func workerFreshForClients(rec workerRecord, now time.Time) bool {
	if rec.LastAckAt != nil {
		return now.Sub(rec.LastAckAt.UTC()) <= workerFreshTTL
	}
	if rec.ApprovedAt != nil {
		return now.Sub(rec.ApprovedAt.UTC()) <= workerFreshTTL
	}
	return now.Sub(rec.CreatedAt.UTC()) <= workerFreshTTL
}

func canonicalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
