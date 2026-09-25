package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Worker self_describe v1 (see ARCHITECTURE "Worker self_describe contract").
// Everything a worker reports is untrusted: it is sanitized once on intake
// (enroll, nudge, ack) and the stored copy is what bundles are built from.
const (
	selfDescribeMaxBytes    = 64 << 10
	selfDescribeMaxString   = 256
	selfDescribeMaxProfiles = 32
	selfDescribeMaxDepth    = 8
	selfDescribeMaxCaps     = 32
	selfDescribeMaxCapLen   = 64
)

// selfDescribeTopLevelKeys is the allowlist of top-level self_describe keys.
// Unknown keys are dropped without rejecting the worker; priority, weight,
// label and region are operator-only and never taken from a worker.
var selfDescribeTopLevelKeys = map[string]struct{}{
	"schema": {}, "hostname": {}, "egress_ip": {}, "orch_url": {}, "agent_url": {},
	"distributor_url": {}, "standalone": {}, "dialect_id": {}, "capacity": {},
	"protocols": {}, "reality": {}, "reality_profiles": {}, "awg": {},
	"awg_profiles": {}, "health": {}, "orchestrator": {}, "distributed_apk": {},
	"capabilities": {},
}

// forbiddenConfigKeys must never appear anywhere in a client bundle.
var forbiddenConfigKeys = map[string]struct{}{
	"private_key": {}, "privatekey": {}, "psk2": {}, "internal_ip": {},
	"internalip": {}, "server_private_key": {},
}

func isForbiddenConfigKey(key string) bool {
	_, ok := forbiddenConfigKeys[strings.ToLower(strings.ReplaceAll(key, "-", "_"))]
	return ok
}

// findForbiddenKey reports the path of the first forbidden key in v. The path
// is only built on the way back up from a hit, so a clean tree costs one walk
// with no per-key string copies.
func findForbiddenKey(v any) (string, bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if isForbiddenConfigKey(k) {
				return k, true
			}
			if rest, ok := findForbiddenKey(child); ok {
				return k + "." + rest, true
			}
		}
	case []any:
		for i, child := range x {
			if rest, ok := findForbiddenKey(child); ok {
				return "[" + strconv.Itoa(i) + "]." + rest, true
			}
		}
	}
	return "", false
}

// selfDescribeReport is what sanitization found. Forbidden means the worker
// sent a secret-looking key: it is stripped and the worker is kept out of
// client bundles until it reports a clean self_describe.
type selfDescribeReport struct {
	Issues    []string
	Forbidden bool
	// Rejected means the whole update was unusable (too large or not an
	// object); the previously stored self_describe stays in effect.
	Rejected bool
}

func (r *selfDescribeReport) add(format string, args ...any) {
	if len(r.Issues) < 32 {
		r.Issues = append(r.Issues, fmt.Sprintf(format, args...))
	}
}

// sanitizeSelfDescribe returns a copy of raw restricted to the self_describe
// contract. Malformed sections are kept and reported (alert, not silent
// drop), except for what could hurt other workers or clients: forbidden keys,
// oversized strings or lists, unknown top-level keys and wrong types.
func sanitizeSelfDescribe(raw map[string]any) (map[string]any, selfDescribeReport) {
	var report selfDescribeReport
	if raw == nil {
		return nil, report
	}
	if encoded, err := json.Marshal(raw); err != nil || len(encoded) > selfDescribeMaxBytes {
		report.Rejected = true
		report.add("self_describe larger than %d bytes or not encodable", selfDescribeMaxBytes)
		return nil, report
	}
	out := make(map[string]any, len(raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := raw[key]
		if _, ok := selfDescribeTopLevelKeys[key]; !ok {
			if isForbiddenConfigKey(key) {
				report.Forbidden = true
				report.add("forbidden key %s", key)
			}
			continue
		}
		clean, ok := sanitizeSelfDescribeValue(value, key, 1, &report)
		if !ok {
			continue
		}
		switch key {
		case "schema", "hostname", "orch_url", "agent_url", "dialect_id":
			if _, isString := clean.(string); !isString {
				report.add("%s: want string", key)
				continue
			}
		case "egress_ip":
			text, isString := clean.(string)
			if !isString {
				report.add("egress_ip: want string")
				continue
			}
			if text != "" {
				if _, err := netip.ParseAddr(text); err != nil {
					report.add("egress_ip: not an IP address")
					continue
				}
			}
		case "distributor_url":
			text, isString := clean.(string)
			if !isString {
				report.add("distributor_url: want string")
				continue
			}
			// config_url is built from it, so a surprising value only alerts.
			if text != "" && !validDistributorURL(text) {
				report.add("distributor_url: unexpected host or scheme")
			}
		case "standalone":
			if _, isBool := clean.(bool); !isBool {
				report.add("standalone: want bool")
				continue
			}
		case "capacity":
			if _, isNumber := clean.(float64); !isNumber {
				if _, isInt := clean.(int); !isInt {
					report.add("capacity: want number")
					continue
				}
			}
		case "protocols":
			list, ok := stringList(clean)
			if !ok {
				report.add("protocols: want string list")
				continue
			}
			clean = list
		case "capabilities":
			clean = sanitizeCapabilities(clean, &report)
		case "reality", "awg", "health", "orchestrator", "distributed_apk":
			section, isMap := clean.(map[string]any)
			if !isMap {
				report.add("%s: want object", key)
				continue
			}
			switch key {
			case "reality":
				validateRealitySection("reality", section, &report)
			case "awg":
				validateAWGSection("awg", section, &report)
			case "distributed_apk":
				validateDistributedAPK(section, &report)
			}
		case "reality_profiles", "awg_profiles":
			list, isList := clean.([]any)
			if !isList {
				report.add("%s: want list", key)
				continue
			}
			if len(list) > selfDescribeMaxProfiles {
				report.add("%s: more than %d profiles, extra dropped", key, selfDescribeMaxProfiles)
				list = list[:selfDescribeMaxProfiles]
			}
			profiles := make([]any, 0, len(list))
			for i, item := range list {
				profile, isMap := item.(map[string]any)
				if !isMap {
					report.add("%s[%d]: want object", key, i)
					continue
				}
				name := fmt.Sprintf("%s[%d]", key, i)
				if key == "reality_profiles" {
					validateRealitySection(name, profile, &report)
				} else {
					validateAWGSection(name, profile, &report)
				}
				profiles = append(profiles, profile)
			}
			clean = profiles
		}
		out[key] = clean
	}
	return out, report
}

// sanitizeSelfDescribeValue deep-copies v, dropping forbidden keys, strings
// longer than selfDescribeMaxString and anything nested too deep. ok=false
// drops v itself.
func sanitizeSelfDescribeValue(v any, path string, depth int, report *selfDescribeReport) (any, bool) {
	if depth > selfDescribeMaxDepth {
		report.add("%s: nested too deep", path)
		return nil, false
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			if isForbiddenConfigKey(k) {
				report.Forbidden = true
				report.add("forbidden key %s.%s", path, k)
				continue
			}
			if len(k) > selfDescribeMaxString {
				report.add("%s: key too long", path)
				continue
			}
			if clean, ok := sanitizeSelfDescribeValue(child, path+"."+k, depth+1, report); ok {
				out[k] = clean
			}
		}
		return out, true
	case []any:
		if len(x) > 256 {
			report.add("%s: list too long", path)
			return nil, false
		}
		out := make([]any, 0, len(x))
		for i, child := range x {
			if clean, ok := sanitizeSelfDescribeValue(child, path+"["+strconv.Itoa(i)+"]", depth+1, report); ok {
				out = append(out, clean)
			}
		}
		return out, true
	case []string:
		items := make([]any, len(x))
		for i, s := range x {
			items[i] = s
		}
		return sanitizeSelfDescribeValue(items, path, depth, report)
	case string:
		if len(x) > selfDescribeMaxString {
			// Probe diagnostics carry free-form error text: cut, don't alert.
			if strings.HasPrefix(path, "health.") {
				return truncateRunes(x, selfDescribeMaxString/4), true
			}
			report.add("%s: string longer than %d", path, selfDescribeMaxString)
			return nil, false
		}
		return x, true
	case map[string]string:
		items := make(map[string]any, len(x))
		for k, s := range x {
			items[k] = s
		}
		return sanitizeSelfDescribeValue(items, path, depth, report)
	case nil, bool, float64, int, int64, json.Number:
		return x, true
	default:
		// Only JSON-decoded values reach here in production; re-decode
		// anything else (tests pass Go literals) through JSON.
		raw, err := json.Marshal(x)
		if err != nil {
			return nil, false
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, false
		}
		return sanitizeSelfDescribeValue(decoded, path, depth, report)
	}
}

func stringList(v any) ([]any, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	for _, item := range list {
		if _, isString := item.(string); !isString {
			return nil, false
		}
	}
	return list, true
}

func sanitizeCapabilities(v any, report *selfDescribeReport) []any {
	list, ok := v.([]any)
	if !ok {
		report.add("capabilities: want string list")
		return []any{}
	}
	out := make([]any, 0, len(list))
	for _, item := range list {
		text, isString := item.(string)
		text = strings.TrimSpace(text)
		if !isString || text == "" || len(text) > selfDescribeMaxCapLen {
			continue
		}
		if slices.Contains(out, any(text)) {
			continue
		}
		if len(out) == selfDescribeMaxCaps {
			report.add("capabilities: more than %d entries, extra dropped", selfDescribeMaxCaps)
			break
		}
		out = append(out, text)
	}
	return out
}

// validateRealitySection reports (but keeps) malformed REALITY fields.
func validateRealitySection(name string, section map[string]any, report *selfDescribeReport) {
	if address := stringFromMap(section, "address"); address != "" && !validHostOrIP(address) {
		report.add("%s.address: not a hostname or IP", name)
	}
	if v6 := stringFromMap(section, "address_v6"); v6 != "" {
		if addr, err := netip.ParseAddr(v6); err != nil || !addr.Is6() {
			report.add("%s.address_v6: not an IPv6 address", name)
		}
	}
	validatePortField(name, section, report)
	for _, key := range []string{"public_key", "publicKey"} {
		if key64 := stringFromMap(section, key); key64 != "" && !validRealityPublicKey(key64) {
			report.add("%s.%s: not a 32-byte base64 key", name, key)
		}
	}
}

// validateAWGSection reports (but keeps) malformed AWG fields.
func validateAWGSection(name string, section map[string]any, report *selfDescribeReport) {
	for _, key := range []string{"address"} {
		if address := stringFromMap(section, key); address != "" && !validHostOrIP(address) {
			report.add("%s.%s: not a hostname or IP", name, key)
		}
	}
	if endpoint := stringFromMap(section, "endpoint"); endpoint != "" && !validHostPort(endpoint) {
		report.add("%s.endpoint: not host:port", name)
	}
	if endpoint := stringFromMap(section, "endpoint_v6"); endpoint != "" && !validHostPort(endpoint) {
		report.add("%s.endpoint_v6: not [v6]:port", name)
	}
	validatePortField(name, section, report)
	for _, key := range []string{"public_key", "server_public", "server_public_key"} {
		if key64 := stringFromMap(section, key); key64 != "" && !validStdBase64Key(key64) {
			report.add("%s.%s: not a 32-byte base64 key", name, key)
		}
	}
	if subnet := stringFromMap(section, "subnet"); subnet != "" {
		if _, err := validAWGSubnet(subnet); err != nil {
			report.add("%s.subnet: %v", name, err)
		}
	}
}

func validateDistributedAPK(section map[string]any, report *selfDescribeReport) {
	if sha := stringFromMap(section, "apk_sha256"); sha != "" {
		if raw, err := hex.DecodeString(sha); err != nil || len(raw) != 32 {
			report.add("distributed_apk.apk_sha256: not a sha256 hex digest")
		}
	}
}

func validatePortField(name string, section map[string]any, report *selfDescribeReport) {
	raw, ok := section["port"]
	if !ok {
		return
	}
	port, isNumber := raw.(float64)
	if isInt, ok := raw.(int); ok {
		port, isNumber = float64(isInt), true
	}
	if !isNumber || port != float64(int(port)) || port < 1 || port > 65535 {
		report.add("%s.port: not in 1..65535", name)
	}
}

func validHostOrIP(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return validHostname(host)
}

func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validHostPort(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || !validHostOrIP(host) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// validRealityPublicKey accepts the X25519 key encodings workers use:
// unpadded RawURL base64 (Xray's own form) or padded URL base64.
func validRealityPublicKey(value string) bool {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if raw, err := enc.DecodeString(value); err == nil && len(raw) == 32 {
			return true
		}
	}
	return false
}

func validStdBase64Key(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == 32
}

// validAWGSubnet accepts a private IPv4 pool large enough to be useful and
// small enough to bound allocation scans.
func validAWGSubnet(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not a CIDR prefix")
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("not IPv4")
	}
	if !prefix.Addr().IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(prefix.Addr()) {
		return netip.Prefix{}, fmt.Errorf("not a private range")
	}
	if prefix.Bits() > 26 || prefix.Bits() < 16 {
		return netip.Prefix{}, fmt.Errorf("size must be /16../26")
	}
	return prefix, nil
}

// validDistributorURL matches what workers use for their distributor: an
// http(s) URL on a single-label name (default http://awg-gw:8080/tw), a
// private, loopback, ULA or CGNAT address, or an https URL.
func validDistributorURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsPrivate() || addr.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
	}
	return validHostname(host) && !strings.Contains(host, ".")
}

// selfDescribeIssuesSummary is the short form shown in alerts and admin.
func selfDescribeIssuesSummary(issues []string) string {
	if len(issues) == 0 {
		return ""
	}
	summary := strings.Join(issues[:min(len(issues), 3)], "; ")
	if len(issues) > 3 {
		summary += fmt.Sprintf(" (+%d more)", len(issues)-3)
	}
	return summary
}
