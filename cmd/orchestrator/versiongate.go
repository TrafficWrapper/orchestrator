package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

func clientVersionCode(clientVersion string) int {
	raw := strings.TrimSpace(clientVersion)
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			continue
		}
		j := i
		for j < len(raw) && ((raw[j] >= '0' && raw[j] <= '9') || raw[j] == '.') {
			j++
		}
		token := strings.Trim(raw[i:j], ".")
		if code := parseClientVersionToken(token); code > 0 {
			return code
		}
		i = j
	}
	return 0
}

func parseClientVersionToken(token string) int {
	token = strings.TrimSpace(strings.TrimPrefix(token, "v"))
	if token == "" {
		return 0
	}
	parts := strings.Split(token, ".")
	if len(parts) == 1 {
		value, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0
		}
		return value
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	minor := 0
	if len(parts) > 1 && parts[1] != "" {
		if minor, err = strconv.Atoi(parts[1]); err != nil {
			return 0
		}
	}
	patch := 0
	if len(parts) > 2 && parts[2] != "" {
		if patch, err = strconv.Atoi(parts[2]); err != nil {
			return 0
		}
	}
	return major*10000 + minor*100 + patch
}

func minVersionFor(feature string) int {
	name := strings.ToUpper(strings.TrimSpace(feature))
	if name == "" {
		return 0
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	value := strings.TrimSpace(os.Getenv("FEATURE_MIN_VERSION_" + b.String()))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func realityFingerprintDefault() string {
	if value := strings.TrimSpace(os.Getenv("REALITY_FP_DEFAULT")); value != "" {
		return clampRealityFingerprint(value)
	}
	return "chrome"
}

func realityFingerprintForClientVersion(clientVersion string) string {
	defaultFP := realityFingerprintDefault()
	modernFP := strings.TrimSpace(os.Getenv("REALITY_FP_MODERN"))
	minVC := getenvInt("REALITY_FP_MODERN_MIN_VC", 0)
	if modernFP == "" || minVC <= 0 {
		return defaultFP
	}
	if clientVersionCode(clientVersion) >= minVC {
		return clampRealityFingerprint(modernFP)
	}
	return defaultFP
}

func clampRealityFingerprint(value string) string {
	fp := strings.ToLower(strings.TrimSpace(value))
	switch fp {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return fp
	case "":
		return "chrome"
	default:
		log.Printf("invalid REALITY fingerprint %q; falling back to chrome", value)
		return "chrome"
	}
}
