package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestClientVersionCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "empty", in: "", want: 0},
		{name: "semver", in: "0.1.16", want: 116},
		{name: "v prefix", in: "v0.1.16", want: 116},
		{name: "embedded", in: "TrafficWrapper 0.1.16 (code 17)", want: 116},
		{name: "single code token", in: "code 17", want: 17},
		{name: "garbage", in: "not-a-version", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientVersionCode(tt.in); got != tt.want {
				t.Fatalf("clientVersionCode(%q)=%d want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestMinVersionFor(t *testing.T) {
	t.Setenv("FEATURE_MIN_VERSION_REALITY_FP_MODERN", "116")
	if got := minVersionFor("reality-fp-modern"); got != 116 {
		t.Fatalf("minVersionFor=%d want 116", got)
	}
	if got := minVersionFor("missing"); got != 0 {
		t.Fatalf("missing minVersionFor=%d want 0", got)
	}
	t.Setenv("FEATURE_MIN_VERSION_BAD", "not-int")
	if got := minVersionFor("bad"); got != 0 {
		t.Fatalf("bad minVersionFor=%d want 0", got)
	}
}

func TestRealityFingerprintForClientVersion(t *testing.T) {
	t.Setenv("REALITY_FP_DEFAULT", "chrome")
	t.Setenv("REALITY_FP_MODERN", "firefox")
	t.Setenv("REALITY_FP_MODERN_MIN_VC", "116")
	if got := realityFingerprintForClientVersion("0.1.15"); got != "chrome" {
		t.Fatalf("old client fp=%q want chrome", got)
	}
	if got := realityFingerprintForClientVersion("TrafficWrapper 0.1.16 (code 17)"); got != "firefox" {
		t.Fatalf("new client fp=%q want firefox", got)
	}
	t.Setenv("REALITY_FP_MODERN", "")
	if got := realityFingerprintForClientVersion("0.1.16"); got != "chrome" {
		t.Fatalf("empty modern fp=%q want chrome", got)
	}
	t.Setenv("REALITY_FP_MODERN", "firefox")
	t.Setenv("REALITY_FP_MODERN_MIN_VC", "0")
	if got := realityFingerprintForClientVersion("0.1.16"); got != "chrome" {
		t.Fatalf("min0 fp=%q want chrome", got)
	}
	t.Setenv("REALITY_FP_MODERN", "utls-modern")
	t.Setenv("REALITY_FP_MODERN_MIN_VC", "116")
	if got := realityFingerprintForClientVersion("0.1.16"); got != "chrome" {
		t.Fatalf("invalid modern fp=%q want chrome", got)
	}
	if got := clampRealityFingerprint(" Android "); got != "android" {
		t.Fatalf("clamp valid fp=%q want android", got)
	}
}

func TestBuildClientBundleRealityFingerprintVersionGate(t *testing.T) {
	t.Setenv("REALITY_FP_DEFAULT", "chrome")
	t.Setenv("REALITY_FP_MODERN", "firefox")
	t.Setenv("REALITY_FP_MODERN_MIN_VC", "116")
	s := newTestServer(t)
	addApprovedWorker(t, s)

	if got := clientBundleRealityFingerprint(t, s, "0.1.15"); got != "chrome" {
		t.Fatalf("old client fingerprint=%q want chrome", got)
	}
	if got := clientBundleRealityFingerprint(t, s, "TrafficWrapper 0.1.16 (code 17)"); got != "firefox" {
		t.Fatalf("new client fingerprint=%q want firefox", got)
	}
	t.Setenv("REALITY_FP_MODERN", "utls-modern")
	if got := clientBundleRealityFingerprint(t, s, "0.1.16"); got != "chrome" {
		t.Fatalf("invalid modern fingerprint=%q want chrome", got)
	}
	t.Setenv("REALITY_FP_MODERN", "")
	if got := clientBundleRealityFingerprint(t, s, "0.1.16"); got != "chrome" {
		t.Fatalf("modern empty fingerprint=%q want chrome", got)
	}
}

func TestBuildClientBundleDNSServers(t *testing.T) {
	s := newTestServer(t)
	s.cfg.DNSServers = []string{"1.1.1.1", "1.0.0.1"}
	addApprovedWorker(t, s)

	bundle, err := s.buildClientBundleForClient(0, "0.1.17")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		DNSServers []string `json:"dns_servers"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &root); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(root.DNSServers, s.cfg.DNSServers) {
		t.Fatalf("dns_servers=%v want %v", root.DNSServers, s.cfg.DNSServers)
	}
}

func clientBundleRealityFingerprint(t *testing.T, s *server, clientVersion string) string {
	t.Helper()
	bundle, err := s.buildClientBundleForClient(0, clientVersion)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Workers []struct {
			Routes []struct {
				Type   string         `json:"type"`
				Params map[string]any `json:"params"`
			} `json:"routes"`
		} `json:"workers"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &root); err != nil {
		t.Fatal(err)
	}
	for _, worker := range root.Workers {
		for _, route := range worker.Routes {
			if route.Type == "reality" {
				if value, _ := route.Params["fingerprint"].(string); value != "" {
					return value
				}
			}
		}
	}
	t.Fatalf("reality route fingerprint not found in %s", bundle.ConfigJSON)
	return ""
}
