package main

import "testing"

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
	t.Setenv("REALITY_FP_MODERN", "utls-modern")
	t.Setenv("REALITY_FP_MODERN_MIN_VC", "116")
	if got := realityFingerprintForClientVersion("0.1.15"); got != "chrome" {
		t.Fatalf("old client fp=%q want chrome", got)
	}
	if got := realityFingerprintForClientVersion("TrafficWrapper 0.1.16 (code 17)"); got != "utls-modern" {
		t.Fatalf("new client fp=%q want utls-modern", got)
	}
	t.Setenv("REALITY_FP_MODERN", "")
	if got := realityFingerprintForClientVersion("0.1.16"); got != "chrome" {
		t.Fatalf("empty modern fp=%q want chrome", got)
	}
	t.Setenv("REALITY_FP_MODERN", "utls-modern")
	t.Setenv("REALITY_FP_MODERN_MIN_VC", "0")
	if got := realityFingerprintForClientVersion("0.1.16"); got != "chrome" {
		t.Fatalf("min0 fp=%q want chrome", got)
	}
}
