package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func TestEgressCheckClassification(t *testing.T) {
	for _, tc := range []struct {
		declared, seen, probe, want string
	}{
		{"203.0.113.5", "203.0.113.5", "", egressCheckMatch},
		{"203.0.113.5", "198.51.100.9", "", egressCheckMismatch},
		{"203.0.113.5", "::ffff:203.0.113.5", "", egressCheckMatch},
		// Private, loopback and docker sources are not evidence.
		{"203.0.113.5", "172.17.0.2", "", egressCheckNA},
		{"203.0.113.5", "127.0.0.1", "", egressCheckNA},
		{"203.0.113.5", "100.64.1.1", "", egressCheckNA},
		// Then the orchestrator's own probe decides.
		{"203.0.113.5", "10.0.0.2", "203.0.113.5", egressCheckMatch},
		{"203.0.113.5", "10.0.0.2", "198.51.100.9", egressCheckMismatch},
	} {
		if got, _ := egressCheck(tc.declared, tc.seen, tc.probe); got != tc.want {
			t.Errorf("declared=%s seen=%s probe=%s: %s want %s", tc.declared, tc.seen, tc.probe, got, tc.want)
		}
	}
}

// X-L12: the ack compares the worker's declared egress with the source the
// orchestrator saw, not with another value from the worker.
func TestAckEgressUsesObservedSource(t *testing.T) {
	s := newTestServer(t)
	peer := bytes.Repeat([]byte{3}, 32)
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(peer))
	ack := func(seen string) ackResponse {
		t.Helper()
		raw, _ := json.Marshal(ackRequest{WorkerID: w.ID, AppliedVersion: 1, EgressIPObserved: "203.0.113.5"})
		resp, err := s.handleAckContext(withSourceIP(context.Background(), seen), peer, raw)
		if err != nil {
			t.Fatal(err)
		}
		return resp.(ackResponse)
	}
	if resp := ack("198.51.100.9"); resp.EgressMatch || resp.EgressIPProbe != "198.51.100.9" {
		t.Fatalf("mismatch not detected: %+v", resp)
	}
	rec, _ := s.store.worker(w.ID)
	if rec.EgressIPSeen != "198.51.100.9" || rec.EgressCheck != egressCheckMismatch {
		t.Fatalf("stored: seen=%q check=%q", rec.EgressIPSeen, rec.EgressCheck)
	}
	if entry, ok := botWorkerProblemEntry(rec, time.Now().UTC()); !ok || entry.Kind != "worker_egress_mismatch" {
		t.Fatalf("no alert: %+v", entry)
	}
	if resp := ack("203.0.113.5"); !resp.EgressMatch {
		t.Fatalf("match not detected: %+v", resp)
	}
	if resp := ack("172.18.0.3"); !resp.EgressMatch || resp.EgressIPProbe != "" {
		t.Fatalf("co-located worker must be n/a without alarm: %+v", resp)
	}
	rec, _ = s.store.worker(w.ID)
	if rec.EgressCheck != egressCheckNA {
		t.Fatalf("check=%q", rec.EgressCheck)
	}
	if _, ok := botWorkerProblemEntry(rec, time.Now().UTC()); ok {
		t.Fatal("n/a must not alert")
	}
}

// APP-M17: echo URLs reach apps as egress_probe_urls.
func TestClientBundleEgressProbeURLs(t *testing.T) {
	if _, err := parseEgressEchoURLs([]string{"http://echo.example/ip"}); err == nil {
		t.Fatal("plain http accepted")
	}
	urls, err := parseEgressEchoURLs([]string{"https://echo.example/ip"})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	addApprovedWorker(t, s)
	s.cfg.EgressEchoURLs = urls
	content, err := s.clientBundleContent()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := content["egress_probe_urls"].([]string)
	if !slices.Equal(got, []string{"https://echo.example/ip"}) {
		t.Fatalf("egress_probe_urls=%v", content["egress_probe_urls"])
	}
}

// APP-L36: the bootstrap payload carries the TLS SPKI pins.
func TestBootstrapCarriesSPKIPins(t *testing.T) {
	s := newTestServer(t)
	s.cfg.TLS = true
	if _, _, err := loadOrCreateTLS(s.cfg); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(filepath.Join(s.cfg.StateDir, "tls.crt"))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := base64.StdEncoding.EncodeToString(sum[:])
	payload := makeBootstrapPayload(s.cfg, "pin", "noise", "token", tokenRecord{})
	if !slices.Equal(payload.OrchTLSSPKISHA256, []string{want}) {
		t.Fatalf("pins=%v want %s", payload.OrchTLSSPKISHA256, want)
	}
	raw, _ := json.Marshal(payload)
	if !strings.Contains(string(raw), `"orch_tls_spki_sha256":["`) {
		t.Fatalf("payload: %s", raw)
	}
	// Behind a proxy the configured list (current + backup) wins.
	backup := strings.Repeat("ab", 32)
	pins, err := parseSPKIPins([]string{want, backup})
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.PublicTLSSPKIPins = pins
	if got := makeBootstrapPayload(s.cfg, "pin", "noise", "token", tokenRecord{}).OrchTLSSPKISHA256; len(got) != 2 || got[0] != want {
		t.Fatalf("configured pins=%v", got)
	}
	if _, err := parseSPKIPins([]string{"nope"}); err == nil {
		t.Fatal("bad pin accepted")
	}
	s.cfg.PublicTLSSPKIPins, s.cfg.TLS = nil, false
	if got := makeBootstrapPayload(s.cfg, "pin", "noise", "token", tokenRecord{}).OrchTLSSPKISHA256; got != nil {
		t.Fatalf("pins without TLS or configuration: %v", got)
	}
}
