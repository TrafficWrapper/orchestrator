package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Egress checks without a third party (X-L12, ORC-M6). The orchestrator
// records the source address of each worker's authenticated ack
// (egress_ip_seen) and compares the worker's declared egress with it, or with
// ORCH_EGRESS_PROBE_URL when the source is not a public address (co-located or
// docker workers: "n/a", no alert). Client routes keep the worker's sanitized
// egress_ip: workers may sit behind NAT, so a mismatch only alerts.
const (
	egressCheckMatch    = "match"
	egressCheckMismatch = "mismatch"
	egressCheckNA       = "n/a"
)

type sourceIPKey struct{}

func withSourceIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceIPKey{}, ip)
}

func sourceIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(sourceIPKey{}).(string)
	return ip
}

// publicIP reports whether value is a globally routable address.
func publicIP(value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	// Carrier-grade NAT space is not a stable public identity either.
	return !netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

// egressCheck compares the worker's declared egress with an address the
// orchestrator observed itself: the ack source when public, else the probe.
// It returns the check result and the reference address used.
func egressCheck(declared, seen, probe string) (string, string) {
	declared = strings.TrimSpace(declared)
	reference := ""
	switch {
	case publicIP(seen):
		reference = seen
	case strings.TrimSpace(probe) != "":
		reference = strings.TrimSpace(probe)
	default:
		return egressCheckNA, ""
	}
	if declared == "" {
		return egressCheckNA, reference
	}
	a, errA := netip.ParseAddr(declared)
	b, errB := netip.ParseAddr(reference)
	if errA == nil && errB == nil && a.Unmap() == b.Unmap() {
		return egressCheckMatch, reference
	}
	if declared == reference {
		return egressCheckMatch, reference
	}
	return egressCheckMismatch, reference
}

// parseEgressEchoURLs validates ORCH_EGRESS_ECHO_URLS: https URLs apps query
// through the tunnel to learn their egress address (APP-M17).
func parseEgressEchoURLs(values []string) ([]string, error) {
	var out []string
	for _, value := range values {
		u, err := url.Parse(strings.TrimSpace(value))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("ORCH_EGRESS_ECHO_URLS: %q is not an https URL", value)
		}
		out = append(out, u.String())
	}
	return out, nil
}

// parseSPKIPins normalizes SHA-256 SPKI pins given as hex or base64 to
// standard base64.
func parseSPKIPins(values []string) ([]string, error) {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		raw, err := hex.DecodeString(strings.ReplaceAll(value, ":", ""))
		if err != nil || len(raw) != sha256.Size {
			raw, err = base64.StdEncoding.DecodeString(value)
		}
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("ORCH_PUBLIC_TLS_SPKI_SHA256: %q is not a SHA-256 digest (hex or base64)", value)
		}
		out = append(out, base64.StdEncoding.EncodeToString(raw))
	}
	return out, nil
}

// certSPKIPin is the base64 SHA-256 of a PEM certificate's public key info.
func certSPKIPin(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("no certificate in PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// orchTLSSPKIPins lists the SPKI pins for the bootstrap payload (APP-L36):
// the configured list behind a proxy, else the orchestrator's own certificate
// when it terminates TLS itself.
func orchTLSSPKIPins(cfg orchConfig) []string {
	if len(cfg.PublicTLSSPKIPins) > 0 {
		return append([]string(nil), cfg.PublicTLSSPKIPins...)
	}
	if !cfg.TLS {
		return nil
	}
	certPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "tls.crt"))
	if err != nil {
		return nil
	}
	pin, err := certSPKIPin(certPEM)
	if err != nil {
		return nil
	}
	return []string{pin}
}

// recordEgressSeen stores the observed egress and check result, writing only
// when they changed; a new mismatch is logged as an alert.
func (s *orchStore) recordEgressSeen(rec workerRecord, seen, check, declared, reference string) error {
	seen = strings.TrimSpace(seen)
	if rec.EgressIPSeen == seen && rec.EgressCheck == check {
		return nil
	}
	if check == egressCheckMismatch && rec.EgressCheck != egressCheckMismatch {
		log.Printf("ALERT worker %s: declared egress %q differs from observed %q", rec.ID, declared, reference)
	}
	return s.updateWorker(rec.ID, func(r *workerRecord) error {
		r.EgressIPSeen, r.EgressCheck = seen, check
		return nil
	})
}
