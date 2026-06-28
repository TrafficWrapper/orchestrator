package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditHashChainReopenAndTamperDetect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	audit.Log(auditEntry{Event: "login", Result: "failed", IP: "198.51.100.10"})
	audit.Log(auditEntry{Event: "login", Result: "ok", IP: "198.51.100.10"})
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("fresh audit chain failed verification: %v", err)
	}
	entries := readAuditEntriesForTest(t, path)
	if len(entries) != 2 || entries[0].PrevHash != "" || entries[1].PrevHash != entries[0].Hash {
		t.Fatalf("bad initial audit chain: %+v", entries)
	}

	reopened, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Log(auditEntry{Event: "password_change", Result: "ok"})
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	entries = readAuditEntriesForTest(t, path)
	if len(entries) != 3 || entries[2].PrevHash != entries[1].Hash {
		t.Fatalf("reopen did not resume previous hash: %+v", entries)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("reopened audit chain failed verification: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"result":"failed"`, `"result":"ok"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); !errors.Is(err, errAuditChainBroken) {
		t.Fatalf("tamper verification err=%v, want %v", err, errAuditChainBroken)
	}
	recovered, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	entries = readAuditEntriesForTest(t, path)
	if got := entries[len(entries)-1]; got.Event != "audit_chain_break_detected" || got.Fields["verify_error"] == "" {
		t.Fatalf("missing audit chain break marker after reopen: %+v", got)
	}
}

func TestAuditOpenDetectsCorruptTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	audit.Log(auditEntry{Event: "login", Result: "ok"})
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-json\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntriesForTest(t, path)
	if got := entries[len(entries)-1]; got.Event != "audit_chain_break_detected" || got.Fields["tail_error"] == "" {
		t.Fatalf("missing corrupt tail marker after reopen: %+v", got)
	}
}

func TestAuditReadersHandleLargeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	audit.Log(auditEntry{
		Event:  "large",
		Result: "ok",
		Fields: map[string]string{
			"blob": strings.Repeat("x", 2*1024*1024),
		},
	})
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("large audit line failed chain verification: %v", err)
	}
	reopened, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Log(auditEntry{Event: "after_large", Result: "ok"})
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("large audit line failed after reopen: %v", err)
	}
}

func readAuditEntriesForTest(t *testing.T, path string) []auditEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	out := make([]auditEntry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || !strings.HasPrefix(strings.TrimSpace(line), "{") {
			continue
		}
		var entry auditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		out = append(out, entry)
	}
	return out
}
