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
		var entry auditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		out = append(out, entry)
	}
	return out
}
