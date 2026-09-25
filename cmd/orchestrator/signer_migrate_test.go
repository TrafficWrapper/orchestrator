package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateLegacySignerKeyMovesKey(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "orch-state", "orch-config.key")
	target := filepath.Join(dir, "signer-state", "orch-config.key")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("key-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacySignerKey(target, legacy); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "key-bytes" {
		t.Fatalf("target=%q err=%v", got, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("target perms=%v err=%v", info.Mode().Perm(), err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy key must be removed, stat err=%v", err)
	}
	// Idempotent once migrated.
	if err := migrateLegacySignerKey(target, legacy); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateLegacySignerKeyRefusesConflict(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.key")
	target := filepath.Join(dir, "target.key")
	_ = os.WriteFile(legacy, []byte("old"), 0o600)
	_ = os.WriteFile(target, []byte("new"), 0o600)
	if err := migrateLegacySignerKey(target, legacy); err == nil {
		t.Fatal("conflicting keys must not be silently resolved")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("legacy key must be kept on conflict")
	}
}

// ORC-I5: the legacy check runs once; afterwards the legacy path is neither
// read nor modified, and a stray file there cannot stop the signer.
func TestMigrateLegacySignerKeyRunsOnce(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "orch-state", "orch-config.key")
	target := filepath.Join(dir, "signer-state", "orch-config.key")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("key-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacySignerKey(target, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacySignerKeyMarkerPath(target)); err != nil {
		t.Fatalf("marker not written after migration: %v", err)
	}
	// A different file appearing at the legacy path later is left alone.
	if err := os.WriteFile(legacy, []byte("other-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacySignerKey(target, legacy); err != nil {
		t.Fatalf("mismatch after a finished migration must not stop the signer: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "key-bytes" {
		t.Fatalf("signer key changed to %q", got)
	}
	if got, _ := os.ReadFile(legacy); string(got) != "other-bytes" {
		t.Fatalf("legacy path was modified after the migration: %q", got)
	}
}

func TestMigrateLegacySignerKeyMarksAbsentLegacyKey(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "orch-state", "orch-config.key")
	target := filepath.Join(dir, "signer-state", "orch-config.key")
	if err := migrateLegacySignerKey(target, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacySignerKeyMarkerPath(target)); err != nil {
		t.Fatalf("marker not written when no legacy key exists: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("late"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacySignerKey(target, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("a legacy file appearing after the check was imported: %v", err)
	}
}

func TestMigrateLegacySignerKeyConflictNotMarked(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.key")
	target := filepath.Join(dir, "target.key")
	_ = os.WriteFile(legacy, []byte("old"), 0o600)
	_ = os.WriteFile(target, []byte("new"), 0o600)
	if err := migrateLegacySignerKey(target, legacy); err == nil {
		t.Fatal("conflicting keys must not be silently resolved")
	}
	if _, err := os.Stat(legacySignerKeyMarkerPath(target)); !os.IsNotExist(err) {
		t.Fatalf("an unresolved conflict was marked as migrated: %v", err)
	}
}

func TestEntrypointSkipsLegacyDirAfterMigration(t *testing.T) {
	entry, err := os.ReadFile("../../docker-entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entry), `"${ORCH_SIGNER_KEY_PATH:-}`+legacySignerKeyMarkerSuffix+`"`) {
		t.Fatal("entrypoint must not re-own the legacy key directory once the migration marker exists")
	}
}

func TestSignerClientTimesOutOnHungSigner(t *testing.T) {
	old := signerCallTimeout
	signerCallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { signerCallTimeout = old })
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(3 * time.Second)
		}
	}()
	start := time.Now()
	_, err = signerClient{socket: sock}.publicKey()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("call hung for %s", elapsed)
	}
}
