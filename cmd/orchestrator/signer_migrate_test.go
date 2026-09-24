package main

import (
	"net"
	"os"
	"path/filepath"
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
