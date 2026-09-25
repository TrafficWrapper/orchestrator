package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// seedStore creates a store with one sealed record and returns its config.
func seedStore(t *testing.T) orchConfig {
	t.Helper()
	cfg := orchConfig{StateDir: t.TempDir()}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	putDeviceRecordForTest(t, st, deviceRecord{ID: "dev", Status: "approved"})
	_ = st.close()
	return cfg
}

func putDeviceRecordForTest(t *testing.T, st *orchStore, rec deviceRecord) {
	t.Helper()
	if err := st.db.Update(func(tx *bolt.Tx) error {
		sealed, err := st.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketDevices).Put([]byte(rec.ID), sealed)
	}); err != nil {
		t.Fatal(err)
	}
}

// ORC-M1: a missing master.key must not be silently replaced when the
// database already holds encrypted records.
func TestMissingMasterKeyIsNotRecreatedOverSealedData(t *testing.T) {
	cfg := seedStore(t)
	keyPath := filepath.Join(cfg.StateDir, "master.key")
	original, _ := os.ReadFile(keyPath)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openOrchStore(cfg); err == nil || !strings.Contains(err.Error(), "master.key is missing") {
		t.Fatalf("open without key: %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a new master.key must not be written")
	}
	// Restoring the key restores the service.
	if err := os.WriteFile(keyPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatalf("restored key: %v", err)
	}
	defer st.close()
	if rec, err := st.device("dev"); err != nil || rec.ID != "dev" {
		t.Fatalf("record unreadable after restore: %v", err)
	}
}

func TestWrongMasterKeyStopsStartup(t *testing.T) {
	cfg := seedStore(t)
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "master.key"), []byte(base64.StdEncoding.EncodeToString(other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openOrchStore(cfg); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
		t.Fatalf("wrong key: %v", err)
	}
	cfg.AllowUnreadableRecords = true
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatalf("override must start: %v", err)
	}
	_ = st.close()
}

// ORC-M1: legacy records that do not decrypt keep the format marker unset,
// so the right key can still migrate them later.
func TestUnreadableLegacyRecordsKeepMarkerUnset(t *testing.T) {
	cfg := orchConfig{StateDir: t.TempDir()}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	right := st.aead
	plain, _ := json.Marshal(deviceRecord{ID: "legacy", Status: "approved"})
	nonce := make([]byte, right.NonceSize())
	_, _ = rand.Read(nonce)
	legacy := base64.RawStdEncoding.EncodeToString(nonce) + "." + base64.RawStdEncoding.EncodeToString(right.Seal(nil, nonce, plain, nil))
	if err := st.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketMeta).Delete(metaSealedFormat); err != nil {
			return err
		}
		return tx.Bucket(bucketDevices).Put([]byte("legacy"), []byte(legacy))
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.close()
	keyPath := filepath.Join(cfg.StateDir, "master.key")
	rightKey, _ := os.ReadFile(keyPath)
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	_ = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(other)+"\n"), 0o600)
	if _, err := openOrchStore(cfg); err == nil {
		t.Fatal("unreadable legacy records must stop startup")
	}
	cfg.AllowUnreadableRecords = true
	st, err = openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var marker []byte
	_ = st.db.View(func(tx *bolt.Tx) error { marker = tx.Bucket(bucketMeta).Get(metaSealedFormat); return nil })
	_ = st.close()
	if marker != nil {
		t.Fatal("marker must not be written over unreadable records")
	}
	cfg.AllowUnreadableRecords = false
	_ = os.WriteFile(keyPath, rightKey, 0o600)
	st, err = openOrchStore(cfg)
	if err != nil {
		t.Fatalf("right key must migrate: %v", err)
	}
	defer st.close()
	if rec, err := st.device("legacy"); err != nil || rec.ID != "legacy" {
		t.Fatalf("legacy record lost: %v", err)
	}
}

func TestClearSealedFormatMarker(t *testing.T) {
	cfg := seedStore(t)
	if err := clearSealedFormatMarker(cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(cfg.StateDir, "orchestrator.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketMeta).Get(metaSealedFormat) != nil {
			t.Fatal("marker still set")
		}
		return nil
	})
}

// ORC-L7: the signer key is pinned; a different key is refused until the
// operator accepts it.
func TestSignerKeyPinned(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.checkSignerKey("key-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.checkSignerKey("key-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.checkSignerKey("key-b"); !errors.Is(err, errSignerKeyChanged) {
		t.Fatalf("changed key: %v", err)
	}
	_ = s.store.close()
	if err := clearSignerPin(s.cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	st, err := openOrchStore(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if err := st.checkSignerKey("key-b"); err != nil {
		t.Fatalf("accepted key: %v", err)
	}
}

// ORC-L7/L9: the signer creates its key once; afterwards a missing key file
// is an error instead of a silent new key.
func TestSignerKeyNotRegeneratedAfterInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orch-config.key")
	pub, _, err := loadOrCreateMinisignKey(path)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := loadOrCreateMinisignKey(path)
	if err != nil || mustText(again) != mustText(pub) {
		t.Fatalf("reload: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateMinisignKey(path); err == nil || !strings.Contains(err.Error(), "initialised before") {
		t.Fatalf("missing key after init: %v", err)
	}
	if info, err := os.Stat(path + ".initialized"); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker: %v", err)
	}
}
