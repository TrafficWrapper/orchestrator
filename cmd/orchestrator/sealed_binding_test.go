package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSealedRecordsAreBoundToTheirKey(t *testing.T) {
	s := newTestServer(t)
	a := deviceRecord{ID: "dev-a", Status: "approved", CreatedAt: time.Now().UTC()}
	b := deviceRecord{ID: "dev-b", Status: "revoked", CreatedAt: time.Now().UTC()}
	putQuotaDevice(t, s, a)
	putQuotaDevice(t, s, b)
	// Swap ciphertexts between keys, as an attacker with DB write access could.
	if err := s.store.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketDevices)
		ra := append([]byte(nil), bk.Get([]byte("dev-a"))...)
		rb := append([]byte(nil), bk.Get([]byte("dev-b"))...)
		if err := bk.Put([]byte("dev-a"), rb); err != nil {
			return err
		}
		return bk.Put([]byte("dev-b"), ra)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.device("dev-a"); err == nil {
		t.Fatal("a record moved to another key must not decrypt")
	}
	// The same ciphertext under another bucket must not decrypt either.
	sealed, err := s.store.sealJSON(bucketDevices, []byte("x"), a)
	if err != nil {
		t.Fatal(err)
	}
	var out deviceRecord
	if err := s.store.openJSON(bucketWorkers, []byte("x"), sealed, &out); err == nil {
		t.Fatal("a record moved to another bucket must not decrypt")
	}
}

func TestLegacySealedRecordsAreReadAndMigrated(t *testing.T) {
	cfg := orchConfig{StateDir: t.TempDir()}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Write a record in the pre-binding format (no prefix, no AD).
	plain, _ := json.Marshal(deviceRecord{ID: "legacy", Status: "approved"})
	nonce := make([]byte, st.aead.NonceSize())
	_, _ = rand.Read(nonce)
	legacy := base64.RawStdEncoding.EncodeToString(nonce) + "." + base64.RawStdEncoding.EncodeToString(st.aead.Seal(nil, nonce, plain, nil))
	if err := st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).Put([]byte("legacy"), []byte(legacy))
	}); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.device("legacy"); err != nil || rec.Status != "approved" {
		t.Fatalf("legacy record unreadable: %v", err)
	}
	_ = st.close()

	st, err = openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	var raw []byte
	_ = st.db.View(func(tx *bolt.Tx) error {
		raw = append([]byte(nil), tx.Bucket(bucketDevices).Get([]byte("legacy"))...)
		return nil
	})
	if !strings.HasPrefix(string(raw), sealedRecordV2Prefix) {
		t.Fatalf("legacy record not migrated: %q", raw)
	}
	if rec, err := st.device("legacy"); err != nil || rec.ID != "legacy" {
		t.Fatalf("migrated record unreadable: %v", err)
	}
}
