package main

import (
	"encoding/json"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func TestTokenLookupFindsIndexedToken(t *testing.T) {
	s := newTestServer(t)
	for i, secret := range []string{"secret-a", "secret-b", "secret-c"} {
		if err := s.store.createToken(string(rune('a'+i)), secret, time.Hour, 1, ""); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.store.findTokenID("secret-b", "", time.Now().UTC())
	if err != nil || id != "b" {
		t.Fatalf("id=%q err=%v want b", id, err)
	}
	id, err = s.store.findTokenID("wrong", "", time.Now().UTC())
	if err != nil || id != "" {
		t.Fatalf("wrong secret matched id=%q err=%v", id, err)
	}
}

func TestTokenLookupFallsBackForLegacyRecords(t *testing.T) {
	s := newTestServer(t)
	hash, err := protocol.HashSecret("legacy-secret")
	if err != nil {
		t.Fatal(err)
	}
	legacy := tokenRecord{ID: "legacy", Hash: hash, ExpiresAt: time.Now().UTC().Add(time.Hour), MaxUses: 1}
	raw, _ := json.Marshal(legacy)
	if err := s.store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Put([]byte(legacy.ID), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.consumeToken("legacy-secret", ""); err != nil {
		t.Fatalf("legacy token not accepted: %v", err)
	}
	if _, err := s.store.consumeToken("legacy-secret", ""); err == nil {
		t.Fatal("legacy token must be single-use")
	}
}

func TestBootstrapTokenLookupUsesIndex(t *testing.T) {
	s := newTestServer(t)
	rec, err := s.store.createBootstrapToken("boot-secret", time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Lookup == "" {
		t.Fatal("bootstrap token must store a lookup index")
	}
	id, err := s.store.findBootstrapTokenID("boot-secret", time.Now().UTC())
	if err != nil || id != rec.ID {
		t.Fatalf("id=%q err=%v want %q", id, err, rec.ID)
	}
}

func TestPruneDeadTokensKeepsLiveOnes(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	put := func(rec tokenRecord) {
		raw, _ := json.Marshal(rec)
		if err := s.store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucketTokens).Put([]byte(rec.ID), raw)
		}); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-30 * 24 * time.Hour)
	put(tokenRecord{ID: "expired-old", ExpiresAt: old, CreatedAt: old, MaxUses: 1})
	put(tokenRecord{ID: "used-old", ExpiresAt: now.Add(24 * time.Hour), CreatedAt: old, MaxUses: 1, Uses: 1})
	put(tokenRecord{ID: "live", ExpiresAt: now.Add(time.Hour), CreatedAt: old, MaxUses: 1})
	put(tokenRecord{ID: "expired-recent", ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour), MaxUses: 1})
	n, err := s.store.pruneDeadTokens(now)
	if err != nil || n != 2 {
		t.Fatalf("pruned=%d err=%v want 2", n, err)
	}
	for id, want := range map[string]bool{"expired-old": false, "used-old": false, "live": true, "expired-recent": true} {
		var exists bool
		_ = s.store.db.View(func(tx *bolt.Tx) error {
			exists = tx.Bucket(bucketTokens).Get([]byte(id)) != nil
			return nil
		})
		if exists != want {
			t.Fatalf("token %s exists=%t want %t", id, exists, want)
		}
	}
}

func TestConsumeBootstrapTokenRejectsExistingDeviceWithoutBurningToken(t *testing.T) {
	s := newTestServer(t)
	if _, err := s.store.createBootstrapToken("boot-a", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.createBootstrapToken("boot-b", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	dev := deviceRecord{ID: "dev-race", IdentityPubKey: "id", NoisePublicKey: "np", AWGPublicKey: "awg"}
	if _, _, err := s.store.consumeBootstrapToken("boot-a", dev, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.store.consumeBootstrapToken("boot-b", dev, nil); err == nil {
		t.Fatal("second enroll of the same device must fail")
	}
	if id, err := s.store.findBootstrapTokenID("boot-b", time.Now().UTC()); err != nil || id == "" {
		t.Fatalf("rejected enroll must not consume the token: id=%q err=%v", id, err)
	}
}
