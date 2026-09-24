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
