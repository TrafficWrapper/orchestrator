package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// R2 enroll AWG key: workers compare AWG keys as bytes, so the orchestrator
// must too. A second spelling of the same 32 bytes (non-canonical base64
// padding bits) is the same key and must hit the uniqueness check.
func TestEnrollAWGKeyUniqueAcrossSpellings(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "canon-worker")
	for _, token := range []string{"boot-a", "boot-b"} {
		if _, err := s.store.createBootstrapToken(token, time.Now().Add(time.Hour), nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	key := make([]byte, 32)
	key[31] = 0x10
	canonical := base64.StdEncoding.EncodeToString(key)
	// Same bytes, last data character with its unused low bits set.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, canonical[42])
	variant := canonical[:42] + string(alphabet[last|1]) + "="
	if raw, err := base64.StdEncoding.DecodeString(variant); err != nil || string(raw) != string(key) {
		t.Fatalf("test variant does not decode to the same key: %v", err)
	}
	enroll := func(token, identity, awg string) deviceEnrollResponse {
		raw, _ := json.Marshal(deviceEnrollRequest{BootstrapToken: token, IdentityPubKey: identity, IdentityKeyType: "ed25519", AWGPublicKey: awg})
		resp, err := s.handleDeviceEnroll(make([]byte, 32), raw)
		if err != nil {
			t.Fatal(err)
		}
		return resp.(deviceEnrollResponse)
	}
	if first := enroll("boot-a", "identity-a", canonical); !first.OK {
		t.Fatalf("first enroll: %+v", first)
	}
	// A non-canonical spelling is refused outright (strict decoding).
	if second := enroll("boot-b", "identity-b", variant); second.OK {
		t.Fatalf("second spelling of the same key enrolled: %+v", second)
	}
	// The canonical spelling of an owned key hits the uniqueness check.
	if third := enroll("boot-b", "identity-b", " "+canonical+" "); third.OK || third.Code != "awg_key_in_use" {
		t.Fatalf("same key with surrounding space: %+v", third)
	}
	for _, bad := range []string{"not-base64", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if resp := enroll("boot-b", "identity-c", bad); resp.OK {
			t.Fatalf("invalid AWG key %q accepted", bad)
		}
	}
}
