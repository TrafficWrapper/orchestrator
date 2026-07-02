package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aead.dev/minisign"
)

func TestSignedDiscoveryBundleUsesUpdateKey(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.cfg.UpdatePublicKey = mustText(pub)
	privText, err := priv.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.StateDir, "update.key"), privText, 0o600); err != nil {
		t.Fatal(err)
	}
	addApprovedWorker(t, s)

	jsonText, minisigText, pubText, err := s.signedDiscoveryBundle()
	if err != nil {
		t.Fatal(err)
	}
	if pubText != mustText(pub) {
		t.Fatalf("pubkey=%q want %q", pubText, mustText(pub))
	}
	if !minisign.Verify(pub, []byte(jsonText), []byte(minisigText)) {
		t.Fatal("discovery bundle minisign verification failed")
	}
	if err := rejectForbiddenKeys([]byte(jsonText)); err != nil {
		t.Fatalf("discovery bundle contains forbidden keys: %v", err)
	}
	var root struct {
		Schema    int    `json:"schema"`
		Namespace string `json:"ns"`
		Endpoints struct {
			Reality []map[string]any `json:"reality"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	if root.Schema != 2 || root.Namespace != "rendezvous-v1" {
		t.Fatalf("bad discovery root: %+v", root)
	}
	if len(root.Endpoints.Reality) != 1 {
		t.Fatalf("reality endpoints=%d want 1", len(root.Endpoints.Reality))
	}

	bundle, err := s.buildClientBundleForClient(0, "0.1.18")
	if err != nil {
		t.Fatal(err)
	}
	var clientRoot struct {
		DiscoveryPubkey string `json:"discovery_pubkey"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &clientRoot); err != nil {
		t.Fatal(err)
	}
	if clientRoot.DiscoveryPubkey != mustText(pub) {
		t.Fatalf("discovery_pubkey=%q want %q", clientRoot.DiscoveryPubkey, mustText(pub))
	}
}

func TestDiscoverySeqBumpPersistsAboveWorkerFloor(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)

	seq, err := s.bumpDiscoverySeq()
	if err != nil {
		t.Fatal(err)
	}
	if seq < 2 {
		t.Fatalf("bumped seq=%d want >=2", seq)
	}
	jsonText, err := s.discoveryBundleJSON(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		t.Fatal(err)
	}
	if root.Seq != seq {
		t.Fatalf("bundle seq=%d want bumped seq=%d", root.Seq, seq)
	}
}
