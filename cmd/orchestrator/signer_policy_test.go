package main

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func policyDoc(ns string, seq int64, worker string) string {
	doc := map[string]any{"ns": ns, "seq": seq}
	if worker != "" {
		doc["worker_id"] = worker
	}
	raw, _ := json.Marshal(doc)
	return string(raw)
}

// ORC-L8: only known namespaces, and seq rises by a bounded step.
func TestSignerPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sign-policy.json")
	p, err := loadSignerPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	config := []string{nsClientConfig, nsWorkerConfig}
	if err := p.admit("not json", config...); err == nil {
		t.Fatal("non-JSON signed")
	}
	if err := p.admit(policyDoc("apk-update-v1", 1, ""), config...); err == nil {
		t.Fatal("foreign namespace signed")
	}
	if err := p.admit(`{"ns":"client-config-v1"}`, config...); err == nil {
		t.Fatal("document without seq signed")
	}
	if err := p.admit(policyDoc(nsClientConfig, 9_000_000_000_000_000_000, ""), config...); err == nil {
		t.Fatal("huge first seq signed")
	}
	if err := p.admit(policyDoc(nsClientConfig, 120, ""), config...); err != nil {
		t.Fatal(err)
	}
	// The one-time migration jump fits the step.
	if err := p.admit(policyDoc(nsClientConfig, 120+1_000_000, ""), config...); err != nil {
		t.Fatalf("migration jump refused: %v", err)
	}
	if err := p.admit(policyDoc(nsClientConfig, 1_000_120+signerMaxSeqStep+1, ""), config...); err == nil {
		t.Fatal("step above the limit signed")
	}
	// Re-signing an older or equal seq is fine.
	if err := p.admit(policyDoc(nsClientConfig, 5, ""), config...); err != nil {
		t.Fatal(err)
	}
	// Worker streams are separate and need a worker_id.
	if err := p.admit(policyDoc(nsWorkerConfig, 3, ""), config...); err == nil {
		t.Fatal("worker config without worker_id signed")
	}
	if err := p.admit(policyDoc(nsWorkerConfig, 3, "w1"), config...); err != nil {
		t.Fatal(err)
	}
	// The highest seq survives a signer restart.
	again, err := loadSignerPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.last[nsClientConfig] != 1_000_120 || again.last[nsWorkerConfig+"/w1"] != 3 {
		t.Fatalf("persisted: %v", again.last)
	}
	if err := again.admit(policyDoc(nsClientConfig, 1_000_120+signerMaxSeqStep+1, ""), config...); err == nil {
		t.Fatal("step limit lost across restart")
	}
}

func signerCall(t *testing.T, keys signerKeys, req signerRequest) signerResponse {
	t.Helper()
	client, server := net.Pipe()
	go handleSignerConn(server, keys)
	defer client.Close()
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp signerResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// ORC-L20: the discovery feed has its own key in the signer, and each key
// signs only its own namespaces.
func TestSignerDiscoveryKey(t *testing.T) {
	pub, priv, _ := minisign.GenerateKey(nil)
	discPub, discPriv, _ := minisign.GenerateKey(nil)
	policy, _ := loadSignerPolicy("")
	keys := signerKeys{pub: pub, priv: priv, discPub: discPub, discPriv: discPriv, policy: policy}
	feed := policyDoc(nsDiscovery, 4, "")
	if resp := signerCall(t, keys, signerRequest{Action: "sign", Message: feed}); resp.OK {
		t.Fatal("config key signed a discovery feed")
	}
	resp := signerCall(t, keys, signerRequest{Action: "sign-discovery", Message: feed})
	if !resp.OK || resp.PublicKey != mustText(discPub) || !minisign.Verify(discPub, []byte(feed), []byte(resp.Signature)) {
		t.Fatalf("discovery signature: %+v", resp)
	}
	if resp := signerCall(t, keys, signerRequest{Action: "sign-discovery", Message: policyDoc(nsClientConfig, 1, "")}); resp.OK {
		t.Fatal("discovery key signed a client config")
	}
	if resp := signerCall(t, keys, signerRequest{Action: "discovery-public-key"}); resp.PublicKey != mustText(discPub) {
		t.Fatalf("discovery public key: %+v", resp)
	}
	if resp := signerCall(t, keys, signerRequest{Action: "sign", Message: policyDoc(nsClientConfig, 1, "")}); !resp.OK || !minisign.Verify(pub, []byte(policyDoc(nsClientConfig, 1, "")), []byte(resp.Signature)) {
		t.Fatalf("config signature: %+v", resp)
	}
}

type fakeDiscoverySigner struct {
	fakeSigner
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func (f fakeDiscoverySigner) discoveryPublicKey() (string, error) { return mustText(f.pub), nil }

func (f fakeDiscoverySigner) signDiscovery(message string) (string, string, error) {
	if !strings.Contains(message, fmt.Sprintf("%q", nsDiscovery)) {
		return "", "", fmt.Errorf("not a discovery feed")
	}
	return string(minisign.Sign(f.priv, []byte(message))), mustText(f.pub), nil
}

// ORC-L20: with ORCH_DISCOVERY_SIGNER the feed and discovery_pubkey switch
// to the signer's discovery key together.
func TestDiscoverySignedBySignerKey(t *testing.T) {
	s := newTestServer(t)
	writeDiscoverySigningKeyForTest(t, s)
	discoveryWorkerForTest(t, s)
	pub, priv, _ := minisign.GenerateKey(nil)
	s.signer = fakeDiscoverySigner{pub: pub, priv: priv}
	s.cfg.DiscoverySigner = true
	snap, err := s.signedDiscoverySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !minisign.Verify(pub, []byte(snap.JSON), []byte(snap.Minisig)) {
		t.Fatal("feed not signed by the discovery key")
	}
	content, err := s.clientBundleContent()
	if err != nil {
		t.Fatal(err)
	}
	if content["discovery_pubkey"] != mustText(pub) {
		t.Fatalf("discovery_pubkey=%v", content["discovery_pubkey"])
	}
	// Without the switch the update key keeps signing (current behaviour).
	s.cfg.DiscoverySigner = false
	if content, _ := s.clientBundleContent(); content["discovery_pubkey"] == mustText(pub) {
		t.Fatal("discovery key announced without ORCH_DISCOVERY_SIGNER")
	}
}
