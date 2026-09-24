package main

import (
	"testing"
)

func TestClientBundleReusedUntilContentChanges(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "bundle-worker")
	first, err := s.buildClientBundle(0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.buildClientBundle(0)
	if err != nil {
		t.Fatal(err)
	}
	if second.ConfigJSON != first.ConfigJSON {
		t.Fatal("identical content must reuse the signed bundle")
	}
	disabled := false
	if err := s.store.updateWorkerPolicy(w.ID, workerPolicyPatch{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	third, err := s.buildClientBundle(0)
	if err != nil {
		t.Fatal(err)
	}
	if third.ConfigJSON == first.ConfigJSON {
		t.Fatal("changed worker set must produce a new bundle")
	}
}
