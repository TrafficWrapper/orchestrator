package main

import (
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestClientBundleReusedUntilContentChanges(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "bundle-worker")
	first, err := s.buildClientBundle()
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.buildClientBundle()
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
	if _, err := s.checkClientBundle(); err != nil {
		t.Fatal(err)
	}
	third, err := s.buildClientBundle()
	if err != nil {
		t.Fatal(err)
	}
	if third.ConfigJSON == first.ConfigJSON {
		t.Fatal("an operator change must be published on the next check")
	}
}

func TestDeviceIPIndexAllocatesDistinctAddressesPerPool(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{ID: "existing", Status: "approved", InternalIP: "10.13.13.10/32",
		AWGProfiles: map[string]deviceAWGProfile{"awg-alt": {InternalIP: "10.14.0.10/32"}}})
	err := s.store.db.Update(func(tx *bolt.Tx) error {
		idx := s.store.newDeviceIPIndex(tx)
		a, err := idx.allocate("awg", "10.13.13.0/24")
		if err != nil {
			return err
		}
		b, err := idx.allocate("awg", "10.13.13.0/24")
		if err != nil {
			return err
		}
		c, err := idx.allocate("awg-alt", "10.14.0.0/24")
		if err != nil {
			return err
		}
		if a != "10.13.13.11/32" || b != "10.13.13.12/32" || c != "10.14.0.11/32" {
			t.Fatalf("got %s %s %s", a, b, c)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
