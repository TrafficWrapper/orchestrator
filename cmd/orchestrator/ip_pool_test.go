package main

import (
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func allocateN(t *testing.T, s *server, cidr string, n int) ([]string, error) {
	t.Helper()
	var out []string
	for i := 0; i < n; i++ {
		var ip string
		err := s.store.db.Update(func(tx *bolt.Tx) error {
			var err error
			ip, err = s.store.allocateDeviceIP(tx, cidr)
			if err != nil {
				return err
			}
			rec := deviceRecord{ID: fmt.Sprintf("dev-%d", i), Status: "approved", InternalIP: ip, CreatedAt: time.Now().UTC()}
			sealed, err := s.store.sealJSON(rec)
			if err != nil {
				return err
			}
			return tx.Bucket(bucketDevices).Put([]byte(rec.ID), sealed)
		})
		if err != nil {
			return out, err
		}
		out = append(out, ip)
	}
	return out, nil
}

func TestDeviceIPPoolSlash24KeepsLegacyRange(t *testing.T) {
	s := newTestServer(t)
	ips, err := allocateN(t, s, "10.13.13.0/24", 245)
	if err != nil {
		t.Fatal(err)
	}
	if ips[0] != "10.13.13.10/32" || ips[len(ips)-1] != "10.13.13.254/32" {
		t.Fatalf("range=%s..%s", ips[0], ips[len(ips)-1])
	}
	if _, err := allocateN(t, s, "10.13.13.0/24", 1); err == nil {
		t.Fatal("pool must be exhausted after .254 (broadcast excluded)")
	}
}

func TestDeviceIPPoolUsesWholeWiderSubnet(t *testing.T) {
	s := newTestServer(t)
	ips, err := allocateN(t, s, "10.20.0.0/22", 300)
	if err != nil {
		t.Fatalf("a /22 must hold more than 245 devices: %v", err)
	}
	if ips[246] != "10.20.1.0/32" {
		t.Fatalf("allocation must continue into the next octet, got %s", ips[246])
	}
}
