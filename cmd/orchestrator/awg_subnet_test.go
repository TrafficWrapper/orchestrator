package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func awgSubnetWorker(t *testing.T, s *server, seed byte, subnet string) workerRecord {
	t.Helper()
	rec, err := s.store.upsertPendingWorker(protocol.KeyToBase64(bytes.Repeat([]byte{seed}, 32)), map[string]any{
		"egress_ip": "203.0.113.5",
		"awg":       map[string]any{"endpoint": "203.0.113.5:51888", "port": 51888, "public_key": testAWGPublicKey, "subnet": subnet},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(rec.ID)
	return rec
}

// R2 AWG subnet: a worker whose pool is outside /16../26 (the worker accepts
// any CIDR) keeps working: its subnet is a warning, not a rejection, and
// enrollment does not fail.
func TestAWGSubnetOutsidePreferredSizeStillServes(t *testing.T) {
	for _, subnet := range []string{"10.13.13.0/27", "10.0.0.0/12"} {
		s := newTestServer(t)
		w := awgSubnetWorker(t, s, 1, subnet)
		workers, _ := s.store.workers()
		profiles := s.fleetAWGProfiles(workers)
		if len(profiles) != 1 || profiles[0].Subnet != mustPrefix(t, subnet) {
			t.Fatalf("%s: profiles=%+v", subnet, profiles)
		}
		if s.awgConflictWorkers(workers)[w.ID] {
			t.Fatalf("%s: worker marked as conflicting", subnet)
		}
		if _, err := s.store.createBootstrapToken("boot", time.Now().Add(time.Hour), nil, nil); err != nil {
			t.Fatal(err)
		}
		enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot"})
		rec, _ := s.store.worker(w.ID)
		if len(rec.SelfDescribeIssues) == 0 {
			t.Fatalf("%s: no warning recorded", subnet)
		}
	}
}

// R2 AWG subnet: with no usable AWG profile at all enrollment still works
// (default pool), instead of failing every enroll and re-enroll.
func TestEnrollWithoutUsableAWGSubnet(t *testing.T) {
	s := newTestServer(t)
	rec, err := s.store.upsertPendingWorker(protocol.KeyToBase64(bytes.Repeat([]byte{1}, 32)), map[string]any{
		"egress_ip": "203.0.113.5",
		"reality":   map[string]any{"address": "203.0.113.5", "port": 443, "publicKey": testRealityPublicKey, "shortId": "abcd"},
		"awg":       map[string]any{"endpoint": "203.0.113.5:51888", "port": 51888, "public_key": testAWGPublicKey, "subnet": "fd00::/64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.createBootstrapToken("boot", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot"})
	if resp.InternalIP == "" {
		t.Fatalf("enroll: %+v", resp)
	}
}

// R2 AWG subnet: the fleet keeps the subnet devices already hold
// credentials in; new or more numerous workers with another subnet do not
// move it (that would require re-issuing every credential).
func TestAWGFleetSubnetFollowsIssuedCredentials(t *testing.T) {
	s := newTestServer(t)
	awgSubnetWorker(t, s, 9, "10.20.0.0/24")
	if _, err := s.store.createBootstrapToken("boot", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot"})
	awgSubnetWorker(t, s, 1, "10.30.0.0/24")
	awgSubnetWorker(t, s, 2, "10.30.0.0/24")
	workers, _ := s.store.workers()
	if got := s.fleetAWGProfiles(workers); got[0].Subnet != "10.20.0.0/24" {
		t.Fatalf("fleet subnet moved away from issued credentials: %s", got[0].Subnet)
	}
}

// R2 AWG subnet: without issued credentials a tie goes to the worker
// approved first, not to the lowest worker ID.
func TestAWGFleetSubnetTieByApprovalOrder(t *testing.T) {
	s := newTestServer(t)
	first := awgSubnetWorker(t, s, 9, "10.20.0.0/24")
	time.Sleep(10 * time.Millisecond)
	second := awgSubnetWorker(t, s, 1, "10.30.0.0/24")
	if !(second.ID < first.ID) {
		t.Skip("worker IDs happen to sort by approval order")
	}
	workers, _ := s.store.workers()
	if got := s.fleetAWGProfiles(workers); got[0].Subnet != "10.20.0.0/24" {
		t.Fatalf("tie went to %s", got[0].Subnet)
	}
}

// R2 AWG subnet: a conflicting worker raises a bot alert, not only a log.
func TestAWGSubnetConflictAlerts(t *testing.T) {
	s := newTestServer(t)
	awgSubnetWorker(t, s, 9, "10.20.0.0/24")
	time.Sleep(10 * time.Millisecond)
	late := awgSubnetWorker(t, s, 1, "10.30.0.0/24")
	problems, err := s.botProblemSnapshot(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range problems {
		found = found || (entry.ID == late.ID && entry.Kind == "worker_awg_conflict")
	}
	if !found {
		t.Fatalf("no conflict alert: %+v", problems)
	}
}

func mustPrefix(t *testing.T, value string) string {
	t.Helper()
	p, err := validAWGSubnet(value)
	if err != nil {
		t.Fatal(err)
	}
	return p.String()
}
