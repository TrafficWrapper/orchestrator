package main

import (
	"net/http"
	"testing"
	"time"
)

// R2 ORC-H2: re-enrollment used to return the same REALITY UUID forever, so
// the RUNBOOK's "re-enroll to rotate" did nothing. A pending rotation is
// applied at the next re-enrollment and returned in that response.
func TestPendingRotationAppliedAtReenroll(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	w := addApprovedWorkerWithStatic(t, s, "rot-worker")
	if _, err := s.store.createBootstrapToken("boot-rot", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	first := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rot"})
	if again := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rot"}); again.RealityUUID != first.RealityUUID {
		t.Fatal("re-enroll without a rotation must keep the credentials")
	}
	call := func(body map[string]any) int {
		return adminCall(t, s.handleAdminRotateDeviceCredentials, "/admin/v1/devices/rotate-credentials", body, nil).Code
	}
	if code := call(map[string]any{"ids": []string{first.DeviceID}}); code != http.StatusForbidden {
		t.Fatalf("rotation without step-up: %d", code)
	}
	if code := call(map[string]any{"ids": []string{first.DeviceID}, "current_secret": "owner-secret-value"}); code != http.StatusOK {
		t.Fatalf("rotation: %d", code)
	}
	// Until the device re-enrolls its credentials still work.
	if dev, _ := s.store.device(first.DeviceID); dev.RealityUUID != first.RealityUUID {
		t.Fatal("pending rotation changed the credentials before re-enrollment")
	}
	before, _ := s.store.worker(w.ID)
	rotated := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rot"})
	if rotated.RealityUUID == first.RealityUUID || rotated.PSK2 == first.PSK2 || rotated.InternalIP != first.InternalIP {
		t.Fatalf("re-enroll after rotation: uuid %s -> %s, psk changed=%t", first.RealityUUID, rotated.RealityUUID, rotated.PSK2 != first.PSK2)
	}
	if after, _ := s.store.worker(w.ID); after.DesiredSeq <= before.DesiredSeq {
		t.Fatal("workers not told about the rotated credentials")
	}
	if again := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-rot"}); again.RealityUUID != rotated.RealityUUID {
		t.Fatal("rotation applied twice")
	}
}

func TestImmediateRotationForAllDevices(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorkerWithStatic(t, s, "rot-all")
	if _, err := s.store.createBootstrapToken("boot-all", time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	first := enrollRequestForTest(t, s, deviceEnrollRequest{BootstrapToken: "boot-all"})
	n, err := s.store.markDeviceRotation(nil, true, true)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if dev, _ := s.store.device(first.DeviceID); dev.RealityUUID == first.RealityUUID || dev.CredentialRotation != "" {
		t.Fatalf("immediate rotation: %+v", dev)
	}
}
