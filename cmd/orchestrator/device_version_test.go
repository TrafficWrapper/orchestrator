package main

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestResolveInstalledVersion(t *testing.T) {
	device := deviceRecord{ClientVersion: "0.1.11"}
	tests := []struct {
		name    string
		device  deviceRecord
		live    telemetrySnapshotRecord
		hasLive bool
		wantVer string
		wantSrc string
	}{
		{
			name:    "telemetry version wins",
			device:  device,
			live:    telemetrySnapshotRecord{ClientVersion: "0.1.12", ClientVC: 13},
			hasLive: true,
			wantVer: "0.1.12",
			wantSrc: "telemetry",
		},
		{
			name:    "telemetry version code fallback",
			device:  device,
			live:    telemetrySnapshotRecord{ClientVC: 13},
			hasLive: true,
			wantVer: "vc 13",
			wantSrc: "telemetry",
		},
		{
			name:    "enroll fallback without telemetry",
			device:  device,
			hasLive: false,
			wantVer: "0.1.11",
			wantSrc: "enroll",
		},
		{
			name:    "enroll fallback when telemetry has no version",
			device:  device,
			live:    telemetrySnapshotRecord{},
			hasLive: true,
			wantVer: "0.1.11",
			wantSrc: "enroll",
		},
		{
			name:    "unknown",
			device:  deviceRecord{},
			hasLive: false,
			wantVer: "",
			wantSrc: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVer, gotSrc := resolveInstalledVersion(tt.device, tt.live, tt.hasLive)
			if gotVer != tt.wantVer || gotSrc != tt.wantSrc {
				t.Fatalf("resolveInstalledVersion() = (%q, %q), want (%q, %q)", gotVer, gotSrc, tt.wantVer, tt.wantSrc)
			}
		})
	}
}

func TestComputeUpdateAvailable(t *testing.T) {
	release := apkReleaseRecord{VersionCode: 13, VersionName: "0.1.12"}
	tests := []struct {
		name          string
		hasLive       bool
		liveVC        int64
		published     bool
		wantUpdate    bool
		wantPublished string
	}{
		{name: "older live code", hasLive: true, liveVC: 12, published: true, wantUpdate: true, wantPublished: "0.1.12"},
		{name: "no publish", hasLive: true, liveVC: 12, published: false},
		{name: "no telemetry", hasLive: false, liveVC: 12, published: true},
		{name: "unknown live code", hasLive: true, liveVC: 0, published: true},
		{name: "same code", hasLive: true, liveVC: 13, published: true},
		{name: "newer code", hasLive: true, liveVC: 14, published: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUpdate, gotPublished := computeUpdateAvailable(tt.hasLive, tt.liveVC, tt.published, release)
			if gotUpdate != tt.wantUpdate || gotPublished != tt.wantPublished {
				t.Fatalf("computeUpdateAvailable() = (%t, %q), want (%t, %q)", gotUpdate, gotPublished, tt.wantUpdate, tt.wantPublished)
			}
		})
	}
}

func TestUpdateDeviceClientVersionFromTelemetry(t *testing.T) {
	s := newTestServer(t)
	insertDeviceRecord(t, s.store, deviceRecord{
		ID:            "device-a",
		Status:        "approved",
		ClientVersion: "0.1.11",
		CreatedAt:     time.Now().UTC(),
	})

	changed, err := s.store.updateDeviceClientVersionFromTelemetry("device-a", "0.1.12")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected non-empty telemetry version to update device record")
	}
	rec, err := s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ClientVersion != "0.1.12" {
		t.Fatalf("client version was not updated: %q", rec.ClientVersion)
	}

	changed, err = s.store.updateDeviceClientVersionFromTelemetry("device-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("empty telemetry version should not clear device version")
	}
	rec, err = s.store.device("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ClientVersion != "0.1.12" {
		t.Fatalf("empty telemetry version cleared device version: %q", rec.ClientVersion)
	}

	changed, err = s.store.updateDeviceClientVersionFromTelemetry("device-a", "0.1.12")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("same telemetry version should be a no-op")
	}
}

func insertDeviceRecord(t *testing.T, st *orchStore, rec deviceRecord) {
	t.Helper()
	raw, err := st.sealJSON(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).Put([]byte(rec.ID), raw)
	}); err != nil {
		t.Fatal(err)
	}
}
