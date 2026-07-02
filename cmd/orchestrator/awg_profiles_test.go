package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSelectAWGProfileForClientVersion(t *testing.T) {
	profiles := []awgProfile{
		{Name: "awg", MinVersionCode: 0, Params: map[string]any{"port": 51888}},
		{Name: "next", MinVersionCode: 116, Params: map[string]any{"port": 52821}},
	}
	if got, ok := selectAWGProfileForClient(profiles, "0.1.15"); !ok || got.Name != "awg" {
		t.Fatalf("old client got profile=%+v ok=%t want awg", got, ok)
	}
	if got, ok := selectAWGProfileForClient(profiles, "0.1.16"); !ok || got.Name != "next" {
		t.Fatalf("new client got profile=%+v ok=%t want next", got, ok)
	}
}

func TestDeviceEnrollAllocatesAWGProfilesAndClientBundleSelectsByVersion(t *testing.T) {
	s := newTestServer(t)
	rec, err := s.store.upsertPendingWorker("worker-static-profiles", map[string]any{
		"label":     "Worker Profiles",
		"egress_ip": "203.0.113.5",
		"reality": map[string]any{
			"address":   "203.0.113.5",
			"port":      8444,
			"publicKey": "pub",
			"shortId":   "sid",
		},
		"awg": map[string]any{
			"profile":    "awg",
			"endpoint":   "203.0.113.5:51888",
			"port":       51888,
			"public_key": "awgpub",
			"subnet":     "10.13.13.0/24",
		},
		"awg_profiles": []any{
			map[string]any{
				"profile":          "awg",
				"endpoint":         "203.0.113.5:51888",
				"port":             51888,
				"public_key":       "awgpub",
				"subnet":           "10.13.13.0/24",
				"min_version_code": 0,
			},
			map[string]any{
				"profile":          "next",
				"endpoint":         "203.0.113.5:52821",
				"port":             52821,
				"public_key":       "awgpub",
				"subnet":           "10.44.0.0/24",
				"min_version_code": 116,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	secret := "bootstrap-secret"
	if _, err := s.store.createBootstrapToken(secret, time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollDeviceForTestWithVersion(t, s, secret, "0.1.16")
	if !resp.OK {
		t.Fatalf("enroll failed: %s", resp.Error)
	}
	if len(resp.AWGProfiles) != 2 {
		t.Fatalf("expected two awg profiles, got %+v", resp.AWGProfiles)
	}
	if !strings.HasPrefix(resp.AWGProfiles["awg"].InternalIP, "10.13.13.") {
		t.Fatalf("base profile allocated from wrong subnet: %+v", resp.AWGProfiles["awg"])
	}
	if !strings.HasPrefix(resp.AWGProfiles["next"].InternalIP, "10.44.0.") {
		t.Fatalf("next profile allocated from wrong subnet: %+v", resp.AWGProfiles["next"])
	}

	oldBundle, err := s.buildClientBundleForClient(0, "0.1.15")
	if err != nil {
		t.Fatal(err)
	}
	if got := clientBundleAWGProfile(t, oldBundle.ConfigJSON); got != "awg" {
		t.Fatalf("old client route profile=%q want awg", got)
	}
	newBundle, err := s.buildClientBundleForClient(0, "0.1.16")
	if err != nil {
		t.Fatal(err)
	}
	if got := clientBundleAWGProfile(t, newBundle.ConfigJSON); got != "next" {
		t.Fatalf("new client route profile=%q want next", got)
	}
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	workerBundle, _, err := s.buildBundles(workers[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(workerBundle.ConfigJSON, `"awg_profiles"`) || !strings.Contains(workerBundle.ConfigJSON, "10.44.0.") {
		t.Fatalf("worker bundle missing awg_profiles: %s", workerBundle.ConfigJSON)
	}
}

func enrollDeviceForTestWithVersion(t *testing.T, s *server, token, version string) deviceEnrollResponse {
	t.Helper()
	raw, _ := json.Marshal(deviceEnrollRequest{
		BootstrapToken:  token,
		DeviceID:        "android-id",
		IdentityPubKey:  "identity-pub",
		IdentityKeyType: "ed25519",
		AWGPublicKey:    "device-awg-public",
		ClientVersion:   version,
	})
	resp, err := s.handleDeviceEnroll(make([]byte, 32), raw)
	if err != nil {
		t.Fatal(err)
	}
	typed, ok := resp.(deviceEnrollResponse)
	if !ok {
		t.Fatalf("unexpected response type %T", resp)
	}
	return typed
}

func clientBundleAWGProfile(t *testing.T, configJSON string) string {
	t.Helper()
	var root struct {
		Workers []struct {
			Routes []struct {
				Type    string `json:"type"`
				Profile string `json:"profile"`
			} `json:"routes"`
		} `json:"workers"`
	}
	if err := json.Unmarshal([]byte(configJSON), &root); err != nil {
		t.Fatal(err)
	}
	for _, worker := range root.Workers {
		for _, route := range worker.Routes {
			if route.Type == "awg" {
				return route.Profile
			}
		}
	}
	t.Fatalf("awg route not found: %s", configJSON)
	return ""
}
