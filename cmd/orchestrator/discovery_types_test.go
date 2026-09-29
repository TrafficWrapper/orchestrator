package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// appDiscoveredBundle mirrors the types the app core decodes the discovery
// feed into (core/transport/discovery.go, awg/dialect.Dialect); one entry
// of the wrong type fails json.Unmarshal of the whole feed there.
type appDiscoveredBundle struct {
	Endpoints struct {
		AWG []struct {
			Priority        int    `json:"priority"`
			Endpoint        string `json:"endpoint"`
			EgressIP        string `json:"egress_ip,omitempty"`
			ServerPublicKey string `json:"server_public_key"`
			AWGPreset       struct {
				Jc, Jmin, Jmax, S1, S2, S3, S4 int
				H1                             string `json:"h1"`
				H2                             string `json:"h2"`
				H3                             string `json:"h3"`
				H4                             string `json:"h4"`
			} `json:"awg_preset"`
			WorkerID string `json:"worker_id"`
		} `json:"awg"`
		Reality []struct {
			Priority    int    `json:"priority"`
			Transport   string `json:"transport,omitempty"`
			Address     string `json:"address,omitempty"`
			EgressIP    string `json:"egress_ip,omitempty"`
			Port        int    `json:"port,omitempty"`
			UUID        string `json:"uuid,omitempty"`
			Flow        string `json:"flow,omitempty"`
			Security    string `json:"security,omitempty"`
			Network     string `json:"network,omitempty"`
			ServerName  string `json:"serverName,omitempty"`
			PublicKey   string `json:"publicKey,omitempty"`
			ShortID     string `json:"shortId,omitempty"`
			Fingerprint string `json:"fingerprint,omitempty"`
			SpiderX     string `json:"spiderX,omitempty"`
			WorkerID    string `json:"worker_id"`
		} `json:"reality"`
	} `json:"endpoints"`
}

func discoveryTypeWorker(t *testing.T, s *server, seed byte, awg, reality map[string]any) workerRecord {
	t.Helper()
	self := map[string]any{"egress_ip": "203.0.113.5", "awg": awg}
	if reality != nil {
		self["reality"] = reality
	}
	rec, err := s.store.upsertPendingWorker(protocol.KeyToBase64(bytes.Repeat([]byte{seed}, 32)), self)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.store.worker(rec.ID)
	return rec
}

func goodAWGSection() map[string]any {
	return map[string]any{"endpoint": "203.0.113.5:51888", "port": 51888, "public_key": testAWGPublicKey, "subnet": "10.13.13.0/24",
		"awg_preset": map[string]any{"jc": 4, "jmin": 40, "jmax": 70, "s1": 20, "s2": 30, "h1": "1", "h2": "2", "h3": "3", "h4": "4"}}
}

// R2 ORC-H3: one worker with wrongly typed feed fields must not break the
// app's decoding of the whole feed; its entry is dropped, others stay.
func TestDiscoveryFeedDropsWronglyTypedEntries(t *testing.T) {
	for _, mode := range []string{discoveryModeReduced, discoveryModeFull} {
		s := newTestServer(t)
		s.cfg.DiscoveryPublic = mode
		good := discoveryTypeWorker(t, s, 1, goodAWGSection(), map[string]any{"address": "203.0.113.5", "port": 443, "publicKey": testRealityPublicKey, "shortId": "abcd"})
		badPreset := goodAWGSection()
		badPreset["awg_preset"] = "wide"
		discoveryTypeWorker(t, s, 2, badPreset, nil)
		badField := goodAWGSection()
		badField["awg_preset"] = map[string]any{"jc": "4", "h1": 1}
		discoveryTypeWorker(t, s, 3, badField, nil)
		discoveryTypeWorker(t, s, 4, goodAWGSection(), map[string]any{"address": "203.0.113.6", "port": "443", "publicKey": testRealityPublicKey})
		jsonText, err := s.discoveryBundleJSON(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		var doc appDiscoveredBundle
		if err := json.Unmarshal([]byte(jsonText), &doc); err != nil {
			t.Fatalf("%s: app cannot decode the feed: %v\n%s", mode, err, jsonText)
		}
		found := false
		for _, e := range doc.Endpoints.AWG {
			found = found || e.WorkerID == good.ID
		}
		if !found || len(doc.Endpoints.AWG) < 2 {
			t.Fatalf("%s: good workers missing: %+v", mode, doc.Endpoints.AWG)
		}
	}
}
