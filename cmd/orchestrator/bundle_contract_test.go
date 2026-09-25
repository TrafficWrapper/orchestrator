package main

import (
	"encoding/json"
	"testing"
	"time"
)

// Contract test (client-config-v1 structure): a bundle built from the
// current worker's self_describe passes the rules apps 0.1.28–0.1.31 apply:
// schema 1, workers is an array, every route has string type/address and
// int port, one primary REALITY and one primary AWG route per worker, no
// forbidden keys, and the params those versions read are present.
func TestClientBundleMeetsOldAppParser(t *testing.T) {
	s := newTestServer(t)
	fixture := loadWorkerSelfDescribeFixture(t)
	rec, err := s.store.upsertPendingWorker("contract-worker", fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.approveWorker(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.store.recordAck(rec.ID, 1, "ok", "", nil, nil, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bundle, err := s.buildClientBundle()
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectForbiddenKeys([]byte(bundle.ConfigJSON)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema  int    `json:"schema"`
		NS      string `json:"ns"`
		Workers []struct {
			Routes []map[string]any `json:"routes"`
		} `json:"workers"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.NS != "client-config-v1" || len(doc.Workers) != 1 {
		t.Fatalf("root: schema=%d ns=%q workers=%d", doc.Schema, doc.NS, len(doc.Workers))
	}
	counts := map[string]int{}
	for _, route := range doc.Workers[0].Routes {
		typ, _ := route["type"].(string)
		addr, _ := route["address"].(string)
		port, isNum := route["port"].(float64)
		if typ == "" || addr == "" || !isNum || port != float64(int(port)) || port <= 0 {
			t.Fatalf("route fails the old parser: %v", route)
		}
		counts[typ]++
		params, _ := route["params"].(map[string]any)
		var want []string
		switch typ {
		case "reality":
			want = []string{"public_key", "publicKey", "short_id", "shortId", "server_name", "serverName", "security", "network", "fingerprint", "spiderX", "dest", "cohort_short_ids", "address_v6", "vision"}
		case "awg":
			want = []string{"endpoint", "public_key", "server_public", "server_public_key", "dialect", "dialect_id", "dns", "endpoint_v6", "awg_profiles"}
		}
		for _, key := range want {
			if _, ok := params[key]; !ok {
				t.Fatalf("%s params lack %s: %v", typ, key, params)
			}
		}
	}
	if counts["reality"] != 1 || counts["awg"] != 1 {
		t.Fatalf("primary routes per worker: %v", counts)
	}
}
