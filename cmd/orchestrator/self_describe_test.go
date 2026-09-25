package main

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loadWorkerSelfDescribeFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/worker_self_describe_master.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// Contract test: what the current worker master reports passes the
// sanitizer untouched — no section or field is dropped and nothing alerts.
func TestSelfDescribeWorkerFixturePassesUnchanged(t *testing.T) {
	fixture := loadWorkerSelfDescribeFixture(t)
	clean, report := sanitizeSelfDescribe(fixture)
	if report.Rejected || report.Forbidden || len(report.Issues) != 0 {
		t.Fatalf("fixture reported: %+v", report)
	}
	if !reflect.DeepEqual(clean, fixture) {
		t.Fatal("sanitizer changed the worker fixture")
	}
}

func TestSelfDescribeDropsUnknownAndOperatorOnlyKeys(t *testing.T) {
	fixture := loadWorkerSelfDescribeFixture(t)
	for key, value := range map[string]any{"priority": -100, "weight": 1000, "label": "x", "region": "eu", "extra": true} {
		fixture[key] = value
	}
	clean, report := sanitizeSelfDescribe(fixture)
	for _, key := range []string{"priority", "weight", "label", "region", "extra"} {
		if _, ok := clean[key]; ok {
			t.Fatalf("%s must be dropped", key)
		}
	}
	if report.Forbidden || report.Rejected {
		t.Fatalf("unknown keys must not reject the worker: %+v", report)
	}
	rec := workerRecord{SelfDescribe: clean}
	if effectiveWorkerPriority(rec) != 10 || effectiveWorkerWeight(rec) != 100 {
		t.Fatal("priority and weight must default to the operator values")
	}
}

func TestSelfDescribeLimits(t *testing.T) {
	fixture := loadWorkerSelfDescribeFixture(t)
	fixture["reality"].(map[string]any)["dest"] = strings.Repeat("a", 300)
	profiles := fixture["awg_profiles"].([]any)
	for len(profiles) < 40 {
		profiles = append(profiles, profiles[0])
	}
	fixture["awg_profiles"] = profiles
	clean, report := sanitizeSelfDescribe(fixture)
	if _, ok := clean["reality"].(map[string]any)["dest"]; ok {
		t.Fatal("oversized string must be dropped")
	}
	if got := len(clean["awg_profiles"].([]any)); got != selfDescribeMaxProfiles {
		t.Fatalf("profiles=%d want %d", got, selfDescribeMaxProfiles)
	}
	if len(report.Issues) == 0 {
		t.Fatal("limits must be reported")
	}
	huge := map[string]any{"hostname": strings.Repeat("h", 200), "health": map[string]any{}}
	blob := make([]any, 0, 400)
	for range 400 {
		blob = append(blob, strings.Repeat("x", 200))
	}
	huge["health"].(map[string]any)["blob"] = blob
	if _, report := sanitizeSelfDescribe(huge); !report.Rejected {
		t.Fatal("self_describe over 64 KiB must be rejected")
	}
}

// A malformed section alerts but is kept: no silent drop of a worker's route.
func TestSelfDescribeMalformedSectionsAlertButStay(t *testing.T) {
	clean, report := sanitizeSelfDescribe(map[string]any{
		"reality": map[string]any{"address": "bad host!", "port": 70000, "public_key": "short"},
	})
	if _, ok := clean["reality"]; !ok {
		t.Fatal("malformed reality section must be kept")
	}
	if len(report.Issues) != 3 {
		t.Fatalf("issues=%v", report.Issues)
	}
}

func TestSelfDescribeTooLargeKeepsPreviousDescription(t *testing.T) {
	s := newTestServer(t)
	w := addApprovedWorkerWithStatic(t, s, "big-worker")
	before, _ := s.store.worker(w.ID)
	huge := map[string]any{}
	for i := range 2000 {
		huge[strings.Repeat("k", 10)+string(rune('a'+i%26))+strings.Repeat("v", i%50)] = strings.Repeat("x", 60)
	}
	huge["hostname"] = strings.Repeat("y", 100)
	blob := make([]any, 0, 400)
	for range 400 {
		blob = append(blob, strings.Repeat("z", 200))
	}
	huge["health"] = map[string]any{"blob": blob}
	if err := s.store.updateWorkerHeartbeat(w.ID, before.DesiredSeq, huge); err != nil {
		t.Fatal(err)
	}
	after, _ := s.store.worker(w.ID)
	if !reflect.DeepEqual(after.SelfDescribe, before.SelfDescribe) || len(after.SelfDescribeIssues) == 0 {
		t.Fatalf("oversized report must keep the previous description and record an issue: %v", after.SelfDescribeIssues)
	}
}

// ORC-H3: one worker with a secret-looking key is left out; every other
// worker's pull, enrollment bundle and discovery keep working.
func TestForbiddenKeyExcludesOnlyThatWorker(t *testing.T) {
	s := newTestServer(t)
	good := addApprovedWorkerWithStatic(t, s, "good-worker")
	bad := addApprovedWorkerWithStatic(t, s, "bad-worker")
	now := time.Now().UTC()
	for _, id := range []string{good.ID, bad.ID} {
		rec, _ := s.store.worker(id)
		if _, _, err := s.store.recordAck(id, rec.DesiredSeq, "ok", "", nil, nil, nil, now); err != nil {
			t.Fatal(err)
		}
	}
	badRec, _ := s.store.worker(bad.ID)
	self := cloneMap(badRec.SelfDescribe)
	reality := cloneMap(self["reality"].(map[string]any))
	reality["private_key"] = "secret"
	self["reality"] = reality
	if _, _, err := s.store.recordAck(bad.ID, badRec.DesiredSeq, "ok", "", self, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.store.worker(bad.ID)
	if !stored.SelfDescribeForbidden {
		t.Fatal("forbidden key must be flagged")
	}
	if _, ok := stored.SelfDescribe["reality"].(map[string]any)["private_key"]; ok {
		t.Fatal("forbidden key must not be stored")
	}
	bundle, err := s.buildClientBundle(0)
	if err != nil {
		t.Fatalf("bundle must still build: %v", err)
	}
	if !strings.Contains(bundle.ConfigJSON, good.ID) || strings.Contains(bundle.ConfigJSON, bad.ID) {
		t.Fatal("bundle must carry the good worker only")
	}
	if _, err := s.discoveryBundleJSON(now); err != nil {
		t.Fatalf("discovery must still build: %v", err)
	}
	// A clean report restores the worker.
	delete(reality, "private_key")
	if _, _, err := s.store.recordAck(bad.ID, badRec.DesiredSeq, "ok", "", self, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	bundle, _ = s.buildClientBundle(0)
	if !strings.Contains(bundle.ConfigJSON, bad.ID) {
		t.Fatal("worker must return after a clean self_describe")
	}
}

func TestFindForbiddenKeyReportsPath(t *testing.T) {
	path, ok := findForbiddenKey(map[string]any{"a": []any{map[string]any{"b": map[string]any{"PSK2": 1}}}})
	if !ok || path != "a.[0].b.PSK2" {
		t.Fatalf("path=%q ok=%t", path, ok)
	}
	if _, ok := findForbiddenKey(map[string]any{"a": []any{"x", map[string]any{"y": 1}}}); ok {
		t.Fatal("clean tree flagged")
	}
}

func TestUpsertPendingWorkerRejectsKeyMismatch(t *testing.T) {
	s := newTestServer(t)
	rec, err := s.store.upsertPendingWorker("key-a", map[string]any{"hostname": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.updateWorker(rec.ID, func(w *workerRecord) error {
		w.StaticPublicKey = "someone-else"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.upsertPendingWorker("key-a", map[string]any{"hostname": "b"}); err == nil {
		t.Fatal("upsert with a different static key must fail")
	}
}

func awgWorker(id, subnet string, extra ...map[string]any) workerRecord {
	self := map[string]any{"awg": map[string]any{"endpoint": "203.0.113.1:51888", "port": 51888, "public_key": "k", "subnet": subnet}}
	if len(extra) > 0 {
		profiles := []any{}
		for _, p := range extra {
			profiles = append(profiles, p)
		}
		self["awg_profiles"] = profiles
	}
	return workerRecord{ID: id, Status: "active", SelfDescribe: self}
}

// ORC-M5: the profile set is the fleet's union with majority subnets; a
// disabled worker or a bogus subnet cannot shape device allocation.
func TestFleetAWGProfilesUnionAndConflicts(t *testing.T) {
	disabled := awgWorker("00-disabled", "10.50.0.0/24")
	disabled.Disabled = true
	workers := []workerRecord{
		awgWorker("00-tiny", "10.13.13.0/30"),
		disabled,
		awgWorker("10-b", "10.13.13.0/24"),
		awgWorker("20-c", "10.13.13.0/24", map[string]any{"profile": "awg2", "subnet": "10.14.14.0/24", "min_version_code": 131}),
		awgWorker("30-d", "10.99.0.0/24"),
	}
	profiles, conflicts := fleetAWGProfiles(workers)
	got := map[string]string{}
	for _, p := range profiles {
		got[p.Name] = p.Subnet
	}
	if got["awg"] != "10.13.13.0/24" || got["awg2"] != "10.14.14.0/24" || len(got) != 2 {
		t.Fatalf("profiles=%v", got)
	}
	if !conflicts["00-tiny"] || !conflicts["30-d"] || conflicts["10-b"] || conflicts["20-c"] || conflicts["00-disabled"] {
		t.Fatalf("conflicts=%v", conflicts)
	}
}

func TestPublishableRoutesStripsSinksAndIncompleteRoutes(t *testing.T) {
	routes := publishableRoutes("w", []any{
		map[string]any{"type": "reality", "address": "a", "port": 443, "discovery_url": "http://x", "params": map[string]any{"discovery_urls": []any{"http://y"}}},
		map[string]any{"type": "awg", "address": "", "port": 51888},
		map[string]any{"type": "awg", "address": "a", "port": 0},
	})
	if len(routes) != 1 {
		t.Fatalf("routes=%v", routes)
	}
	route := routes[0].(map[string]any)
	if _, ok := route["discovery_url"]; ok {
		t.Fatal("discovery_url must be stripped")
	}
	if _, ok := route["params"].(map[string]any)["discovery_urls"]; ok {
		t.Fatal("params.discovery_urls must be stripped")
	}
}

func TestBotSafeTextAndLabels(t *testing.T) {
	if got := botSafeText("a\nApprove\u202e x\ty", 64); got != "a Approve x y" {
		t.Fatalf("got %q", got)
	}
	if got := botSafeText(strings.Repeat("z", 100), 10); len([]rune(got)) > 10 {
		t.Fatalf("not truncated: %q", got)
	}
	if got := botEntityLabel("Phone", "twpk_0123456789abcdef"); got != "Phone [twpk_0123456]" {
		t.Fatalf("label=%q", got)
	}
}

func TestPendingWorkerNoticeBoundedAndRejectable(t *testing.T) {
	s := newTestServer(t)
	rec, err := s.store.upsertPendingWorker("pending-long", map[string]any{
		"reality": map[string]any{"address": "worker.example", "port": 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	bot.notifyPendingWorkers(context.Background())
	msg := mock.lastSent()
	if !strings.Contains(msg.Text, "address: worker.example") {
		t.Fatalf("notice=%q", msg.Text)
	}
	if len(msg.Keyboard.InlineKeyboard[0]) != 2 || msg.Keyboard.InlineKeyboard[0][1].CallbackData != "worker:reject:"+rec.ID {
		t.Fatalf("reject button missing: %+v", msg.Keyboard)
	}
	bot.handleWorkerCallback(context.Background(), telegramCallbackQuery{ID: "cb", Data: "worker:reject:" + rec.ID})
	if _, err := s.store.worker(rec.ID); err == nil {
		t.Fatal("rejected pending worker must be deleted")
	}
}

func TestSelfDescribeIssuesRaiseWorkerAlert(t *testing.T) {
	now := time.Now().UTC()
	rec := workerRecord{ID: "w1", Status: "active", LastAckAt: &now, SelfDescribeForbidden: true, SelfDescribeIssues: []string{"forbidden key reality.psk2"}}
	entry, ok := botWorkerProblemEntry(rec, now)
	if !ok || entry.Kind != "worker_self_describe" || !strings.Contains(entry.Detail, "excluded") {
		t.Fatalf("entry=%+v ok=%t", entry, ok)
	}
}
