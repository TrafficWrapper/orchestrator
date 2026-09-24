package main

import (
	"os"
	"path/filepath"
	"testing"
)

func publishTestAPK(t *testing.T, s *server, seq int64, body, manifestJSON string) (apkReleaseRecord, error) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "in.apk")
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rec := apkReleaseRecord{
		Seq:       seq,
		APKName:   "app.apk",
		APKSHA256: sha256HexBytes([]byte(body)),
		APKSize:   int64(len(body)),
	}
	return s.storeAPKRelease(rec, manifestJSON, "sig", f, nil)
}

func TestStoreAPKReleaseRejectsStaleSeqWithoutTouchingLiveFiles(t *testing.T) {
	s := newTestServer(t)
	live, err := publishTestAPK(t, s, 1, "apk one", `{"seq":1}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishTestAPK(t, s, 1, "apk two", `{"seq":1,"other":true}`); err == nil {
		t.Fatal("publishing an already-live seq must fail")
	}
	manifest, err := os.ReadFile(live.ManifestPath)
	if err != nil || string(manifest) != `{"seq":1}` {
		t.Fatalf("live manifest was modified: %q err=%v", manifest, err)
	}
	apk, err := os.ReadFile(live.APKPath)
	if err != nil || string(apk) != "apk one" {
		t.Fatalf("live apk was modified: %q err=%v", apk, err)
	}
	next, err := publishTestAPK(t, s, 2, "apk two", `{"seq":2}`)
	if err != nil {
		t.Fatal(err)
	}
	if cur, _, _ := s.store.currentAPKRelease(); cur.Seq != 2 || cur.APKPath != next.APKPath {
		t.Fatalf("current release=%+v", cur)
	}
	entries, _ := os.ReadDir(filepath.Join(s.cfg.StateDir, "apk", "releases"))
	for _, e := range entries {
		if e.Name() != "1" && e.Name() != "2" {
			t.Fatalf("unexpected leftover %q", e.Name())
		}
	}
}
