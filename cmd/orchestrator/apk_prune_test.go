package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPruneOldAPKReleaseDirsKeepsNewestAndCurrent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "releases")
	for _, name := range []string{"1", "2", "3", "4", "5", "6", "7", "notes"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneOldAPKReleaseDirs(root, 3, 2); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"2", "6", "7", "notes"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("expected %s to be kept: %v", name, err)
		}
	}
	for _, name := range []string{"1", "3", "4", "5"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be pruned, err=%v", name, err)
		}
	}
}
