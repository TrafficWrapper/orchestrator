package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

func (s *server) pruneOldAPKReleases(keepN int, currentSeq int64) error {
	return pruneOldAPKReleaseDirs(filepath.Join(s.cfg.StateDir, "apk", "releases"), keepN, currentSeq)
}

func pruneOldAPKReleaseDirs(root string, keepN int, currentSeq int64) error {
	if keepN < 1 {
		keepN = 1
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var seqs []int64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		seq, err := strconv.ParseInt(entry.Name(), 10, 64)
		if err != nil || seq <= 0 {
			continue
		}
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] > seqs[j] })
	keep := map[int64]bool{currentSeq: true}
	for _, seq := range seqs {
		if len(keep) >= keepN {
			break
		}
		keep[seq] = true
	}
	var errs []error
	for _, seq := range seqs {
		if keep[seq] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, strconv.FormatInt(seq, 10))); err != nil {
			errs = append(errs, fmt.Errorf("remove release %d: %w", seq, err))
		}
	}
	return errors.Join(errs...)
}
