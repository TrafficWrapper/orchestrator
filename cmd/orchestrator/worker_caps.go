package main

import (
	"slices"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Worker capability values the orchestrator understands (see CONTRACT.md).
// A worker announces them in self_describe.capabilities and, for the running
// binary, in the optional worker_capabilities of each pull.
const (
	workerCapDesiredStateEnabled = "desired_state_enabled"

	maxWorkerCapabilities  = 32
	maxWorkerCapabilityLen = 64
)

var knownWorkerCapabilities = []string{
	workerCapRealityFlow,
	workerCapDesiredStateEnabled,
	workerCapRevokedStatus,
	workerCapAPKFetch,
}

// sanitizeWorkerCapabilities keeps only known capability values, trimmed,
// deduplicated and sorted. At most maxWorkerCapabilities input entries are
// looked at; unknown or oversized entries are dropped without an error.
func sanitizeWorkerCapabilities(in []string) []string {
	if len(in) > maxWorkerCapabilities {
		in = in[:maxWorkerCapabilities]
	}
	var out []string
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maxWorkerCapabilityLen {
			continue
		}
		if !slices.Contains(knownWorkerCapabilities, value) || slices.Contains(out, value) {
			continue
		}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

// setWorkerPullCapabilities stores the capabilities a worker sent in its
// latest pull. The record is written only when the value changed.
func (s *orchStore) setWorkerPullCapabilities(id string, caps []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		_, _, err := s.mutateWorkerTx(tx, id, func(rec *workerRecord) (bool, error) {
			if slices.Equal(rec.PullCapabilities, caps) {
				return false, nil
			}
			rec.PullCapabilities = slices.Clone(caps)
			return true, nil
		})
		return err
	})
}
