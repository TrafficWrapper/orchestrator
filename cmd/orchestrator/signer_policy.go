package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Signer policy (ORC-L8). The signer only signs documents of known
// namespaces, and a document's seq may rise by at most signerMaxSeqStep over
// the highest seq it signed before for the same stream (a namespace, per
// worker for worker configs), persisted next to the key. A briefly
// compromised orchestrator therefore cannot obtain a signature on a huge seq
// that every worker and app would then accept forever. The step leaves room
// for the one-time client seq migration jump (+1,000,000) and for floor
// raises, which can be repeated.
const (
	signerMaxSeqStep = 10_000_000
	// signerMaxFirstSeq bounds the first seq seen for a stream.
	signerMaxFirstSeq = 1 << 40

	nsClientConfig = "client-config-v1"
	nsWorkerConfig = "worker-config-v1"
	nsDiscovery    = "rendezvous-v1"
)

type signerPolicy struct {
	path string
	mu   sync.Mutex
	last map[string]int64
}

type signerPolicyState struct {
	Last map[string]int64 `json:"last"`
}

func loadSignerPolicy(path string) (*signerPolicy, error) {
	p := &signerPolicy{path: path, last: map[string]int64{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	var st signerPolicyState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("signer policy state %s: %w", path, err)
	}
	if st.Last != nil {
		p.last = st.Last
	}
	return p, nil
}

func signerPolicyPath(keyPath string) string {
	return filepath.Join(filepath.Dir(keyPath), "sign-policy.json")
}

// admit checks a document against the allowed namespaces and the seq step,
// and records a new highest seq. Lower or equal seqs (re-signing with a new
// issued_at, restores) are always allowed.
func (p *signerPolicy) admit(message string, namespaces ...string) error {
	var doc struct {
		NS       string `json:"ns"`
		Seq      *int64 `json:"seq"`
		WorkerID string `json:"worker_id"`
	}
	if err := json.Unmarshal([]byte(message), &doc); err != nil {
		return errors.New("signer policy: message is not a JSON document")
	}
	allowed := false
	for _, ns := range namespaces {
		allowed = allowed || doc.NS == ns
	}
	if !allowed {
		return fmt.Errorf("signer policy: namespace %q not allowed", doc.NS)
	}
	if doc.Seq == nil || *doc.Seq < 0 {
		return errors.New("signer policy: seq is missing")
	}
	stream := doc.NS
	if doc.NS == nsWorkerConfig {
		if strings.TrimSpace(doc.WorkerID) == "" {
			return errors.New("signer policy: worker_id is missing")
		}
		stream += "/" + doc.WorkerID
	}
	seq := *doc.Seq
	p.mu.Lock()
	defer p.mu.Unlock()
	last, seen := p.last[stream]
	switch {
	case !seen && seq > signerMaxFirstSeq:
		return fmt.Errorf("signer policy: first seq %d for %s is too large", seq, stream)
	case seen && seq > last && seq-last > signerMaxSeqStep:
		return fmt.Errorf("signer policy: seq %d for %s jumps more than %d past %d", seq, stream, signerMaxSeqStep, last)
	case seen && seq <= last:
		return nil
	}
	p.last[stream] = seq
	return p.saveLocked()
}

func (p *signerPolicy) saveLocked() error {
	if p.path == "" {
		return nil
	}
	raw, err := json.Marshal(signerPolicyState{Last: p.last})
	if err != nil {
		return err
	}
	return writeFileAtomic(p.path, raw, 0o600)
}
