package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Client bundle seq (client-config-v1): a persistent, strictly increasing
// platform counter, not a function of worker seqs. Clients reject seq below
// what they have seen and ignore equal seq, so:
//
//   - one seq always means one content: the published content is stored with
//     its seq and every pull and enrollment serves it, re-signed only for
//     fresher issued_at/expires_at;
//   - a content change is published under seq+1 once the same new content is
//     seen on two consecutive checks (clientBundleCheckEvery apart), which
//     also debounces bursts;
//   - content older than 2/3 of the bundle TTL is re-published under seq+1 so
//     clients never sit on an expired bundle;
//   - every publish raises each serving worker's DesiredSeq to at least the
//     counter, so a rolled-back binary that derives seq from max(DesiredSeq)
//     still never goes below what clients have seen.
//
// First start (no stored counter) migrates to max(DesiredSeq, AppliedSeq)
// over all workers + clientSeqMigrationGap, but not below
// ORCH_CLIENT_SEQ_FLOOR.
const (
	clientSeqMigrationGap  = 1_000_000
	clientAppliedSeqWindow = 10_000
	clientBundleCheckEvery = 5 * time.Second
	clientBundleSignReuse  = time.Minute
)

var metaClientBundle = []byte("client_bundle_state")

type clientBundleState struct {
	Seq         int64     `json:"seq"`
	ContentJSON string    `json:"content_json"`
	ContentHash string    `json:"content_hash"`
	PublishedAt time.Time `json:"published_at"`
	// CandidateHash is a changed content seen once and waiting for a
	// second, identical check before it is published.
	CandidateHash string `json:"candidate_hash,omitempty"`
}

func (s *orchStore) clientBundleState() (clientBundleState, bool, error) {
	var st clientBundleState
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaClientBundle)
		if raw == nil {
			return nil
		}
		found = true
		return s.openJSON(bucketMeta, metaClientBundle, raw, &st)
	})
	return st, found, err
}

func (s *orchStore) putClientBundleStateTx(tx *bolt.Tx, st clientBundleState) error {
	sealed, err := s.sealJSON(bucketMeta, metaClientBundle, st)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketMeta).Put(metaClientBundle, sealed)
}

// raiseServingWorkersTx keeps DesiredSeq >= seq (and bumped) for every worker
// that serves clients, so they pull the new client bundle.
func (s *orchStore) raiseServingWorkersTx(tx *bolt.Tx, seq int64) error {
	tx.OnCommit(s.signalWorkerSeqChange)
	return rewriteBucket(tx.Bucket(bucketWorkers), func(k, raw []byte) ([]byte, error) {
		var rec workerRecord
		if err := s.openJSON(bucketWorkers, k, raw, &rec); err != nil {
			return nil, err
		}
		if !workerGetsDevices(rec) {
			return nil, nil
		}
		rec.DesiredSeq = max(rec.DesiredSeq+1, seq)
		return s.sealJSON(bucketWorkers, k, rec)
	})
}

// migratedClientSeq is the first counter value: above anything a worker or
// client can have seen from the old max(DesiredSeq) scheme.
func migratedClientSeq(tx *bolt.Tx, s *orchStore, floor int64) (int64, error) {
	var highest int64
	err := tx.Bucket(bucketWorkers).ForEach(func(k, raw []byte) error {
		var rec workerRecord
		if err := s.openJSON(bucketWorkers, k, raw, &rec); err != nil {
			return err
		}
		highest = max(highest, rec.DesiredSeq, rec.AppliedSeq)
		return nil
	})
	return max(highest+clientSeqMigrationGap, floor), err
}

// publishClientContent records content as the client bundle content and
// returns the (possibly new) state. force publishes a change without waiting
// for a second identical check.
func (s *orchStore) publishClientContent(contentJSON string, now time.Time, ttl time.Duration, floor int64, force bool) (clientBundleState, error) {
	sum := sha256.Sum256([]byte(contentJSON))
	hash := hex.EncodeToString(sum[:])
	var out clientBundleState
	err := s.db.Update(func(tx *bolt.Tx) error {
		var st clientBundleState
		raw := tx.Bucket(bucketMeta).Get(metaClientBundle)
		first := raw == nil
		if !first {
			if err := s.openJSON(bucketMeta, metaClientBundle, raw, &st); err != nil {
				return err
			}
		}
		switch {
		case first:
			seq, err := migratedClientSeq(tx, s, floor)
			if err != nil {
				return err
			}
			st = clientBundleState{Seq: seq}
		case st.ContentHash == hash:
			st.CandidateHash = ""
			if now.Sub(st.PublishedAt) < ttl*2/3 {
				if st.Seq < floor {
					break
				}
				out = st
				return nil
			}
			// Re-publish the same content before clients' copy expires.
			st.Seq++
		case !force && st.CandidateHash != hash:
			st.CandidateHash = hash
			out = st
			return s.putClientBundleStateTx(tx, st)
		default:
			st.Seq++
		}
		st.Seq = max(st.Seq, floor)
		st.ContentJSON = contentJSON
		st.ContentHash = hash
		st.PublishedAt = now
		st.CandidateHash = ""
		if err := s.putClientBundleStateTx(tx, st); err != nil {
			return err
		}
		out = st
		return s.raiseServingWorkersTx(tx, st.Seq)
	})
	return out, err
}

// raiseClientSeq moves the counter to at least seq (a worker reporting a
// higher applied seq after a restore, or an operator raising the floor) and
// republishes the same content under it.
func (s *orchStore) raiseClientSeq(seq int64, now time.Time) (clientBundleState, bool, error) {
	var out clientBundleState
	raised := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaClientBundle)
		if raw == nil {
			return errors.New("client bundle not published yet")
		}
		if err := s.openJSON(bucketMeta, metaClientBundle, raw, &out); err != nil {
			return err
		}
		if seq <= out.Seq {
			return nil
		}
		out.Seq = seq
		out.PublishedAt = now
		raised = true
		if err := s.putClientBundleStateTx(tx, out); err != nil {
			return err
		}
		return s.raiseServingWorkersTx(tx, out.Seq)
	})
	return out, raised, err
}

// observeClientAppliedSeq handles an ack's client_applied_seq: a worker that
// already applied a client bundle at or above the counter (restored DB)
// moves the counter past it, within a bounded window; anything further is
// only reported.
func (s *server) observeClientAppliedSeq(rec workerRecord, applied int64) {
	if applied <= 0 || !workerGetsDevices(rec) {
		return
	}
	st, found, err := s.store.clientBundleState()
	if err != nil || !found || applied < st.Seq {
		return
	}
	if applied > st.Seq+clientAppliedSeqWindow {
		log.Printf("ALERT worker %s reports client_applied_seq=%d far above counter %d; not following (raise the floor if this is a restore)", rec.ID, applied, st.Seq)
		return
	}
	if _, _, err := s.store.raiseClientSeq(applied+1, time.Now().UTC()); err != nil {
		log.Printf("client seq raise after worker %s report failed: %v", rec.ID, err)
	}
}

// refreshClientBundle recomputes the shared content and publishes it when
// the change is confirmed (or at once with force).
func (s *server) refreshClientBundle(force bool) (clientBundleState, error) {
	content, err := s.clientBundleContent()
	if err != nil {
		return clientBundleState{}, err
	}
	contentJSON, err := canonicalJSON(content)
	if err != nil {
		return clientBundleState{}, err
	}
	if err := rejectForbiddenKeys([]byte(contentJSON)); err != nil {
		return clientBundleState{}, err
	}
	return s.store.publishClientContent(contentJSON, time.Now().UTC(), s.clientBundleTTL(), s.cfg.ClientSeqFloor, force)
}

func (s *server) clientBundleTTL() time.Duration {
	if s.cfg.ClientBundleTTL > 0 {
		return s.cfg.ClientBundleTTL
	}
	return 24 * time.Hour
}

// checkClientBundle is one publisher pass; operator actions since the last
// pass publish without the confirmation delay.
func (s *server) checkClientBundle() (clientBundleState, error) {
	return s.refreshClientBundle(s.store.clientContentForced.Swap(false))
}

// runClientBundlePublisher checks the shared content every
// clientBundleCheckEvery.
func (s *server) runClientBundlePublisher(ctx context.Context) {
	ticker := time.NewTicker(clientBundleCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.checkClientBundle(); err != nil {
				log.Printf("client bundle publish: %v", err)
			}
		}
	}
}

// buildClientBundle returns the signed shared client bundle for the published
// seq. Enrollment and pull always get this same bundle.
func (s *server) buildClientBundle() (signedConfig, error) {
	st, found, err := s.store.clientBundleState()
	if err != nil {
		return signedConfig{}, err
	}
	if !found {
		if st, err = s.refreshClientBundle(true); err != nil {
			return signedConfig{}, err
		}
	}
	now := time.Now().UTC()
	s.clientBundleMu.Lock()
	cached := s.clientBundleSigned
	s.clientBundleMu.Unlock()
	if cached.seq == st.Seq && now.Sub(cached.issued) < clientBundleSignReuse && !now.Before(cached.issued) {
		return cached.signed, nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(st.ContentJSON), &payload); err != nil {
		return signedConfig{}, err
	}
	payload["seq"] = st.Seq
	payload["issued_at"] = now.Format(time.RFC3339)
	payload["expires_at"] = now.Add(s.clientBundleTTL()).Format(time.RFC3339)
	clientJSON, err := canonicalJSON(payload)
	if err != nil {
		return signedConfig{}, err
	}
	signed, err := s.signer.sign(clientJSON)
	if err != nil {
		return signedConfig{}, err
	}
	s.clientBundleMu.Lock()
	s.clientBundleSigned = signedClientBundle{seq: st.Seq, issued: now, signed: signed}
	s.clientBundleMu.Unlock()
	return signed, nil
}

type signedClientBundle struct {
	seq    int64
	issued time.Time
	signed signedConfig
}

// handleAdminClientSeqFloor raises the client seq counter (after restoring an
// older DB). Needs step-up: it moves every client and worker forward.
func (s *server) handleAdminClientSeqFloor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Floor int64 `json:"floor"`
		stepUpProof
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Floor <= 0 {
		writeError(w, "floor must be positive", http.StatusBadRequest)
		return
	}
	if _, err := s.buildClientBundle(); err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	if !s.stepUp(w, r, "client_seq_floor", "raise client config seq to "+strconv.FormatInt(req.Floor, 10), req.stepUpProof) {
		return
	}
	st, raised, err := s.store.raiseClientSeq(req.Floor, time.Now().UTC())
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditEvent(auditEntry{Event: "client_seq_floor", IP: clientIP(r), Result: "ok", Fields: map[string]string{"seq": strconv.FormatInt(st.Seq, 10), "raised": strconv.FormatBool(raised)}})
	writeJSON(w, map[string]any{"ok": true, "seq": st.Seq, "raised": raised})
}
