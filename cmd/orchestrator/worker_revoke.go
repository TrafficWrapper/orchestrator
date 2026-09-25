package main

import (
	"net/http"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Worker revocation (status "revoked", terminal).
//
// A worker that declares the revoked_status capability is refused right
// away. Older workers only understand a config bundle, so revocation is two
// phase for them: first they get a signed bundle with every protocol off and
// no devices (DesiredSeq+1), which their pull path applies and so drops all
// accounts; once they ack that seq, or after workerRevokeGrace, every call is
// refused. Live sessions on an old worker survive until reconnect, so the
// runbook rotates REALITY UUIDs after a revoke.
const (
	workerCapRevokedStatus = "revoked_status"
	workerRevokeGrace      = 10 * time.Minute

	workerCodeRevoked = "worker_revoked"
	workerCodePending = "worker_pending"
)

// workerCapabilities is what the worker declared in self_describe, plus what
// it sent in this very request (a downgraded image may leave a stale
// self_describe behind, so the request wins when present).
func workerCapabilities(rec workerRecord, request []string) []string {
	if len(request) > 0 {
		return request
	}
	raw, _ := rec.SelfDescribe["capabilities"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if text, ok := v.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func workerHasCapability(rec workerRecord, request []string, capability string) bool {
	return slices.Contains(workerCapabilities(rec, request), capability)
}

// workerRevokeFinal reports whether a revoked worker must now be refused
// outright rather than served its empty phase-one bundle.
func workerRevokeFinal(rec workerRecord, request []string, now time.Time) bool {
	if rec.Status != "revoked" {
		return false
	}
	if rec.RevokeFinal || workerHasCapability(rec, request, workerCapRevokedStatus) {
		return true
	}
	return rec.RevokedAt == nil || now.Sub(*rec.RevokedAt) >= workerRevokeGrace
}

// workerGetsDevices reports whether a worker may receive device credentials.
func workerGetsDevices(rec workerRecord) bool {
	return (rec.Status == "approved" || rec.Status == "active") && !rec.Disabled
}

type workerRefusal struct {
	OK     bool   `json:"ok"`
	Status string `json:"status"`
	Error  string `json:"error"`
	Code   string `json:"code"`
}

func workerRevokedResponse() workerRefusal {
	return workerRefusal{OK: false, Status: "revoked", Error: "worker revoked", Code: workerCodeRevoked}
}

func workerPendingResponse() workerRefusal {
	return workerRefusal{OK: false, Status: "pending", Error: "owner approval required", Code: workerCodePending}
}

// revokeWorker marks a worker revoked. Workers that never got devices are
// final immediately; others get one more (empty) config first.
func (s *orchStore) revokeWorker(id string) error {
	id = strings.TrimSpace(id)
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkers)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errWorkerNotFound
		}
		var rec workerRecord
		if err := s.openJSON(bucketWorkers, []byte(id), raw, &rec); err != nil {
			return err
		}
		if rec.Status == "revoked" {
			return nil
		}
		now := time.Now().UTC()
		hadDevices := rec.Status != "pending"
		rec.Status = "revoked"
		rec.RevokedAt = &now
		if hadDevices {
			rec.DesiredSeq = max(rec.DesiredSeq, 0) + 1
			rec.RevokeSeq = rec.DesiredSeq
		} else {
			rec.RevokeFinal = true
		}
		sealed, err := s.sealJSON(bucketWorkers, []byte(id), rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(id), sealed); err != nil {
			return err
		}
		// The other workers republish a client bundle without it.
		return s.bumpWorkerSeqsTx(tx)
	})
	if err == nil {
		s.touchDiscoveryWorkerRevision()
	}
	return err
}

// handleAdminWorkerRevoke revokes a worker for good. It needs step-up: a
// revoked key can never re-enroll.
func (s *server) handleAdminWorkerRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
		stepUpProof
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	rec, err := s.store.worker(req.ID)
	if err != nil {
		writeStoreError(w, http.StatusNotFound, err)
		return
	}
	if !s.stepUp(w, r, "worker_revoke", "revoke worker "+shortString(rec.ID, 16), req.stepUpProof) {
		return
	}
	if err := s.store.revokeWorker(rec.ID); err != nil {
		s.auditEvent(auditEntry{Event: "worker_revoke", IP: clientIP(r), Result: "failed", Fields: map[string]string{"worker_id": rec.ID}})
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.auditEvent(auditEntry{Event: "worker_revoke", IP: clientIP(r), Result: "ok", Fields: map[string]string{"worker_id": rec.ID}})
	writeJSON(w, map[string]any{"ok": true, "status": "revoked"})
}
