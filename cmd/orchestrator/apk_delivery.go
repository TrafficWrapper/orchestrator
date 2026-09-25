package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// APK delivery apart from config pull (ORC-M8, ORC-M15, ORC-M16, ORC-L22).
//
// A worker that declares apk_fetch_v1 in the worker_capabilities of its pull
// gets update_ref (manifest plus the APK's seq, name, sha256 and size) and
// fetches the APK in chunks over /w/v1/apk/chunk. Other workers get the APK
// inline only while it fits ORCH_APK_INLINE_MAX_BYTES; a refused inline is
// the update field left out entirely, and the config is always delivered.

const (
	workerCapAPKFetch = "apk_fetch_v1"

	defaultAPKInlineMaxBytes = 40 << 20
	// maxAPKInlineMaxBytes keeps inline responses inside what old workers
	// accept (128 MiB, with base64 and JSON growing the APK ~1.8x).
	maxAPKInlineMaxBytes = 64 << 20
	defaultAPKMaxBytes   = 200 << 20
	maxAPKMaxBytes       = uploadRequestBodyMaxBytes - (8 << 20)

	apkChunkMaxBytes = 4 << 20
	// maxConcurrentAPKChunks bounds chunk reads in flight.
	maxConcurrentAPKChunks = 8

	// apkInlineMaxFailures inline attempts of the same APK that the worker
	// never got past (it pulled again with the same have_seq) stop inline
	// delivery to it for apkInlineBackoff, doubling up to apkInlineBackoffMax.
	apkInlineMaxFailures = 2
	apkInlineBackoff     = 15 * time.Minute
	apkInlineBackoffMax  = 6 * time.Hour

	// Write deadlines for responses carrying APK bytes: a base allowance plus
	// time at apkMinWriteRate.
	apkWriteBase    = 60 * time.Second
	apkMinWriteRate = 256 << 10
)

// Codes of /w/v1/apk/chunk refusals.
const (
	apkCodeSuperseded = "release_superseded"
	apkCodeBadRange   = "bad_range"
)

// updateRef describes the current release for workers that fetch the APK in
// chunks.
type updateRef struct {
	APKSeq          int64  `json:"apk_seq"`
	APKName         string `json:"apk_name"`
	APKSHA256       string `json:"apk_sha256"`
	APKSize         int64  `json:"apk_size"`
	ManifestJSON    string `json:"manifest_json"`
	ManifestMinisig string `json:"manifest_minisig"`
}

type apkChunkRequest struct {
	WorkerID  string `json:"worker_id"`
	APKSeq    int64  `json:"apk_seq"`
	APKSHA256 string `json:"apk_sha256"`
	Offset    int64  `json:"offset"`
	Length    int64  `json:"length"`
}

type apkChunkResponse struct {
	OK         bool   `json:"ok"`
	ServerTime int64  `json:"server_time,omitempty"`
	Code       string `json:"code,omitempty"`
	Error      string `json:"error,omitempty"`
	Status     string `json:"status,omitempty"`
	TotalSize  int64  `json:"total_size,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	release    func()
}

func (r apkChunkResponse) releaseAfterWrite() {
	if r.release != nil {
		r.release()
	}
}

func (r apkChunkResponse) responseWriteTimeout() time.Duration {
	if r.DataBase64 == "" {
		return 0
	}
	return apkWriteTimeout(int64(len(r.DataBase64)))
}

// apkWriteTimeout bounds how long writing size bytes of APK may take, so a
// slow reader cannot hold a shipment slot forever (ORC-M16).
func apkWriteTimeout(size int64) time.Duration {
	return apkWriteBase + time.Duration(size/apkMinWriteRate)*time.Second
}

func (s *server) apkInlineMaxBytes() int64 {
	if s.cfg.APKInlineMaxBytes > 0 {
		return s.cfg.APKInlineMaxBytes
	}
	return defaultAPKInlineMaxBytes
}

func (s *server) apkMaxBytes() int64 {
	if s.cfg.APKMaxBytes > 0 {
		return s.cfg.APKMaxBytes
	}
	return defaultAPKMaxBytes
}

// validateAPKLimits rejects limits old workers cannot take.
func validateAPKLimits(cfg orchConfig) error {
	if cfg.APKInlineMaxBytes > maxAPKInlineMaxBytes {
		return fmt.Errorf("ORCH_APK_INLINE_MAX_BYTES=%d: must be at most %d", cfg.APKInlineMaxBytes, maxAPKInlineMaxBytes)
	}
	if cfg.APKMaxBytes > maxAPKMaxBytes {
		return fmt.Errorf("ORCH_APK_MAX_BYTES=%d: must be at most %d", cfg.APKMaxBytes, maxAPKMaxBytes)
	}
	return nil
}

// apkReleaseApplied reports whether the worker already serves rel: by the
// sha256 and seq it reports in distributed_apk when it reports a seq, else by
// the legacy ack marker.
func apkReleaseApplied(rec workerRecord, rel apkReleaseRecord) bool {
	if dist, ok := mapFromAny(rec.SelfDescribe["distributed_apk"]); ok {
		if seq := int64(intFromMap(dist, "seq", 0)); seq > 0 {
			return seq == rel.Seq && strings.EqualFold(stringFromMap(dist, "apk_sha256"), rel.APKSHA256)
		}
	}
	return rec.APKAppliedSeq == rel.Seq
}

// apkDelivery is what one pull carries for the APK.
type apkDelivery struct {
	update       *updateArtifact
	ref          *updateRef
	release      func()
	writeTimeout time.Duration
}

// apkDeliveryForPull decides the APK part of a pull. Failures to read the
// release only drop the APK from this pull (ORC-L22).
func (s *server) apkDeliveryForPull(worker workerRecord, haveSeq int64, requestCaps []string) (apkDelivery, error) {
	rel, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok {
		return apkDelivery{}, err
	}
	if haveSeq > 0 && apkReleaseApplied(worker, rel) {
		return apkDelivery{}, nil
	}
	// Only the running worker's own declaration counts: a stored
	// self_describe may predate an image downgrade.
	if slices.Contains(requestCaps, workerCapAPKFetch) {
		ref, err := s.cachedUpdateRef(rel)
		if err != nil {
			log.Printf("apk update_ref for worker %s: %v", worker.ID, err)
			return apkDelivery{}, s.store.clearWorkerAPKSent(worker.ID)
		}
		if err := s.store.markWorkerAPKSent(worker.ID, rel.Seq, worker.DesiredSeq); err != nil {
			return apkDelivery{}, err
		}
		return apkDelivery{ref: ref}, nil
	}
	if rel.APKSize > s.apkInlineMaxBytes() {
		log.Printf("apk seq=%d (%d bytes) exceeds the inline limit; worker %s gets config only until it supports %s", rel.Seq, rel.APKSize, worker.ID, workerCapAPKFetch)
		return apkDelivery{}, s.store.clearWorkerAPKSent(worker.ID)
	}
	now := time.Now().UTC()
	if worker.APKInlineSHA == rel.APKSHA256 && worker.APKInlineRetryAt != nil && now.Before(*worker.APKInlineRetryAt) {
		return apkDelivery{}, s.store.clearWorkerAPKSent(worker.ID)
	}
	release, acquired := s.acquireAPKShipment(worker.ID, apkShipmentWait)
	if !acquired {
		// The worker would otherwise stay on the old APK until an unrelated
		// seq bump: bump its own seq so its next nudge pulls again. The sent
		// markers are cleared so a later ack cannot mark an APK applied
		// that this pull did not carry (ORC-M15).
		log.Printf("apk shipment slots busy; worker %s will retry the update", worker.ID)
		if err := s.store.updateWorker(worker.ID, func(rec *workerRecord) error {
			if rec.DesiredSeq <= worker.DesiredSeq {
				rec.DesiredSeq = worker.DesiredSeq + 1
			}
			rec.APKSentSeq, rec.APKSentAtSeq = 0, 0
			return nil
		}); err != nil {
			return apkDelivery{}, err
		}
		return apkDelivery{}, nil
	}
	update, err := s.cachedUpdateArtifact(rel)
	if err != nil {
		release()
		log.Printf("apk read for worker %s: %v", worker.ID, err)
		return apkDelivery{}, s.store.clearWorkerAPKSent(worker.ID)
	}
	allowed, err := s.store.beginAPKInline(worker.ID, rel, haveSeq, worker.DesiredSeq, now)
	if err != nil || !allowed {
		release()
		return apkDelivery{}, err
	}
	return apkDelivery{update: update, release: release, writeTimeout: apkWriteTimeout(int64(len(update.APKBase64)))}, nil
}

// beginAPKInline records an inline shipment of rel. A worker that pulls again
// with the same have_seq after an inline shipment of the same APK never got
// past it (e.g. it ran out of memory); after apkInlineMaxFailures such
// attempts inline delivery stops for a growing backoff, with an alert.
func (s *orchStore) beginAPKInline(id string, rel apkReleaseRecord, haveSeq, atSeq int64, now time.Time) (bool, error) {
	allowed := true
	err := s.updateWorker(id, func(rec *workerRecord) error {
		failed := false
		if rec.APKInlineSHA != rel.APKSHA256 {
			rec.APKInlineSHA, rec.APKInlineFailures, rec.APKInlineRetryAt = rel.APKSHA256, 0, nil
		} else if rec.APKInlinePending && rec.APKInlineHaveSeq == haveSeq {
			rec.APKInlineFailures++
			failed = true
		}
		rec.APKInlineHaveSeq = haveSeq
		if failed && rec.APKInlineFailures >= apkInlineMaxFailures {
			backoff := min(apkInlineBackoff<<min(rec.APKInlineFailures-apkInlineMaxFailures, 5), apkInlineBackoffMax)
			retry := now.Add(backoff)
			rec.APKInlineRetryAt = &retry
			rec.APKInlinePending = false
			rec.APKSentSeq, rec.APKSentAtSeq = 0, 0
			allowed = false
			log.Printf("ALERT worker %s: inline APK seq=%d never applied after %d attempts; config only until %s", id, rel.Seq, rec.APKInlineFailures, retry.Format(time.RFC3339))
			return nil
		}
		// After a backoff one more attempt goes out; failing it again
		// doubles the backoff.
		rec.APKInlineRetryAt = nil
		rec.APKInlinePending = true
		rec.APKSentSeq, rec.APKSentAtSeq = rel.Seq, atSeq
		return nil
	})
	return allowed, err
}

// clearWorkerAPKSent drops the sent markers after a pull without the APK.
func (s *orchStore) clearWorkerAPKSent(id string) error {
	rec, err := s.worker(id)
	if err != nil || (rec.APKSentSeq == 0 && rec.APKSentAtSeq == 0) {
		return err
	}
	return s.updateWorker(id, func(rec *workerRecord) error {
		rec.APKSentSeq, rec.APKSentAtSeq = 0, 0
		return nil
	})
}

// acquireAPKShipment takes one of the global inline slots, at most one per
// worker (ORC-M16).
func (s *server) acquireAPKShipment(workerID string, wait time.Duration) (func(), bool) {
	s.apkShipOnce.Do(func() { s.apkShipSem = make(chan struct{}, maxConcurrentAPKShipments) })
	s.apkShipMu.Lock()
	if s.apkShipWorkers == nil {
		s.apkShipWorkers = map[string]bool{}
	}
	if s.apkShipWorkers[workerID] {
		s.apkShipMu.Unlock()
		return nil, false
	}
	s.apkShipWorkers[workerID] = true
	s.apkShipMu.Unlock()
	unmark := func() {
		s.apkShipMu.Lock()
		delete(s.apkShipWorkers, workerID)
		s.apkShipMu.Unlock()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case s.apkShipSem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.apkShipSem; unmark() }) }, true
	case <-timer.C:
		unmark()
		return nil, false
	}
}

// cachedUpdateRef reads the release manifest once per seq.
func (s *server) cachedUpdateRef(rel apkReleaseRecord) (*updateRef, error) {
	s.apkArtifactMu.Lock()
	defer s.apkArtifactMu.Unlock()
	if s.apkRef != nil && s.apkRef.APKSeq == rel.Seq {
		return s.apkRef, nil
	}
	manifestJSON, err := os.ReadFile(rel.ManifestPath)
	if err != nil {
		return nil, err
	}
	minisig, err := os.ReadFile(rel.MinisigPath)
	if err != nil {
		return nil, err
	}
	ref := &updateRef{
		APKSeq:          rel.Seq,
		APKName:         rel.APKName,
		APKSHA256:       strings.ToLower(rel.APKSHA256),
		APKSize:         rel.APKSize,
		ManifestJSON:    strings.TrimSpace(string(manifestJSON)),
		ManifestMinisig: strings.TrimSpace(string(minisig)),
	}
	s.apkRef = ref
	return ref, nil
}

// handleAPKChunk serves one range of the current release's APK.
func (s *server) handleAPKChunk(ctx context.Context, peer []byte, raw []byte) (any, error) {
	var req apkChunkRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return apkChunkResponse{OK: false, Error: err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return apkChunkResponse{OK: false, Error: "worker identity mismatch"}, nil
	}
	switch rec.Status {
	case "revoked":
		return apkChunkResponse{OK: false, Status: "revoked", Code: workerCodeRevoked, Error: "worker revoked"}, nil
	case "pending":
		return apkChunkResponse{OK: false, Status: "pending", Code: workerCodePending, Error: "owner approval required"}, nil
	}
	rel, ok, err := s.store.currentAPKRelease()
	if err != nil {
		return nil, err
	}
	// A re-signed manifest keeps the same APK: a download of an older seq
	// with the same sha256 goes on.
	if !ok || !strings.EqualFold(strings.TrimSpace(req.APKSHA256), rel.APKSHA256) || req.APKSeq > rel.Seq {
		return apkChunkResponse{OK: false, Code: apkCodeSuperseded, Error: "release superseded"}, nil
	}
	if req.Offset < 0 || req.Offset >= rel.APKSize || req.Length <= 0 || req.Length > apkChunkMaxBytes {
		return apkChunkResponse{OK: false, Code: apkCodeBadRange, Error: "bad range", TotalSize: rel.APKSize}, nil
	}
	length := min(req.Length, rel.APKSize-req.Offset)
	release, err := s.acquireAPKChunk(ctx)
	if err != nil {
		return nil, err
	}
	data, err := readAPKRange(rel.APKPath, req.Offset, length)
	if err != nil {
		release()
		log.Printf("apk chunk for worker %s: %v", rec.ID, err)
		return apkChunkResponse{OK: false, Error: "apk unavailable"}, nil
	}
	return apkChunkResponse{OK: true, TotalSize: rel.APKSize, DataBase64: base64.StdEncoding.EncodeToString(data), release: release}, nil
}

func readAPKRange(path string, offset, length int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buf := make([]byte, length)
	n, err := file.ReadAt(buf, offset)
	if err != nil && !(errors.Is(err, io.EOF) && int64(n) == length) {
		return nil, err
	}
	return buf, nil
}

func (s *server) acquireAPKChunk(ctx context.Context) (func(), error) {
	s.apkChunkOnce.Do(func() { s.apkChunkSem = make(chan struct{}, maxConcurrentAPKChunks) })
	select {
	case s.apkChunkSem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.apkChunkSem }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startupGrace reports whether the process started less than workerFreshTTL
// ago: worker silence during the orchestrator's own downtime is not a worker
// failure (ORC-L34).
func (s *server) startupGrace(now time.Time) bool {
	return !s.startedAt.IsZero() && now.Sub(s.startedAt) < workerFreshTTL
}

// seenSinceStart treats a worker as last seen no earlier than process start.
func (s *server) seenSinceStart(rec workerRecord) workerRecord {
	if s.startedAt.IsZero() {
		return rec
	}
	if rec.LastAckAt == nil || rec.LastAckAt.Before(s.startedAt) {
		started := s.startedAt
		rec.LastAckAt = &started
	}
	return rec
}
