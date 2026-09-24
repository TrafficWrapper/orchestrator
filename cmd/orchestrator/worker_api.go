package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type enrollRequest struct {
	Token           string         `json:"token"`
	WorkerStaticPub string         `json:"worker_static_pub"`
	SelfDescribe    map[string]any `json:"self_describe"`
}

type enrollResponse struct {
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
	WorkerID        string `json:"worker_id,omitempty"`
	Status          string `json:"status,omitempty"`
	SignerPublicKey string `json:"signer_public_key,omitempty"`
}

type pullRequest struct {
	WorkerID string `json:"worker_id"`
	HaveSeq  int64  `json:"have_seq"`
}

type pullResponse struct {
	OK           bool            `json:"ok"`
	Error        string          `json:"error,omitempty"`
	Status       string          `json:"status,omitempty"`
	WorkerID     string          `json:"worker_id,omitempty"`
	DesiredSeq   int64           `json:"desired_seq,omitempty"`
	NotModified  bool            `json:"not_modified,omitempty"`
	WorkerBundle signedConfig    `json:"worker_bundle,omitempty"`
	ClientBundle signedConfig    `json:"client_bundle,omitempty"`
	Update       *updateArtifact `json:"update,omitempty"`
	// release frees the APK shipment slot once the response is written.
	release func()
}

type updateArtifact struct {
	ManifestJSON    string `json:"manifest_json,omitempty"`
	ManifestMinisig string `json:"manifest_minisig,omitempty"`
	APKName         string `json:"apk_name,omitempty"`
	APKSHA256       string `json:"apk_sha256,omitempty"`
	APKBase64       string `json:"apk_base64,omitempty"`
}

type ackRequest struct {
	WorkerID         string         `json:"worker_id"`
	AppliedVersion   int64          `json:"applied_version"`
	SelfCheck        string         `json:"self_check"`
	EgressIPObserved string         `json:"egress_ip_observed"`
	SelfDescribe     map[string]any `json:"self_describe,omitempty"`
	Usage            []deviceUsage  `json:"usage,omitempty"`
}

type ackResponse struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	DesiredSeq    int64  `json:"desired_seq,omitempty"`
	AppliedSeq    int64  `json:"applied_seq,omitempty"`
	EgressIPProbe string `json:"egress_ip_probe,omitempty"`
	EgressMatch   bool   `json:"egress_match"`
	QuotaBlocks   int    `json:"quota_blocks,omitempty"`
}

type deviceUsage struct {
	DeviceID     string `json:"device_id,omitempty"`
	AWGPublicKey string `json:"awg_public_key,omitempty"`
	Source       string `json:"source,omitempty"`
	RxBytes      uint64 `json:"rx_bytes,omitempty"`
	TxBytes      uint64 `json:"tx_bytes,omitempty"`
}

type nudgeRequest struct {
	WorkerID     string         `json:"worker_id"`
	HaveSeq      int64          `json:"have_seq"`
	SelfDescribe map[string]any `json:"self_describe,omitempty"`
}

type nudgeResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DesiredSeq int64  `json:"desired_seq,omitempty"`
	Heartbeat  bool   `json:"heartbeat,omitempty"`
}

func (s *server) handleEnroll(peer []byte, raw []byte) (any, error) {
	var req enrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	staticPub := protocol.KeyToBase64(peer)
	if strings.TrimSpace(req.WorkerStaticPub) != "" && req.WorkerStaticPub != staticPub {
		return nil, errors.New("worker static pub mismatch")
	}
	if _, err := s.store.consumeToken(req.Token, staticPub); err != nil {
		return enrollResponse{OK: false, Error: err.Error()}, nil
	}
	rec, err := s.store.upsertPendingWorker(staticPub, req.SelfDescribe)
	if err != nil {
		return nil, err
	}
	pub, err := s.signerPublicKey()
	if err != nil {
		return nil, err
	}
	return enrollResponse{OK: true, WorkerID: rec.ID, Status: rec.Status, SignerPublicKey: pub}, nil
}

func (s *server) handlePull(peer []byte, raw []byte) (any, error) {
	var req pullRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return pullResponse{OK: false, Error: err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return pullResponse{OK: false, Error: "worker identity mismatch"}, nil
	}
	if rec.Status == "pending" {
		return pullResponse{OK: false, Status: "pending", Error: "owner approval required"}, nil
	}
	if req.HaveSeq >= rec.DesiredSeq {
		return pullResponse{OK: true, Status: rec.Status, WorkerID: rec.ID, DesiredSeq: rec.DesiredSeq, NotModified: true}, nil
	}
	wb, cb, err := s.buildBundles(rec)
	if err != nil {
		return nil, err
	}
	update, release, err := s.updateArtifactForPull(rec, req.HaveSeq)
	if err != nil {
		return nil, err
	}
	return pullResponse{OK: true, Status: rec.Status, WorkerID: rec.ID, DesiredSeq: rec.DesiredSeq, WorkerBundle: wb, ClientBundle: cb, Update: update, release: release}, nil
}

const (
	nudgeLongPollTimeout = 25 * time.Second
	nudgeFallbackPoll    = 5 * time.Second
)

func (s *server) handleNudge(ctx context.Context, peer []byte, raw []byte) (any, error) {
	var req nudgeRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	deadline := time.NewTimer(nudgeLongPollTimeout)
	defer deadline.Stop()
	expired := false
	updatedHeartbeat := false
	for {
		// Grab the change signal before reading, so a bump committed between
		// the read and the wait still wakes us.
		changed := s.store.workerSeqChanged()
		rec, err := s.store.worker(req.WorkerID)
		if err != nil {
			return nudgeResponse{OK: false, Error: err.Error()}, nil
		}
		if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
			return nudgeResponse{OK: false, Error: "worker identity mismatch"}, nil
		}
		if !updatedHeartbeat {
			_ = s.store.updateWorkerHeartbeat(rec.ID, req.HaveSeq, req.SelfDescribe)
			updatedHeartbeat = true
		}
		if rec.DesiredSeq > req.HaveSeq || expired {
			return nudgeResponse{OK: true, DesiredSeq: rec.DesiredSeq, Heartbeat: rec.DesiredSeq <= req.HaveSeq}, nil
		}
		select {
		case <-ctx.Done():
			return nudgeResponse{OK: false, Error: ctx.Err().Error()}, nil
		case <-deadline.C:
			expired = true
		case <-changed:
		case <-time.After(nudgeFallbackPoll):
			// Safety net for a seq change that bypassed the signal.
		}
	}
}

func (s *server) handleAck(peer []byte, raw []byte) (any, error) {
	var req ackRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rec, err := s.store.worker(req.WorkerID)
	if err != nil {
		return ackResponse{OK: false, Error: err.Error()}, nil
	}
	if rec.StaticPublicKey != protocol.KeyToBase64(peer) {
		return ackResponse{OK: false, Error: "worker identity mismatch"}, nil
	}
	probe := s.probeEgressIP(rec)
	egressMatch := probe != "" && probe == req.EgressIPObserved
	if probe == "" {
		log.Printf("worker %s egress probe unavailable; observed=%q", rec.ID, req.EgressIPObserved)
	}
	desiredSeq, quotaBlocks, err := s.store.recordAck(rec.ID, req.AppliedVersion, req.EgressIPObserved, req.SelfDescribe, &probe, req.Usage, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if quotaBlocks > 0 {
		log.Printf("quota enforcement blocked devices count=%d worker=%s", quotaBlocks, rec.ID)
	}
	return ackResponse{OK: true, DesiredSeq: desiredSeq, AppliedSeq: req.AppliedVersion, EgressIPProbe: probe, EgressMatch: egressMatch, QuotaBlocks: quotaBlocks}, nil
}

const egressProbeCacheTTL = time.Minute

func (s *server) probeEgressIP(rec workerRecord) string {
	if s.cfg.EgressProbeURL == "" {
		return stringFromMap(rec.SelfDescribe, "egress_ip")
	}
	// ORCH_EGRESS_PROBE_URL is one URL for the whole orchestrator (meant for a
	// co-located worker), so the answer is the same for every ack: cache it
	// instead of blocking each ack on a synchronous HTTP call.
	// One refresh at a time and never under the lock: concurrent acks get the
	// previous value instead of queueing behind a slow HTTP call.
	s.egressProbeMu.Lock()
	value := s.egressProbeValue
	fresh := !s.egressProbeAt.IsZero() && time.Since(s.egressProbeAt) < egressProbeCacheTTL
	if fresh || s.egressProbeFetching {
		s.egressProbeMu.Unlock()
		return value
	}
	s.egressProbeFetching = true
	s.egressProbeMu.Unlock()
	value = s.fetchEgressProbe()
	s.egressProbeMu.Lock()
	s.egressProbeValue = value
	s.egressProbeAt = time.Now()
	s.egressProbeFetching = false
	s.egressProbeMu.Unlock()
	return value
}

func (s *server) fetchEgressProbe() string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(s.cfg.EgressProbeURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err == nil {
		return stringFromMap(body, "egress_ip")
	}
	return strings.TrimSpace(string(raw))
}

func (p pullResponse) releaseAfterWrite() {
	if p.release != nil {
		p.release()
	}
}
