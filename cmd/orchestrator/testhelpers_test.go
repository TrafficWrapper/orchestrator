package main

import (
	"errors"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Helpers used only by tests; production code paths use the batched or
// combined variants (recordAck, recordTelemetry, deviceIPIndex, ...).

func (s *server) loadUpdateArtifact() (*updateArtifact, error) {
	rel, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok {
		return nil, err
	}
	return readUpdateArtifact(rel)
}

func (s *server) setAuthApproverForTest(approver authApprover) {
	s.botMu.Lock()
	s.authApprover = approver
	s.botMu.Unlock()
}

func (s *server) signedDiscoveryBundle() (string, string, string, error) {
	bundle, err := s.signedDiscoverySnapshot()
	if err != nil {
		return "", "", "", err
	}
	return bundle.JSON, bundle.Minisig, bundle.PublicKey, nil
}

func (l *loginLimiter) isLocked(key string) (time.Time, bool) {
	if l == nil || strings.TrimSpace(key) == "" {
		return time.Time{}, false
	}
	keys := loginLimiterKeys(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.pruneLocked(now)
	var until time.Time
	for _, k := range keys {
		if state := l.states[k.key]; state.isLocked(now) && state.LockedUntil.After(until) {
			until = state.LockedUntil
		}
	}
	return until, !until.IsZero()
}

func (l *loginLimiter) recordFailure(key string) (time.Time, bool) {
	reservation := l.reserveAttempt(key)
	return reservation.LockedUntil, reservation.Locked || reservation.LockedAfterAttempt
}

func (s *orchStore) adminTOTP() (adminTOTPRecord, bool, error) {
	var rec adminTOTPRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaAdminTOTP)
		if raw == nil {
			return nil
		}
		return s.openJSON(bucketMeta, metaAdminTOTP, raw, &rec)
	})
	if err != nil {
		return adminTOTPRecord{}, false, err
	}
	if strings.TrimSpace(rec.Secret) == "" {
		return adminTOTPRecord{}, false, nil
	}
	return rec, rec.Enabled, nil
}

func (s *orchStore) setTelemetrySnapshot(rec telemetrySnapshotRecord) error {
	if strings.TrimSpace(rec.DeviceID) == "" {
		return errors.New("telemetry device_id is required")
	}
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}
	sealed, err := s.sealJSON(bucketTelemetry, []byte(rec.DeviceID), rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTelemetry).Put([]byte(rec.DeviceID), sealed)
	})
}

func (s *orchStore) updateDeviceClientVersionFromTelemetry(id, version string) (bool, error) {
	id = strings.TrimSpace(id)
	version = strings.TrimSpace(version)
	if id == "" {
		return false, errors.New("device id is required")
	}
	if version == "" {
		return false, nil
	}
	changed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("device not found")
		}
		var rec deviceRecord
		if err := s.openJSON(bucketDevices, []byte(id), raw, &rec); err != nil {
			return err
		}
		if strings.TrimSpace(rec.ClientVersion) == version {
			return nil
		}
		if clientVersionWouldRollback(rec.ClientVersion, version) {
			return nil
		}
		rec.ClientVersion = version
		sealed, err := s.sealJSON(bucketDevices, []byte(rec.ID), rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.ID), sealed); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}

// applyReportedDeviceUsage is the ack hot path: devices are loaded by id, and
// the full scan only runs when a report cannot be attributed that way (legacy
// reports keyed solely by AWG public key).
func (s *orchStore) applyReportedDeviceUsage(workerID string, reports []deviceUsage, now time.Time) (int, error) {
	blocked := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		blocked, err = s.applyReportedDeviceUsageTx(tx, workerID, reports, now)
		return err
	})
	if err != nil {
		return 0, err
	}
	return blocked, nil
}

func (s *orchStore) updateAck(id string, applied int64, observed string, self map[string]any) error {
	return s.updateAckWithProbe(id, applied, observed, self, nil)
}

func (s *orchStore) updateAckWithProbe(id string, applied int64, observed string, self map[string]any, probe *string) error {
	return s.updateWorker(id, func(rec *workerRecord) error {
		applyAck(rec, applied, observed, self, probe)
		return nil
	})
}

func (s *orchStore) updateWorkerSelfDescribe(id string, self map[string]any) error {
	if len(self) == 0 {
		return nil
	}
	return s.updateWorker(id, func(rec *workerRecord) error {
		rec.SelfDescribe = self
		return nil
	})
}

func (s *orchStore) allocateDeviceIP(tx *bolt.Tx, cidr string) (string, error) {
	return s.newDeviceIPIndex(tx).allocate("awg", cidr)
}
