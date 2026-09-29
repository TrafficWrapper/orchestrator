package main

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Rotation of per-device transport credentials (REALITY UUID and AWG PSKs),
// e.g. after a worker that served the device was compromised (R2 ORC-H2).
// A pending rotation is applied on the device's next re-enrollment, which
// returns the new credentials in the same response, so the device never
// loses its routes; an immediate rotation changes them at once and the
// device reconnects after it re-enrolls.
const deviceRotationPending = "pending"

// rotateDeviceCredentials gives device a new REALITY UUID and new AWG
// pre-shared keys; addresses and keys the app holds stay the same.
func rotateDeviceCredentials(device *deviceRecord) error {
	device.RealityUUID = uuidV4()
	for name, creds := range device.AWGProfiles {
		psk, err := randomBase64Key()
		if err != nil {
			return err
		}
		creds.PSK2 = psk
		device.AWGProfiles[name] = creds
	}
	if base, ok := device.AWGProfiles["awg"]; ok {
		device.PSK2 = base.PSK2
	} else if device.PSK2 != "" {
		psk, err := randomBase64Key()
		if err != nil {
			return err
		}
		device.PSK2 = psk
	}
	device.CredentialRotation = ""
	return nil
}

// markDeviceRotation schedules (or with immediate, performs) a rotation for
// the listed devices, or every approved device with all. It returns how many
// devices were affected.
func (s *orchStore) markDeviceRotation(ids []string, all, immediate bool) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		var updated []deviceRecord
		if err := b.ForEach(func(k, raw []byte) error {
			var device deviceRecord
			if err := s.openJSON(bucketDevices, k, raw, &device); err != nil {
				return err
			}
			if device.Status != "approved" || (!all && !slices.Contains(ids, device.ID)) {
				return nil
			}
			if immediate {
				if err := rotateDeviceCredentials(&device); err != nil {
					return err
				}
			} else {
				device.CredentialRotation = deviceRotationPending
			}
			updated = append(updated, device)
			return nil
		}); err != nil {
			return err
		}
		for _, device := range updated {
			if err := putSealedTx(s, tx, bucketDevices, device.ID, device); err != nil {
				return err
			}
		}
		n = len(updated)
		if n > 0 && immediate {
			return s.bumpWorkerSeqsTx(tx)
		}
		return nil
	})
	return n, err
}

// handleAdminRotateDeviceCredentials schedules or performs a credential
// rotation; it needs step-up.
func (s *server) handleAdminRotateDeviceCredentials(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs       []string `json:"ids"`
		All       bool     `json:"all"`
		Immediate bool     `json:"immediate"`
		stepUpProof
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ids := make([]string, 0, len(req.IDs))
	for _, id := range req.IDs {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 && !req.All {
		writeError(w, "ids or all is required", http.StatusBadRequest)
		return
	}
	if !s.stepUp(w, r, "device_rotate_credentials", "rotate device transport credentials", req.stepUpProof) {
		return
	}
	n, err := s.store.markDeviceRotation(ids, req.All, req.Immediate)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditEvent(auditEntry{Event: "device_rotate_credentials", IP: clientIP(r), Result: "ok", Fields: map[string]string{
		"devices": strconv.Itoa(n), "all": strconv.FormatBool(req.All), "immediate": strconv.FormatBool(req.Immediate)}})
	writeJSON(w, map[string]any{"ok": true, "devices": n, "immediate": req.Immediate})
}

// applyPendingRotation rotates a device whose rotation is pending, at its
// re-enrollment, and tells workers.
func (s *orchStore) applyPendingRotation(id string) (deviceRecord, error) {
	return s.updateDevice(id, true, func(rec *deviceRecord) error {
		if rec.CredentialRotation != deviceRotationPending {
			return errNoPendingRotation
		}
		return rotateDeviceCredentials(rec)
	})
}

var errNoPendingRotation = errors.New("no pending rotation")
