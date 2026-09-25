package main

import (
	"context"
	"log"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Client capabilities the orchestrator understands (ORC-L5). Anything else an
// app declares is dropped without an error, so newer apps keep enrolling.
const (
	// capabilityRouteAlternatives: the app picks nested route alternatives
	// (params.reality_profiles / params.awg_profiles) by its credentials.
	capabilityRouteAlternatives = "route_alternatives_v1"
	// capabilityRealityFlowAck: the app confirms a Vision switch with
	// reality_flow_ack before it takes effect (X-L13).
	capabilityRealityFlowAck = "reality_flow_ack"

	maxClientCapabilities   = 32
	maxClientCapabilityLen  = 64
	realityFlowSwitchMinGap = 10 * time.Minute
	awgBackfillEvery        = time.Minute
)

var knownClientCapabilities = []string{
	capabilityRealityVision,
	"reality_profiles",
	"reality_short_id",
	"awg_dialect_wide",
	"ipv6_endpoints",
	"tunnel_dns",
	capabilityRouteAlternatives,
	capabilityRealityFlowAck,
}

// allowedClientCapabilities keeps the known capabilities (trimmed,
// lower-cased, deduplicated, sorted), looking at no more than
// maxClientCapabilities entries of at most maxClientCapabilityLen bytes.
func allowedClientCapabilities(raw []string) []string {
	var out []string
	for i, c := range raw {
		if i >= maxClientCapabilities {
			break
		}
		if len(c) > maxClientCapabilityLen {
			continue
		}
		c = strings.ToLower(strings.TrimSpace(c))
		if slices.Contains(knownClientCapabilities, c) && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// deviceClientVersionCode is the stored diagnostic version code: the one the
// app sent, else derived from its version name (major*10000+minor*100+patch,
// so 0.1.31 is 131). It is not the Android versionCode of the APK.
func deviceClientVersionCode(sent int, clientVersion string) int {
	if sent > 0 && sent < 1<<30 {
		return sent
	}
	return clientVersionCode(clientVersion)
}

// realityFlowDecision is the REALITY flow a re-enrollment leaves on the
// device: the active flow, and the one waiting for the app's ack.
type realityFlowDecision struct {
	Flow    string
	Pending string
	// Switched is set when Flow differs from the stored flow.
	Switched bool
}

// decideRealityFlow applies the requested Vision state (X-L13, ORC-L5):
//   - turning Vision off takes effect at once;
//   - turning it on for an app with reality_flow_ack is two-phase: the reply
//     announces reality_flow_pending and the switch happens on the next
//     enrollment that acks it;
//   - apps without reality_flow_ack switch at once, as before;
//   - a switch sooner than realityFlowSwitchMinGap after the previous one
//     keeps the previous flow without an error.
func decideRealityFlow(existing deviceRecord, caps []string, ack string, now time.Time) realityFlowDecision {
	current := existing.RealityFlow
	desired := deviceRealityFlow(caps)
	if desired == current {
		return realityFlowDecision{Flow: current}
	}
	if desired == "" {
		return realityFlowDecision{Flow: "", Switched: true}
	}
	if existing.RealityFlowChangedAt != nil && now.Sub(*existing.RealityFlowChangedAt) < realityFlowSwitchMinGap && !now.Before(*existing.RealityFlowChangedAt) {
		return realityFlowDecision{Flow: current, Pending: existing.RealityFlowPending}
	}
	if slices.Contains(caps, capabilityRealityFlowAck) {
		if existing.RealityFlowPending == desired && strings.TrimSpace(ack) == desired {
			return realityFlowDecision{Flow: desired, Switched: true}
		}
		return realityFlowDecision{Flow: current, Pending: desired}
	}
	return realityFlowDecision{Flow: desired, Switched: true}
}

// devicesWithoutCapability counts approved devices whose app did not declare
// capability at its last enrollment.
func (s *orchStore) devicesWithoutCapability(capability string) (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).ForEach(func(k, raw []byte) error {
			var device deviceRecord
			if err := s.openJSON(bucketDevices, k, raw, &device); err != nil {
				return err
			}
			if device.Status == "approved" && !slices.Contains(device.ClientCapabilities, capability) {
				n++
			}
			return nil
		})
	})
	return n, err
}

// backfillDeviceAWGProfiles gives every approved device credentials for each
// profile in the fleet union (X-M4), so a profile added after a device
// enrolled is usable without re-enrollment. It returns how many devices
// changed; the config is bumped once when any did.
func (s *orchStore) backfillDeviceAWGProfiles(profiles []awgProfile) (int, error) {
	if len(profiles) == 0 {
		return 0, nil
	}
	missing := false
	if err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).ForEach(func(k, raw []byte) error {
			if missing {
				return nil
			}
			var device deviceRecord
			if err := s.openJSON(bucketDevices, k, raw, &device); err != nil {
				return err
			}
			missing = device.Status == "approved" && deviceLacksAWGProfile(device, profiles)
			return nil
		})
	}); err != nil || !missing {
		return 0, err
	}
	changed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		ipIndex := s.newDeviceIPIndex(tx)
		var updated []deviceRecord
		if err := b.ForEach(func(k, raw []byte) error {
			var device deviceRecord
			if err := s.openJSON(bucketDevices, k, raw, &device); err != nil {
				return err
			}
			if device.Status != "approved" || strings.TrimSpace(device.AWGPublicKey) == "" || !deviceLacksAWGProfile(device, profiles) {
				return nil
			}
			if err := s.ensureDeviceAWGProfilesTx(tx, ipIndex, &device, profiles, device.AWGPublicKey); err != nil {
				log.Printf("awg backfill: device %s: %v", device.ID, err)
				return nil
			}
			updated = append(updated, device)
			return nil
		}); err != nil {
			return err
		}
		for _, device := range updated {
			sealed, err := s.sealJSON(bucketDevices, []byte(device.ID), device)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(device.ID), sealed); err != nil {
				return err
			}
		}
		changed = len(updated)
		if changed == 0 {
			return nil
		}
		return s.bumpWorkerSeqsTx(tx)
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}

func deviceLacksAWGProfile(device deviceRecord, profiles []awgProfile) bool {
	for _, profile := range profiles {
		name := normalizeAWGProfileName(profile.Name)
		if name == "" {
			name = "awg"
		}
		creds, ok := device.AWGProfiles[name]
		if !ok || strings.TrimSpace(creds.InternalIP) == "" || strings.TrimSpace(creds.PSK2) == "" {
			return true
		}
	}
	return false
}

// backfillAWGCredentials runs one backfill over the current fleet profiles.
func (s *server) backfillAWGCredentials() (int, error) {
	workers, err := s.store.workers()
	if err != nil {
		return 0, err
	}
	return s.store.backfillDeviceAWGProfiles(workerAWGProfiles(workers))
}

// runAWGCredentialBackfill keeps device credentials in step with the fleet's
// AWG profiles.
func (s *server) runAWGCredentialBackfill(ctx context.Context) {
	ticker := time.NewTicker(awgBackfillEvery)
	defer ticker.Stop()
	for {
		if n, err := s.backfillAWGCredentials(); err != nil {
			log.Printf("awg backfill: %v", err)
		} else if n > 0 {
			log.Printf("awg backfill: provisioned new AWG profiles for %d devices", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// normalizeShortIDs lower-cases, trims and deduplicates stored short IDs
// (workers compare them lower-cased, X-L3).
func normalizeShortIDs(ids []string) []string {
	out := []string{}
	for _, id := range ids {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}
