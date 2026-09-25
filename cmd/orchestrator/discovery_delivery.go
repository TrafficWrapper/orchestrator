package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// Public discovery modes (ORCH_DISCOVERY_PUBLIC, X-M1, ORC-M20):
//   - reduced (default): AWG entries only, endpoints.reality is empty;
//   - off: the public endpoint serves nothing, the feed only reaches clients
//     through workers (/tw/endpoints.json);
//   - full: the previous format including REALITY entries, opt-in.
//
// Every mode signs one feed per discovery seq, and workers receive that same
// feed in pull as discovery_bundle (X-M7).
const (
	discoveryModeReduced = "reduced"
	discoveryModeOff     = "off"
	discoveryModeFull    = "full"

	// discoveryPublishEvery is how often the feed is rebuilt to notice
	// content changes; discoveryReissueAfter re-sends it to workers before
	// half of its 12h lifetime has passed.
	discoveryPublishEvery = 30 * time.Second
	discoveryReissueAfter = 5 * time.Hour
)

var metaDiscoveryDelivered = []byte("discovery_delivered")

func parseDiscoveryMode(value string) (string, error) {
	switch mode := strings.ToLower(strings.TrimSpace(value)); mode {
	case "":
		return discoveryModeReduced, nil
	case discoveryModeReduced, discoveryModeOff, discoveryModeFull:
		return mode, nil
	default:
		return "", fmt.Errorf("ORCH_DISCOVERY_PUBLIC=%q: want reduced, off or full", value)
	}
}

func (s *server) discoveryMode() string {
	if s.cfg.DiscoveryPublic == "" {
		return discoveryModeReduced
	}
	return s.cfg.DiscoveryPublic
}

// discoveryBundle is the signed feed workers publish at /tw/endpoints.json.
type discoveryBundle struct {
	EndpointsJSON        string `json:"endpoints_json"`
	EndpointsJSONMinisig string `json:"endpoints_json_minisig"`
}

// discoveryBundleForPull returns the current signed feed, or nil when it
// cannot be built (the pull still carries the config).
func (s *server) discoveryBundleForPull() *discoveryBundle {
	snap, err := s.signedDiscoverySnapshot()
	if err != nil {
		return nil
	}
	return &discoveryBundle{EndpointsJSON: snap.JSON, EndpointsJSONMinisig: snap.Minisig}
}

type discoveryDelivered struct {
	Seq int64     `json:"seq"`
	At  time.Time `json:"at"`
}

// publishDiscoveryToWorkers rebuilds the feed and bumps every worker when its
// seq changed, or when the copy they hold is getting old, so workers always
// serve a current, unexpired feed. It reports whether workers were bumped.
func (s *server) publishDiscoveryToWorkers(now time.Time) (bool, error) {
	snap, err := s.signedDiscoverySnapshot()
	if err != nil {
		return false, err
	}
	var doc struct {
		Seq int64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(snap.JSON), &doc); err != nil {
		return false, err
	}
	last, found, err := getMeta[discoveryDelivered](s.store, metaDiscoveryDelivered)
	if err != nil {
		return false, err
	}
	if found && last.Seq == doc.Seq && now.Sub(last.At) < discoveryReissueAfter && !now.Before(last.At) {
		return false, nil
	}
	if err := s.store.db.Update(s.store.bumpWorkerSeqsTx); err != nil {
		return false, err
	}
	return true, putMeta(s.store, metaDiscoveryDelivered, discoveryDelivered{Seq: doc.Seq, At: now})
}

func (s *server) runDiscoveryPublisher(ctx context.Context) {
	ticker := time.NewTicker(discoveryPublishEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.publishDiscoveryToWorkers(time.Now().UTC()); err != nil {
				log.Printf("discovery publish: %v", err)
			}
		}
	}
}
