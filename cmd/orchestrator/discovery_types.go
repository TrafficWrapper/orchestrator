package main

import (
	"encoding/json"
	"log"
)

// The shapes the app core decodes the discovery feed into
// (core/transport/discovery.go; awg_preset is awg/dialect.Dialect). A single
// entry of another type fails the app's json.Unmarshal of the whole feed, so
// each worker's entries are checked against them and dropped on a mismatch
// (R2 ORC-H3). Extra keys are fine: the app ignores them.
type feedAWGPreset struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
}

type feedAWGEntry struct {
	Priority        int           `json:"priority"`
	Endpoint        string        `json:"endpoint"`
	EgressIP        string        `json:"egress_ip"`
	ServerPublicKey string        `json:"server_public_key"`
	AWGPreset       feedAWGPreset `json:"awg_preset"`
	WorkerID        string        `json:"worker_id"`
}

type feedRealityEntry struct {
	Priority    int    `json:"priority"`
	Transport   string `json:"transport"`
	Address     string `json:"address"`
	EgressIP    string `json:"egress_ip"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Flow        string `json:"flow"`
	Security    string `json:"security"`
	Network     string `json:"network"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
	SpiderX     string `json:"spiderX"`
	WorkerID    string `json:"worker_id"`
}

// feedEntryDecodes reports whether item decodes into target the way the app
// decodes it; a mismatch is logged against the worker.
func feedEntryDecodes(workerID, kind string, item map[string]any, target any) bool {
	raw, err := json.Marshal(item)
	if err == nil {
		err = json.Unmarshal(raw, target)
	}
	if err != nil {
		log.Printf("discovery: worker %s %s entry dropped: %v", workerID, kind, err)
		return false
	}
	return true
}
