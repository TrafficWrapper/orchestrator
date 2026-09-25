package main

import (
	"log"
	"slices"
	"strings"
)

// Route alternatives (client-config-v1 "route params: nested alternatives").
// Every client gets the same shared bundle, so a worker publishes one
// primary REALITY and one primary AWG route that every app version can use,
// and its other profiles only as nested alternatives in the primary route's
// params, with the conditions for choosing them. Apps 0.1.28–0.1.31 ignore
// the nested lists and keep using the primary routes.

const workerCapRealityFlow = "reality_flow"

// realityProfileName is the worker's base REALITY profile.
const realityProfileName = "reality"

// baseRealityProfile is the reality_profiles entry describing the legacy
// primary route: named "reality", else the one on the primary port.
func baseRealityProfile(rec workerRecord, primaryPort int) map[string]any {
	raw, _ := rec.SelfDescribe["reality_profiles"].([]any)
	var byPort map[string]any
	for _, item := range raw {
		profile, ok := mapFromAny(item)
		if !ok {
			continue
		}
		if stringFromMap(profile, "name") == realityProfileName {
			return profile
		}
		if byPort == nil && primaryPort > 0 && intFromMap(profile, "port", 0) == primaryPort {
			byPort = profile
		}
	}
	return byPort
}

// realityVision reports whether a REALITY inbound applies the per-device
// Vision flow: the worker declared reality_flow, or the profile advertises
// the Vision flow. There is no "TCP means Vision" guess (X-L2): an old
// worker that does not apply reality_flow would reject Vision clients.
func realityVision(rec workerRecord, profile map[string]any) bool {
	if flows, ok := profile["flows"].([]any); ok {
		return slices.Contains(flows, any(realityFlowVision))
	}
	if !strings.EqualFold(firstStringFromMap(profile, "network"), "") && !strings.EqualFold(firstStringFromMap(profile, "network"), "tcp") {
		return false
	}
	return workerHasCapability(rec, nil, workerCapRealityFlow)
}

// realityFlowsFor keeps flows consistent with the vision decision: HEAD apps
// derive vision from flows alone.
func realityFlowsFor(vision bool, profile map[string]any) []any {
	if !vision {
		return []any{""}
	}
	if flows, ok := profile["flows"].([]any); ok && slices.Contains(flows, any(realityFlowVision)) {
		return flows
	}
	return []any{"", realityFlowVision}
}

// xhttpForClient returns the xhttp settings clients need: mode as today and
// host only when it differs from the server name (X-L11: the inbound checks
// it, so dropping a different host makes the route answer 404).
func xhttpForClient(raw any, serverName string) (map[string]any, bool) {
	settings, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for _, key := range []string{"path", "mode", "extra"} {
		if v, ok := settings[key]; ok {
			out[key] = v
		}
	}
	mode := firstStringFromMap(out, "mode")
	if mode == "" || strings.EqualFold(mode, "auto") {
		out["mode"] = "stream-up"
	}
	if host := strings.TrimSpace(stringFromMap(settings, "host")); host != "" && !strings.EqualFold(host, serverName) && validHostname(host) {
		out["host"] = host
	}
	return out, true
}

// nestedRealityProfiles lists the worker's other REALITY profiles as
// alternatives of the primary route.
func nestedRealityProfiles(rec workerRecord, primaryPort int, base map[string]any) []any {
	raw, _ := rec.SelfDescribe["reality_profiles"].([]any)
	out := []any{}
	for _, item := range raw {
		profile, ok := mapFromAny(item)
		if !ok || (base != nil && stringFromMap(profile, "name") == stringFromMap(base, "name")) {
			continue
		}
		port := intFromMap(profile, "port", 0)
		address := stringFromMap(profile, "address")
		if port <= 0 || address == "" || port == primaryPort {
			continue
		}
		vision := realityVision(rec, profile)
		entry := map[string]any{
			"name":        stringFromMap(profile, "name"),
			"network":     firstNotBlank(stringFromMap(profile, "network"), "tcp"),
			"port":        port,
			"address":     address,
			"server_name": stringFromMap(profile, "server_name"),
			"public_key":  firstStringFromMap(profile, "public_key", "publicKey"),
			"short_id":    firstStringFromMap(profile, "short_id", "shortId"),
			"flows":       realityFlowsFor(vision, profile),
			"vision":      vision,
		}
		if v6 := stringFromMap(profile, "address_v6"); v6 != "" {
			entry["address_v6"] = v6
		}
		if xhttp, ok := xhttpForClient(profile["xhttp"], stringFromMap(profile, "server_name")); ok {
			entry["xhttp"] = xhttp
		}
		out = append(out, entry)
	}
	return out
}

// awgPrimaryProfile picks the AWG profile of the primary route: the base
// profile every device has credentials for. Only a worker whose base was
// drained before this rule existed keeps the old behaviour (first remaining
// profile) until the operator undrains it.
func awgPrimaryProfile(rec workerRecord) (awgProfile, bool) {
	all := awgProfilesFromWorker(rec)
	for _, p := range all {
		if p.Name == "awg" && !slices.Contains(rec.DrainingAWGProfiles, p.Name) {
			return p, true
		}
	}
	for _, p := range all {
		if p.Name == "awg" {
			log.Printf("ALERT worker %s: base AWG profile is drained; older apps may lack credentials for %q", rec.ID, firstNonDrained(all, rec.DrainingAWGProfiles).Name)
			if alt := firstNonDrained(all, rec.DrainingAWGProfiles); alt.Name != "" {
				return alt, true
			}
			return p, true
		}
	}
	return awgProfile{}, false
}

func firstNonDrained(profiles []awgProfile, drained []string) awgProfile {
	for _, p := range profiles {
		if !slices.Contains(drained, p.Name) {
			return p
		}
	}
	return awgProfile{}
}

// nestedAWGProfiles lists the worker's other (non-drained) AWG profiles as
// alternatives; apps use one only with credentials for it from enrollment
// and a version code >= min_version_code.
func nestedAWGProfiles(rec workerRecord, primary string) []any {
	out := []any{}
	for _, p := range awgProfilesFromWorker(rec) {
		if p.Name == primary || slices.Contains(rec.DrainingAWGProfiles, p.Name) {
			continue
		}
		params := p.Params
		entry := map[string]any{
			"profile":           p.Name,
			"port":              intFromMap(params, "port", 0),
			"endpoint":          stringFromMap(params, "endpoint"),
			"public_key":        p.ServerPublicKey,
			"server_public_key": p.ServerPublicKey,
			"min_version_code":  p.MinVersionCode,
		}
		if entry["endpoint"] == "" {
			continue
		}
		for _, key := range []string{"endpoint_v6", "dialect_id"} {
			if v := stringFromMap(params, key); v != "" {
				entry[key] = v
			}
		}
		if dialect, ok := firstRawMapValue(params, "dialect", "awg_preset"); ok {
			entry["dialect"] = dialect
		}
		if dns, ok := params["dns"].([]any); ok {
			entry["dns"] = dns
		} else {
			entry["dns"] = []any{}
		}
		out = append(out, entry)
	}
	return out
}
