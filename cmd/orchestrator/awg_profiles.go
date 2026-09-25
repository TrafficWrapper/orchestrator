package main

import (
	"log"
	"sort"
	"strings"
)

type awgProfile struct {
	Name            string
	MinVersionCode  int
	Subnet          string
	ServerPublicKey string
	Params          map[string]any
}

// workerAWGProfiles is the fleet's AWG profile set used to allocate device
// credentials: the union over approved, enabled workers. For each profile the
// subnet most workers agree on wins (ties: lowest worker ID); a worker whose
// subnet differs, or is not a sane private pool, is left out of it.
func workerAWGProfiles(workers []workerRecord) []awgProfile {
	profiles, _ := fleetAWGProfiles(workers)
	return profiles
}

// awgProfileConflictWorkers lists workers whose AWG profiles disagree with the
// fleet set; their AWG routes are not offered to clients.
func awgProfileConflictWorkers(workers []workerRecord) map[string]bool {
	_, conflicts := fleetAWGProfiles(workers)
	return conflicts
}

func fleetAWGProfiles(workers []workerRecord) ([]awgProfile, map[string]bool) {
	type candidate struct {
		profile awgProfile
		votes   int
		firstID string
	}
	eligible := make([]workerRecord, 0, len(workers))
	for _, rec := range workers {
		if (rec.Status == "approved" || rec.Status == "active") && !rec.Disabled && !rec.SelfDescribeForbidden {
			eligible = append(eligible, rec)
		}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].ID < eligible[j].ID })
	conflicts := map[string]bool{}
	var names []string
	bySubnet := map[string]map[string]*candidate{}
	workerSubnets := map[string]map[string]string{}
	for _, rec := range eligible {
		for _, profile := range awgProfilesFromWorker(rec) {
			subnet := strings.TrimSpace(profile.Subnet)
			if subnet == "" {
				subnet = "10.13.13.0/24"
			}
			prefix, err := validAWGSubnet(subnet)
			if err != nil {
				log.Printf("awg profiles: worker %s profile %s subnet %q rejected: %v", rec.ID, profile.Name, subnet, err)
				conflicts[rec.ID] = true
				continue
			}
			subnet = prefix.String()
			profile.Subnet = subnet
			if bySubnet[profile.Name] == nil {
				bySubnet[profile.Name] = map[string]*candidate{}
				names = append(names, profile.Name)
			}
			c := bySubnet[profile.Name][subnet]
			if c == nil {
				c = &candidate{profile: profile, firstID: rec.ID}
				bySubnet[profile.Name][subnet] = c
			}
			c.votes++
			if workerSubnets[rec.ID] == nil {
				workerSubnets[rec.ID] = map[string]string{}
			}
			workerSubnets[rec.ID][profile.Name] = subnet
		}
	}
	out := make([]awgProfile, 0, len(names))
	for _, name := range names {
		var best *candidate
		for _, c := range bySubnet[name] {
			if best == nil || c.votes > best.votes || c.votes == best.votes && c.firstID < best.firstID {
				best = c
			}
		}
		out = append(out, best.profile)
		for workerID, subnets := range workerSubnets {
			if subnet, ok := subnets[name]; ok && subnet != best.profile.Subnet {
				log.Printf("awg profiles: worker %s profile %s subnet %s conflicts with fleet %s; its AWG is not offered", workerID, name, subnet, best.profile.Subnet)
				conflicts[workerID] = true
			}
		}
	}
	return out, conflicts
}

func awgProfilesFromWorker(rec workerRecord) []awgProfile {
	out := []awgProfile{}
	if base, ok := mapFromAny(rec.SelfDescribe["awg"]); ok {
		base = cloneMap(base)
		if stringFromMap(base, "profile") == "" {
			base["profile"] = "awg"
		}
		out = append(out, awgProfileFromParams(base))
	}
	if rawProfiles, ok := rec.SelfDescribe["awg_profiles"].([]any); ok {
		seen := map[string]struct{}{}
		for _, profile := range out {
			seen[profile.Name] = struct{}{}
		}
		for _, raw := range rawProfiles {
			params, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			profile := awgProfileFromParams(cloneMap(params))
			if profile.Name == "" {
				continue
			}
			if _, exists := seen[profile.Name]; exists {
				continue
			}
			seen[profile.Name] = struct{}{}
			out = append(out, profile)
		}
	}
	return out
}

func awgProfileFromParams(params map[string]any) awgProfile {
	name := normalizeAWGProfileName(firstStringFromMap(params, "profile", "name"))
	if name == "" {
		name = "awg"
	}
	return awgProfile{
		Name:            name,
		MinVersionCode:  intFromMap(params, "min_version_code", 0),
		Subnet:          firstStringFromMap(params, "subnet"),
		ServerPublicKey: firstStringFromMap(params, "public_key", "server_public", "server_public_key"),
		Params:          params,
	}
}

func selectAWGProfileForClient(profiles []awgProfile, clientVersion string) (awgProfile, bool) {
	if len(profiles) == 0 {
		return awgProfile{}, false
	}
	code := clientVersionCode(clientVersion)
	var best awgProfile
	found := false
	for _, profile := range profiles {
		if profile.MinVersionCode > code {
			continue
		}
		if !found || profile.MinVersionCode > best.MinVersionCode {
			best = profile
			found = true
		}
	}
	if found {
		return best, true
	}
	for _, profile := range profiles {
		if profile.MinVersionCode == 0 {
			return profile, true
		}
	}
	return profiles[0], true
}

func normalizeAWGProfileName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		default:
			return ""
		}
	}
	return b.String()
}

func mapFromAny(raw any) (map[string]any, bool) {
	params, ok := raw.(map[string]any)
	return params, ok && len(params) > 0
}
