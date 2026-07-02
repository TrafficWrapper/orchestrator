package main

import "strings"

type awgProfile struct {
	Name            string
	MinVersionCode  int
	Subnet          string
	ServerPublicKey string
	Params          map[string]any
}

func workerAWGProfiles(workers []workerRecord) []awgProfile {
	for _, rec := range workers {
		if rec.Status != "approved" && rec.Status != "active" {
			continue
		}
		profiles := awgProfilesFromWorker(rec)
		if len(profiles) > 0 {
			return profiles
		}
	}
	return nil
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
