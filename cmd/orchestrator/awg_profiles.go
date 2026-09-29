package main

import (
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type awgProfile struct {
	Name            string
	MinVersionCode  int
	Subnet          string
	ServerPublicKey string
	Params          map[string]any
}

// The fleet's AWG profile set is used to allocate device credentials: the
// union over approved, enabled workers. For each profile one subnet is
// chosen; a worker whose subnet differs is left out of client routes and
// raises an alert. The choice is stable: the subnet devices already hold
// credentials in wins, then the one most workers use, then the one first
// approved, so an upgrade or a new worker never moves the pool under issued
// credentials (R2).

// fleetAWGProfiles is the profile set for this fleet and its devices.
func (s *server) fleetAWGProfiles(workers []workerRecord) []awgProfile {
	profiles, _ := fleetAWGProfilesWith(workers, s.issuedAWGCredentials())
	return profiles
}

// awgConflictWorkers lists workers whose AWG profiles disagree with the
// fleet set; their AWG routes are not offered to clients.
func (s *server) awgConflictWorkers(workers []workerRecord) map[string]bool {
	_, conflicts := fleetAWGProfilesWith(workers, s.issuedAWGCredentials())
	return conflicts
}

// issuedAWGCredentials counts the approved devices holding credentials for
// profile name inside subnet.
func (s *server) issuedAWGCredentials() func(name, subnet string) int {
	devices, err := s.store.approvedDevices()
	if err != nil || len(devices) == 0 {
		return nil
	}
	return func(name, subnet string) int {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil {
			return 0
		}
		n := 0
		for _, device := range devices {
			ip := device.AWGProfiles[name].InternalIP
			if ip == "" && name == "awg" {
				ip = device.InternalIP
			}
			if addr, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimSpace(ip), "/32")); err == nil && prefix.Contains(addr) {
				n++
			}
		}
		return n
	}
}

// fleetAWGProfiles without issued credentials (tests, first start).
func fleetAWGProfiles(workers []workerRecord) ([]awgProfile, map[string]bool) {
	return fleetAWGProfilesWith(workers, nil)
}

func fleetAWGProfilesWith(workers []workerRecord, issued func(name, subnet string) int) ([]awgProfile, map[string]bool) {
	type candidate struct {
		profile       awgProfile
		votes         int
		firstApproved time.Time
		issued        int
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
		approved := rec.CreatedAt
		if rec.ApprovedAt != nil {
			approved = *rec.ApprovedAt
		}
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
				c = &candidate{profile: profile, firstApproved: approved}
				if issued != nil {
					c.issued = issued(profile.Name, subnet)
				}
				bySubnet[profile.Name][subnet] = c
			}
			c.votes++
			if approved.Before(c.firstApproved) {
				c.firstApproved = approved
			}
			if workerSubnets[rec.ID] == nil {
				workerSubnets[rec.ID] = map[string]string{}
			}
			workerSubnets[rec.ID][profile.Name] = subnet
		}
	}
	better := func(a, b *candidate) bool {
		switch {
		case a.issued != b.issued:
			return a.issued > b.issued
		case a.votes != b.votes:
			return a.votes > b.votes
		case !a.firstApproved.Equal(b.firstApproved):
			return a.firstApproved.Before(b.firstApproved)
		}
		return a.profile.Subnet < b.profile.Subnet
	}
	out := make([]awgProfile, 0, len(names))
	for _, name := range names {
		var best *candidate
		for _, c := range bySubnet[name] {
			if best == nil || better(c, best) {
				best = c
			}
		}
		out = append(out, best.profile)
		for workerID, subnets := range workerSubnets {
			if subnet, ok := subnets[name]; ok && subnet != best.profile.Subnet {
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
