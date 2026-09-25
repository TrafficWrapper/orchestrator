package main

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type deviceEnrollRequest struct {
	BootstrapToken  string `json:"bootstrap_token"`
	NoisePublicKey  string `json:"noise_public_key,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	AndroidID       string `json:"android_id,omitempty"`
	Model           string `json:"model,omitempty"`
	IdentityPubKey  string `json:"identity_pubkey"`
	IdentityKeyType string `json:"identity_key_type,omitempty"`
	EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	AWGPublicKey    string `json:"awg_public_key,omitempty"`
	// ClientCapabilities lists what the app supports, e.g. "reality_vision",
	// "reality_short_id", "ipv6_endpoints", "tunnel_dns". Absent in older apps,
	// which therefore keep the flow-less REALITY account. Capabilities is an
	// accepted alias.
	ClientCapabilities []string `json:"client_capabilities,omitempty"`
	Capabilities       []string `json:"capabilities,omitempty"`
	// ClientVersionCode is the app's derived version code
	// (major*10000+minor*100+patch), kept for diagnostics only.
	ClientVersionCode int `json:"client_version_code,omitempty"`
	// RealityFlowAck confirms the reality_flow_pending of the previous reply
	// (apps declaring reality_flow_ack).
	RealityFlowAck string `json:"reality_flow_ack,omitempty"`
}

// capabilities returns the known client capabilities declared in either
// field (allowedClientCapabilities); unknown ones are dropped silently.
func (r deviceEnrollRequest) capabilities() []string {
	return allowedClientCapabilities(append(append([]string(nil), r.ClientCapabilities...), r.Capabilities...))
}

type deviceEnrollResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Code classifies a refusal (enrollErrorCode); apps without it fall
	// back to matching Error.
	Code        string                      `json:"code,omitempty"`
	DeviceID    string                      `json:"device_id,omitempty"`
	Status      string                      `json:"status,omitempty"`
	RealityUUID string                      `json:"reality_uuid,omitempty"`
	InternalIP  string                      `json:"internal_ip,omitempty"`
	PSK2        string                      `json:"psk2,omitempty"`
	AWGProfiles map[string]deviceAWGProfile `json:"awg_profiles,omitempty"`
	// RealityFlow is the flow of this device's REALITY account on every
	// worker ("" or xtls-rprx-vision); the app must use exactly this value
	// on TCP REALITY routes (XHTTP routes never carry a flow).
	RealityFlow string `json:"reality_flow"`
	// RealityFlowPending is the flow the device switches to once the app
	// acks it in its next enrollment (apps declaring reality_flow_ack).
	RealityFlowPending string       `json:"reality_flow_pending,omitempty"`
	ServerAWGPublic    string       `json:"server_awg_public,omitempty"`
	SignerPublicKey    string       `json:"signer_public_key,omitempty"`
	ClientBundle       signedConfig `json:"client_bundle,omitempty"`
}

type bootstrapPayload struct {
	OrchestratorURL string          `json:"orchestrator_url"`
	ConfigPubkeyPin string          `json:"config_pubkey_pin"`
	OrchNoisePublic string          `json:"orch_noise_public"`
	UpdatePubkey    string          `json:"update_pubkey,omitempty"`
	SeedWorkers     []string        `json:"seed_workers"`
	BootstrapToken  string          `json:"bootstrap_token"`
	Limits          json.RawMessage `json:"limits,omitempty"`
	Expires         string          `json:"expires"`
	// OrchTLSSPKISHA256 lists base64 SHA-256 SPKI pins (current and backup)
	// of the orchestrator's TLS certificate for first enrollment (APP-L36).
	OrchTLSSPKISHA256 []string `json:"orch_tls_spki_sha256,omitempty"`
}

// handleDeviceEnroll adds a structured code to refusals (the error texts
// stay what apps 0.1.28–0.1.31 match on).
func (s *server) handleDeviceEnroll(peer []byte, raw []byte) (any, error) {
	resp, err := s.deviceEnroll(peer, raw)
	if r, ok := resp.(deviceEnrollResponse); ok && !r.OK && r.Code == "" {
		r.Code = enrollErrorCode(r.Error)
		resp = r
	}
	return resp, err
}

func (s *server) deviceEnroll(peer []byte, raw []byte) (any, error) {
	var req deviceEnrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	noisePub := protocol.KeyToBase64(peer)
	if strings.TrimSpace(req.NoisePublicKey) != "" && req.NoisePublicKey != noisePub {
		return deviceEnrollResponse{OK: false, Error: "device noise pub mismatch"}, nil
	}
	if strings.TrimSpace(req.BootstrapToken) == "" {
		return deviceEnrollResponse{OK: false, Error: "bootstrap token is required"}, nil
	}
	if strings.TrimSpace(req.IdentityPubKey) == "" {
		return deviceEnrollResponse{OK: false, Error: "identity_pubkey is required"}, nil
	}
	if strings.TrimSpace(req.AWGPublicKey) == "" {
		return deviceEnrollResponse{OK: false, Error: "awg_public_key is required"}, nil
	}
	identityPub := strings.TrimSpace(req.IdentityPubKey)
	awgPublic := strings.TrimSpace(req.AWGPublicKey)
	id := deviceID(req.IdentityPubKey, noisePub)
	workers, err := s.store.workers()
	if err != nil {
		return nil, err
	}
	awgProfiles := workerAWGProfiles(workers)
	serverAWGPublic := workerAWGPublicKeyFromProfiles(awgProfiles)
	if serverAWGPublic == "" {
		return deviceEnrollResponse{OK: false, Error: "no approved worker with awg public key"}, nil
	}
	existing, err := s.store.device(id)
	if err == nil {
		storedIdentityPub := strings.TrimSpace(existing.IdentityPubKey)
		storedNoisePub := strings.TrimSpace(existing.NoisePublicKey)
		storedAWGPublic := strings.TrimSpace(existing.AWGPublicKey)
		switch {
		case existing.Status == "revoked":
			return deviceEnrollResponse{OK: false, Error: "device is not approved", Code: "device_revoked"}, nil
		case existing.Status != "approved":
			return deviceEnrollResponse{OK: false, Error: "device is not approved"}, nil
		case storedIdentityPub == "" || storedIdentityPub != identityPub:
			return deviceEnrollResponse{OK: false, Error: "device identity mismatch"}, nil
		case storedNoisePub == "" || storedNoisePub != noisePub:
			return deviceEnrollResponse{OK: false, Error: "device noise pub mismatch"}, nil
		case storedAWGPublic == "" || storedAWGPublic != awgPublic:
			return deviceEnrollResponse{OK: false, Error: "device awg public key mismatch"}, nil
		}
		existing, err = s.store.ensureDeviceAWGProfiles(existing.ID, awgProfiles, awgPublic)
		if err != nil {
			return nil, err
		}
		// Re-enrollment after an app upgrade or downgrade re-negotiates Vision
		// and records the new version, so the returned bundle picks the AWG
		// profile for the version actually installed.
		caps := req.capabilities()
		version := strings.TrimSpace(req.ClientVersion)
		if version == "" {
			version = existing.ClientVersion
		}
		versionCode := deviceClientVersionCode(req.ClientVersionCode, version)
		now := time.Now().UTC()
		flow := decideRealityFlow(existing, caps, req.RealityFlowAck, now)
		if flow.Switched || flow.Pending != existing.RealityFlowPending || !slices.Equal(caps, existing.ClientCapabilities) || version != existing.ClientVersion || versionCode != existing.ClientVersionCode {
			// Only a flow switch is worker-visible (ORC-L5).
			existing, err = s.store.updateDevice(existing.ID, flow.Switched, func(rec *deviceRecord) error {
				if flow.Switched {
					rec.RealityFlowChangedAt = &now
				}
				rec.RealityFlow = flow.Flow
				rec.RealityFlowPending = flow.Pending
				rec.ClientCapabilities = caps
				rec.ClientVersion = version
				rec.ClientVersionCode = versionCode
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		bundle, err := s.buildClientBundle()
		if err != nil {
			return nil, err
		}
		if !clientBundleHasWorkers(bundle) {
			return deviceEnrollResponse{OK: false, Error: "no approved worker available yet"}, nil
		}
		pub, err := s.signerPublicKey()
		if err != nil {
			return nil, err
		}
		return deviceEnrollResponse{
			OK:                 true,
			DeviceID:           existing.ID,
			Status:             existing.Status,
			RealityUUID:        existing.RealityUUID,
			InternalIP:         existing.InternalIP,
			PSK2:               existing.PSK2,
			AWGProfiles:        existing.AWGProfiles,
			RealityFlow:        existing.RealityFlow,
			RealityFlowPending: existing.RealityFlowPending,
			ServerAWGPublic:    serverAWGPublic,
			SignerPublicKey:    pub,
			ClientBundle:       bundle,
		}, nil
	} else if !errors.Is(err, errNotFound) {
		return nil, err
	}
	device := deviceRecord{
		ID:                 id,
		NoisePublicKey:     noisePub,
		IdentityPubKey:     identityPub,
		IdentityKeyType:    strings.TrimSpace(req.IdentityKeyType),
		AndroidID:          strings.TrimSpace(req.AndroidID),
		Model:              strings.TrimSpace(req.Model),
		EnrollmentNonce:    strings.TrimSpace(req.EnrollmentNonce),
		ClientVersion:      strings.TrimSpace(req.ClientVersion),
		ClientVersionCode:  deviceClientVersionCode(req.ClientVersionCode, req.ClientVersion),
		AWGPublicKey:       awgPublic,
		RealityFlow:        deviceRealityFlow(req.capabilities()),
		ClientCapabilities: req.capabilities(),
	}
	// Never hand out ok:true with no worker to connect to, and decide that
	// before the one-time token is spent (retryable for all app versions).
	bundle, err := s.buildClientBundle()
	if err != nil {
		return nil, err
	}
	if !clientBundleHasWorkers(bundle) {
		return deviceEnrollResponse{OK: false, Error: "no approved worker available yet"}, nil
	}
	_, stored, err := s.store.consumeBootstrapToken(req.BootstrapToken, device, awgProfiles)
	if err != nil {
		return deviceEnrollResponse{OK: false, Error: err.Error()}, nil
	}
	pub, err := s.signerPublicKey()
	if err != nil {
		return nil, err
	}
	return deviceEnrollResponse{
		OK:              true,
		DeviceID:        stored.ID,
		Status:          stored.Status,
		RealityUUID:     stored.RealityUUID,
		InternalIP:      stored.InternalIP,
		PSK2:            stored.PSK2,
		AWGProfiles:     stored.AWGProfiles,
		RealityFlow:     stored.RealityFlow,
		ServerAWGPublic: serverAWGPublic,
		SignerPublicKey: pub,
		ClientBundle:    bundle,
	}, nil
}

func makeBootstrapPayload(cfg orchConfig, pubkey, orchNoisePublic, token string, rec tokenRecord) bootstrapPayload {
	return bootstrapPayload{
		OrchestratorURL: strings.TrimRight(cfg.PublicURL, "/"),
		ConfigPubkeyPin: pubkey,
		OrchNoisePublic: orchNoisePublic,
		UpdatePubkey:    strings.TrimSpace(cfg.UpdatePublicKey),
		SeedWorkers:     append([]string(nil), rec.SeedWorkers...),
		BootstrapToken:  token,
		Limits:          copyRawJSON(rec.Limits),
		Expires:         rec.ExpiresAt.UTC().Format(time.RFC3339),

		OrchTLSSPKISHA256: orchTLSSPKIPins(cfg),
	}
}

func clientBundleHasWorkers(bundle signedConfig) bool {
	var doc struct {
		Workers []json.RawMessage `json:"workers"`
	}
	return json.Unmarshal([]byte(bundle.ConfigJSON), &doc) == nil && len(doc.Workers) > 0
}

// enrollErrorCode maps an enrollment refusal to its structured code. Codes
// of retryable refusals (no_worker, retry) come with texts that carry the
// transient markers old apps look for ("no approved worker", "retry").
func enrollErrorCode(text string) string {
	switch {
	case strings.Contains(text, "no approved worker"):
		return "no_worker"
	case strings.Contains(text, "bootstrap token"):
		return "token_invalid"
	case strings.Contains(text, "device is not approved"):
		return "device_not_approved"
	case strings.Contains(text, "identity mismatch"):
		return "identity_mismatch"
	case strings.Contains(text, "noise pub mismatch"):
		return "noise_mismatch"
	case strings.Contains(text, "awg public key mismatch"):
		return "awg_key_mismatch"
	case strings.Contains(text, "retry"):
		return "retry"
	}
	return ""
}
