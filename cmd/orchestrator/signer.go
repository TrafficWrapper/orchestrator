package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"
)

const signerDialTimeout = 2 * time.Second

// signerCallTimeout bounds one signer round trip (a var so tests can shorten it).
var signerCallTimeout = 10 * time.Second

type signerRequest struct {
	Action  string `json:"action"`
	Message string `json:"message,omitempty"`
}

type signerResponse struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Signature string `json:"signature,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

type signerClient struct {
	socket string
}

type configSigner interface {
	publicKey() (string, error)
	sign(message string) (signedConfig, error)
}

func runSigner(cfg orchConfig) error {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	keyPath := signerKeyPath(cfg)
	if err := migrateLegacySignerKey(keyPath, cfg.SignerLegacyKeyPath); err != nil {
		return err
	}
	pub, priv, err := loadOrCreateMinisignKey(keyPath)
	if err != nil {
		return err
	}
	// The discovery feed has its own key in the signer (ORC-L20); it is
	// used once the orchestrator runs with ORCH_DISCOVERY_SIGNER=1.
	discPub, discPriv, err := loadOrCreateMinisignKey(discoveryKeyPath(keyPath))
	if err != nil {
		return err
	}
	policy, err := loadSignerPolicy(signerPolicyPath(keyPath))
	if err != nil {
		return err
	}
	keys := signerKeys{pub: pub, priv: priv, discPub: discPub, discPriv: discPriv, policy: policy}
	_ = os.Remove(cfg.SignerSocket)
	if err := os.MkdirAll(filepath.Dir(cfg.SignerSocket), 0o700); err != nil {
		return err
	}
	var l net.Listener
	if err := withUmask(0o177, func() error {
		var err error
		l, err = net.Listen("unix", cfg.SignerSocket)
		return err
	}); err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chmod(cfg.SignerSocket, 0o600); err != nil {
		return err
	}
	fmt.Printf("signer=ready socket=%s public_key=%s\n", cfg.SignerSocket, mustText(pub))
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go handleSignerConn(c, keys)
	}
}

func signerKeyPath(cfg orchConfig) string {
	if p := strings.TrimSpace(cfg.SignerKeyPath); p != "" {
		return p
	}
	return filepath.Join(cfg.StateDir, "orch-config.key")
}

// migrateLegacySignerKey moves a config-signing key from the shared
// orchestrator state directory into the signer-only key path, keeping the
// pinned public key stable. The legacy copy is removed so the internet-facing
// orchestrator process can no longer read it.
func migrateLegacySignerKey(keyPath, legacyPath string) error {
	legacyPath = strings.TrimSpace(legacyPath)
	if legacyPath == "" || filepath.Clean(legacyPath) == filepath.Clean(keyPath) {
		return nil
	}
	legacy, err := os.ReadFile(legacyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := os.Stat(keyPath); err == nil {
		current, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		if string(current) != string(legacy) {
			return fmt.Errorf("signer key exists at both %s and legacy %s with different contents; remove the one that is not pinned by workers/clients", keyPath, legacyPath)
		}
		return os.Remove(legacyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, legacy, 0o600); err != nil {
		return err
	}
	fmt.Printf("signer=migrated key from=%s to=%s\n", legacyPath, keyPath)
	return os.Remove(legacyPath)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// signerKeys are the signer's keys and signing policy.
type signerKeys struct {
	pub, discPub   minisign.PublicKey
	priv, discPriv minisign.PrivateKey
	policy         *signerPolicy
}

func discoveryKeyPath(keyPath string) string {
	return filepath.Join(filepath.Dir(keyPath), "discovery.key")
}

func handleSignerConn(c net.Conn, keys signerKeys) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(signerCallTimeout))
	var req signerRequest
	resp := signerResponse{OK: true}
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		resp = signerResponse{OK: false, Error: err.Error()}
	} else {
		switch req.Action {
		case "public-key":
			resp.PublicKey = mustText(keys.pub)
		case "discovery-public-key":
			resp.PublicKey = mustText(keys.discPub)
		case "sign", "sign-discovery":
			pub, priv, namespaces := keys.pub, keys.priv, []string{nsClientConfig, nsWorkerConfig}
			if req.Action == "sign-discovery" {
				pub, priv, namespaces = keys.discPub, keys.discPriv, []string{nsDiscovery}
			}
			if strings.TrimSpace(req.Message) == "" {
				resp = signerResponse{OK: false, Error: "message is empty"}
			} else if err := keys.policy.admit(req.Message, namespaces...); err != nil {
				resp = signerResponse{OK: false, Error: err.Error()}
			} else {
				resp.Signature = string(minisign.Sign(priv, []byte(req.Message)))
				resp.PublicKey = mustText(pub)
			}
		default:
			resp = signerResponse{OK: false, Error: "unknown signer action"}
		}
	}
	_ = json.NewEncoder(c).Encode(resp)
}

// loadOrCreateMinisignKey loads the signing key. A key is only generated on
// first initialisation: once <key>.initialized exists, a missing key file is
// an error (a lost key must be restored or rotated on purpose, never silently
// replaced; ORC-L7). Keys are written atomically and fsynced (ORC-L9).
func loadOrCreateMinisignKey(path string) (minisign.PublicKey, minisign.PrivateKey, error) {
	marker := path + ".initialized"
	if raw, err := os.ReadFile(path); err == nil {
		var priv minisign.PrivateKey
		if err := priv.UnmarshalText(raw); err != nil {
			return minisign.PublicKey{}, minisign.PrivateKey{}, err
		}
		pub, ok := priv.Public().(minisign.PublicKey)
		if !ok {
			return minisign.PublicKey{}, minisign.PrivateKey{}, errors.New("bad minisign public key")
		}
		if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
			if err := writeFileAtomic(marker, []byte(mustText(pub)+"\n"), 0o600); err != nil {
				return minisign.PublicKey{}, minisign.PrivateKey{}, err
			}
		}
		return pub, priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	if _, err := os.Stat(marker); err == nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, fmt.Errorf("signing key %s is missing but was initialised before: restore it, or remove %s to generate a new key on purpose", path, marker)
	}
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	raw, err := priv.MarshalText()
	if err != nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	if err := writeFileAtomic(marker, []byte(mustText(pub)+"\n"), 0o600); err != nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	return pub, priv, nil
}

func mustText(v interface{ MarshalText() ([]byte, error) }) string {
	raw, err := v.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func (c signerClient) publicKey() (string, error) {
	resp, err := c.call(signerRequest{Action: "public-key"})
	if err != nil {
		return "", err
	}
	return resp.PublicKey, nil
}

// discoverySigner signs the discovery feed with the signer's discovery key.
type discoverySigner interface {
	discoveryPublicKey() (string, error)
	signDiscovery(message string) (string, string, error)
}

func (c signerClient) discoveryPublicKey() (string, error) {
	resp, err := c.call(signerRequest{Action: "discovery-public-key"})
	if err != nil {
		return "", err
	}
	return resp.PublicKey, nil
}

// signDiscovery returns the signature and the public key that made it.
func (c signerClient) signDiscovery(message string) (string, string, error) {
	resp, err := c.call(signerRequest{Action: "sign-discovery", Message: message})
	if err != nil {
		return "", "", err
	}
	return resp.Signature, resp.PublicKey, nil
}

func (c signerClient) sign(message string) (signedConfig, error) {
	resp, err := c.call(signerRequest{Action: "sign", Message: message})
	if err != nil {
		return signedConfig{}, err
	}
	sum := sha256.Sum256([]byte(message))
	return signedConfig{
		ConfigJSON:   message,
		Minisig:      resp.Signature,
		PublicKey:    resp.PublicKey,
		ConfigSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func (c signerClient) call(req signerRequest) (signerResponse, error) {
	conn, err := net.DialTimeout("unix", c.socket, signerDialTimeout)
	if err != nil {
		return signerResponse{}, err
	}
	defer conn.Close()
	// A hung signer must not wedge every pull, enroll and discovery request.
	_ = conn.SetDeadline(time.Now().Add(signerCallTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return signerResponse{}, err
	}
	var resp signerResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return signerResponse{}, err
	}
	if !resp.OK {
		return signerResponse{}, errors.New(resp.Error)
	}
	return resp, nil
}

// signerPublicKey returns the config-signing public key, asking the signer
// once and caching the answer (it only changes with a restart-level key
// rotation). Failures are not cached.
func (s *server) signerPublicKey() (string, error) {
	s.signerPubMu.Lock()
	cached := s.signerPub
	s.signerPubMu.Unlock()
	if cached != "" {
		return cached, nil
	}
	pub, err := s.signer.publicKey()
	if err != nil {
		return "", err
	}
	if err := s.store.checkSignerKey(pub); err != nil {
		return "", err
	}
	s.signerPubMu.Lock()
	s.signerPub = pub
	s.signerPubMu.Unlock()
	return pub, nil
}
