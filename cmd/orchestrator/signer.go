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

	"aead.dev/minisign"
)

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
	keyPath := filepath.Join(cfg.StateDir, "orch-config.key")
	pub, priv, err := loadOrCreateMinisignKey(keyPath)
	if err != nil {
		return err
	}
	_ = os.Remove(cfg.SignerSocket)
	if err := os.MkdirAll(filepath.Dir(cfg.SignerSocket), 0o700); err != nil {
		return err
	}
	l, err := net.Listen("unix", cfg.SignerSocket)
	if err != nil {
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
		go handleSignerConn(c, pub, priv)
	}
}

func handleSignerConn(c net.Conn, pub minisign.PublicKey, priv minisign.PrivateKey) {
	defer c.Close()
	var req signerRequest
	resp := signerResponse{OK: true}
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		resp = signerResponse{OK: false, Error: err.Error()}
	} else {
		switch req.Action {
		case "public-key":
			resp.PublicKey = mustText(pub)
		case "sign":
			if strings.TrimSpace(req.Message) == "" {
				resp = signerResponse{OK: false, Error: "message is empty"}
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

func loadOrCreateMinisignKey(path string) (minisign.PublicKey, minisign.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var priv minisign.PrivateKey
		if err := priv.UnmarshalText(raw); err != nil {
			return minisign.PublicKey{}, minisign.PrivateKey{}, err
		}
		pub, ok := priv.Public().(minisign.PublicKey)
		if !ok {
			return minisign.PublicKey{}, minisign.PrivateKey{}, errors.New("bad minisign public key")
		}
		return pub, priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	raw, err := priv.MarshalText()
	if err != nil {
		return minisign.PublicKey{}, minisign.PrivateKey{}, err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
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
	conn, err := net.Dial("unix", c.socket)
	if err != nil {
		return signerResponse{}, err
	}
	defer conn.Close()
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
