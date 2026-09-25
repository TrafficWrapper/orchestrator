package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flynn/noise"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func tokenCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: orchestrator token create --id ID --value TOKEN --ttl 1h")
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	id := fs.String("id", "", "token id")
	value := fs.String("value", "", "token value")
	ttlText := fs.String("ttl", "1h", "ttl")
	workerStaticPub := fs.String("worker-static-pub", "", "optional pinned worker static public key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ttl, err := time.ParseDuration(*ttlText)
	if err != nil {
		return err
	}
	if err := adminPost(cfg, "/admin/v1/token/create", map[string]string{"id": *id, "value": *value, "ttl": ttl.String(), "worker_static_pub": *workerStaticPub}, os.Stdout); !errors.Is(err, errAdminServerUnreachable) {
		// Reached the server: report its answer instead of bypassing it.
		return err
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	if err := st.createToken(*id, *value, ttl, 1, *workerStaticPub); err != nil {
		return err
	}
	fmt.Printf("token_created id=%s ttl=%s max_uses=1\n", *id, ttl)
	return nil
}

func bootstrapTokenCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: orchestrator bootstrap-token create --limits JSON --expires RFC3339 [--seed-workers URL,URL]")
	}
	fs := flag.NewFlagSet("bootstrap-token create", flag.ContinueOnError)
	limitsText := fs.String("limits", "{}", "bootstrap limits json")
	expiresText := fs.String("expires", "", "RFC3339 expiry")
	seedWorkersText := fs.String("seed-workers", "", "comma-separated seed worker URLs")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	expiresAt, err := parseRFC3339Required(*expiresText)
	if err != nil {
		return err
	}
	limits, err := parseJSONObjectRaw(*limitsText)
	if err != nil {
		return err
	}
	seedWorkers := splitCSV(*seedWorkersText)
	req := map[string]any{
		"limits":       json.RawMessage(limits),
		"expires":      expiresAt.Format(time.RFC3339),
		"seed_workers": seedWorkers,
	}
	if err := adminPost(cfg, "/admin/v1/bootstrap-token/create", req, os.Stdout); !errors.Is(err, errAdminServerUnreachable) {
		// Reached the server: report its answer instead of bypassing it.
		return err
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	if len(seedWorkers) == 0 {
		workers, err := st.workers()
		if err == nil {
			seedWorkers = defaultSeedWorkersFromRecords(workers)
		}
	}
	signer := signerClient{socket: cfg.SignerSocket}
	pub, err := signer.publicKey()
	if err != nil {
		return err
	}
	static, err := loadOrCreateStaticKey(cfg)
	if err != nil {
		return err
	}
	secret, err := randomTokenSecret()
	if err != nil {
		return err
	}
	rec, err := st.createBootstrapToken(secret, expiresAt, limits, seedWorkers)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(makeBootstrapPayload(cfg, pub, protocol.KeyToBase64(static.Public), secret, rec))
}

func statusCommand(cfg orchConfig) error {
	if err := adminGet(cfg, "/admin/v1/status", os.Stdout); !errors.Is(err, errAdminServerUnreachable) {
		// Reached the server: report its answer instead of bypassing it.
		return err
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		return err
	}
	defer st.close()
	workers, err := st.workers()
	if err != nil {
		return err
	}
	for _, w := range workers {
		fmt.Printf("worker=%s status=%s desired=%d applied=%d egress_ack=%s egress_probe=%s\n", w.ID, w.Status, w.DesiredSeq, w.AppliedSeq, w.EgressIPObserved, w.EgressIPProbe)
	}
	return nil
}

func deviceEnrollSmokeCommand(cfg orchConfig, args []string) error {
	fs := flag.NewFlagSet("device-enroll-smoke", flag.ContinueOnError)
	token := fs.String("bootstrap-token", "", "one-time bootstrap token secret")
	deviceID := fs.String("device-id", "smoke-device", "device id")
	identityPub := fs.String("identity-pub", "smoke-identity", "device identity public key")
	awgPublic := fs.String("awg-public-key", "", "device AWG public key, generated if empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*token) == "" {
		return errors.New("--bootstrap-token is required")
	}
	clientStatic, err := protocol.GenerateKeypair()
	if err != nil {
		return err
	}
	awgPrivate := ""
	if strings.TrimSpace(*awgPublic) == "" {
		awgKey, err := protocol.GenerateKeypair()
		if err != nil {
			return err
		}
		awgPrivate = protocol.KeyToBase64(awgKey.Private)
		*awgPublic = protocol.KeyToBase64(awgKey.Public)
	}
	serverStatic, err := loadOrCreateStaticKey(cfg)
	if err != nil {
		return err
	}
	var resp deviceEnrollResponse
	if err := noiseJSONRequest(
		cfg,
		protocol.KeyToBase64(serverStatic.Public),
		clientStatic,
		"/d/v1/enroll",
		deviceEnrollRequest{
			BootstrapToken:  *token,
			NoisePublicKey:  protocol.KeyToBase64(clientStatic.Public),
			DeviceID:        *deviceID,
			IdentityPubKey:  *identityPub,
			IdentityKeyType: "smoke",
			EnrollmentNonce: randID(),
			ClientVersion:   "device-enroll-smoke",
			AWGPublicKey:    *awgPublic,
		},
		&resp,
	); err != nil {
		return err
	}
	out := map[string]any{
		"response":        resp,
		"awg_private_key": awgPrivate,
		"awg_public_key":  *awgPublic,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func adminCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 || args[0] != "set-password" {
		return errors.New("usage: orchestrator admin set-password (--stdin | --env VAR | --file PATH)")
	}
	fs := flag.NewFlagSet("admin set-password", flag.ContinueOnError)
	value := fs.String("value", "", "deprecated unsafe admin secret")
	stdin := fs.Bool("stdin", false, "read admin secret from stdin")
	envName := fs.String("env", "", "read admin secret from environment variable")
	filePath := fs.String("file", "", "read admin secret from file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	secret, err := readSecretInput(secretInputOptions{
		Value:       *value,
		Stdin:       *stdin,
		EnvName:     *envName,
		FilePath:    *filePath,
		UnsafeLabel: "--value",
	})
	if err != nil {
		return err
	}
	if err := validateAdminPassword(secret); err != nil {
		return err
	}
	st, err := openOrchStore(cfg)
	if err != nil {
		// A running orchestrator holds the database; setting the password
		// through the API needs the current one (change it in the admin UI).
		return fmt.Errorf("%w (stop the orchestrator to set the password directly, or change it in the admin UI)", err)
	}
	defer st.close()
	if err := st.setAdminPassword(secret); err != nil {
		return err
	}
	fmt.Println("admin_password_set")
	return nil
}

type secretInputOptions struct {
	Value       string
	Stdin       bool
	EnvName     string
	FilePath    string
	UnsafeLabel string
}

func readSecretInput(opts secretInputOptions) (string, error) {
	sources := 0
	if opts.Value != "" {
		sources++
	}
	if opts.Stdin {
		sources++
	}
	if strings.TrimSpace(opts.EnvName) != "" {
		sources++
	}
	if strings.TrimSpace(opts.FilePath) != "" {
		sources++
	}
	if sources != 1 {
		return "", errors.New("provide exactly one secret source: --stdin, --env, --file, or deprecated open argument")
	}
	switch {
	case opts.Value != "":
		label := firstNotBlank(opts.UnsafeLabel, "open argument")
		log.Printf("WARNING: %s exposes the secret via shell history and process list; use --stdin, --env, or --file", label)
		return strings.TrimSpace(opts.Value), nil
	case opts.Stdin:
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	case strings.TrimSpace(opts.EnvName) != "":
		value, ok := os.LookupEnv(strings.TrimSpace(opts.EnvName))
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", opts.EnvName)
		}
		return strings.TrimSpace(value), nil
	case strings.TrimSpace(opts.FilePath) != "":
		raw, err := os.ReadFile(strings.TrimSpace(opts.FilePath))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	default:
		return "", errors.New("secret source is required")
	}
}

func adminPost(cfg orchConfig, path string, payload any, out io.Writer) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return adminRequest(cfg, http.MethodPost, path, bytes.NewReader(raw), out)
}

func adminGet(cfg orchConfig, path string, out io.Writer) error {
	return adminRequest(cfg, http.MethodGet, path, nil, out)
}

func noiseJSONRequest(cfg orchConfig, serverPublic string, clientStatic noise.DHKey, path string, req any, resp any) error {
	serverPub, err := protocol.DecodeKeyBase64(serverPublic)
	if err != nil {
		return err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(protocol.Prologue),
		StaticKeypair: clientStatic,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	var start startResponse
	if err := adminRequest(cfg, http.MethodPost, "/d/v1/handshake/start", bytes.NewReader(mustJSON(startRequest{Message: base64.StdEncoding.EncodeToString(msg1)})), discardDecode(&start)); err != nil {
		return err
	}
	if !start.OK {
		return errors.New(start.Error)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		return err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return err
	}
	msg3, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	payload, err := protocol.EncryptJSON(sendCipher, req)
	if err != nil {
		return err
	}
	var envResp noiseEnvelopeResponse
	if err := adminRequest(cfg, http.MethodPost, path, bytes.NewReader(mustJSON(noiseEnvelope{
		SID:     start.SID,
		Message: base64.StdEncoding.EncodeToString(msg3),
		Payload: base64.StdEncoding.EncodeToString(payload),
	})), discardDecode(&envResp)); err != nil {
		return err
	}
	if !envResp.OK {
		return errors.New(envResp.Error)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envResp.Payload)
	if err != nil {
		return err
	}
	return protocol.DecryptJSON(recvCipher, encrypted, resp)
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

type responseDecoder struct {
	target any
}

func discardDecode(target any) io.Writer {
	return responseDecoder{target: target}
}

func (d responseDecoder) Write(raw []byte) (int, error) {
	if err := json.Unmarshal(raw, d.target); err != nil {
		return 0, err
	}
	return len(raw), nil
}

// errAdminServerUnreachable marks a CLI admin request that never reached the
// server; only then may commands fall back to opening the database directly.
var errAdminServerUnreachable = errors.New("orchestrator admin API unreachable")

// adminTLSConfig trusts the orchestrator's own self-signed certificate
// (state/tls.crt, pinned by exact bytes) and otherwise performs normal
// verification, instead of skipping verification while sending a bearer
// token to whatever ORCH_ADMIN_URL points at.
// adminTLSRoots overrides the system roots for admin API verification
// (tests only; nil means the system pool).
var adminTLSRoots *x509.CertPool

func adminTLSConfig(cfg orchConfig, host string) *tls.Config {
	pinned, _ := os.ReadFile(filepath.Join(cfg.StateDir, "tls.crt"))
	var pinnedDER []byte
	if block, _ := pem.Decode(pinned); block != nil {
		pinnedDER = block.Bytes
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification happens in VerifyConnection so the pinned certificate
		// can be accepted without a matching hostname.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			leaf := cs.PeerCertificates[0]
			if pinnedDER != nil && bytes.Equal(leaf.Raw, pinnedDER) {
				return nil
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			// Verify against the host we dialed: for an IP host no SNI is sent,
			// so cs.ServerName is empty and would skip the name check.
			if strings.TrimSpace(host) == "" {
				return errors.New("admin URL has no host to verify")
			}
			_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates, Roots: adminTLSRoots})
			return err
		},
	}
}

func adminRequest(cfg orchConfig, method, path string, body io.Reader, out io.Writer) error {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	req, err := http.NewRequest(method, adminBaseURL(cfg)+path, body)
	if err != nil {
		return err
	}
	tr.TLSClientConfig = adminTLSConfig(cfg, req.URL.Hostname())
	client := http.Client{Transport: tr, Timeout: 15 * time.Second}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if token := strings.TrimSpace(os.Getenv("ORCH_ADMIN_SESSION_TOKEN")); token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return fmt.Errorf("%w: %v", errAdminServerUnreachable, err)
		}
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(raw))
		var apiErr apiError
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Error != "" {
			message = apiErr.Error
		}
		return fmt.Errorf("admin http %d: %s", resp.StatusCode, message)
	}
	_, _ = out.Write(raw)
	return nil
}

func adminBaseURL(cfg orchConfig) string {
	if value := strings.TrimRight(strings.TrimSpace(os.Getenv("ORCH_ADMIN_URL")), "/"); value != "" {
		return value
	}
	listen := strings.TrimSpace(cfg.Listen)
	if listen == "" {
		listen = ":9091"
	}
	host := "127.0.0.1"
	port := "9091"
	if strings.HasPrefix(listen, ":") {
		port = strings.TrimPrefix(listen, ":")
	} else {
		parts := strings.Split(listen, ":")
		if len(parts) > 1 {
			port = parts[len(parts)-1]
			candidateHost := strings.Join(parts[:len(parts)-1], ":")
			if candidateHost != "" && candidateHost != "0.0.0.0" && candidateHost != "::" && candidateHost != "[::]" {
				host = strings.Trim(candidateHost, "[]")
			}
		}
	}
	scheme := "https"
	if !cfg.TLS {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}
