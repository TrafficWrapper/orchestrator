package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/pbkdf2"
)

const (
	Prologue     = "TrafficWrapper orchestrator worker v1"
	MaxFrameSize = 1 << 20
	KeySize      = 32
)

type KeyPairFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func CipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

func GenerateKeypair() (noise.DHKey, error) {
	return CipherSuite().GenerateKeypair(rand.Reader)
}

func NewKeyPairFile(key noise.DHKey) KeyPairFile {
	return KeyPairFile{PrivateKey: KeyToBase64(key.Private), PublicKey: KeyToBase64(key.Public)}
}

func DecodeKeyPair(privateKey, publicKey string) (noise.DHKey, error) {
	privateBytes, err := DecodeKeyBase64(privateKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("private key: %w", err)
	}
	publicBytes, err := DecodeKeyBase64(publicKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("public key: %w", err)
	}
	return noise.DHKey{Private: privateBytes, Public: publicBytes}, nil
}

func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func DecodeKeyBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != KeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", KeySize, len(raw))
	}
	return raw, nil
}

func Base64KeyToHex(value string) (string, error) {
	raw, err := DecodeKeyBase64(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", size)
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func EncryptJSON(cipher *noise.CipherState, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(nil, nil, plain)
}

func DecryptJSON(cipher *noise.CipherState, encrypted []byte, value any) error {
	plain, err := cipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func HashSecret(secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secret is empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const iterations = 150000
	key := pbkdf2.Key([]byte(secret), salt, iterations, KeySize, sha256.New)
	return fmt.Sprintf("pbkdf2-sha256:%d:%s:%s", iterations, base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)), nil
}

func VerifySecret(encoded, secret string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || secret == "" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10000 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != KeySize {
		return false
	}
	actual := pbkdf2.Key([]byte(secret), salt, iterations, len(expected), sha256.New)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
