package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/pbkdf2"
)

// HashIterations is the PBKDF2 work factor for newly hashed secrets. Tests
// lower it (never below MinHashIterations, which VerifySecret enforces).
var HashIterations = 150000

// MinHashIterations is the weakest stored hash VerifySecret accepts.
const MinHashIterations = 10000

const (
	Prologue = "TrafficWrapper orchestrator worker v1"
	KeySize  = 32
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
	iterations := HashIterations
	key := pbkdf2.Key([]byte(secret), salt, iterations, KeySize, sha256.New)
	return fmt.Sprintf("pbkdf2-sha256:%d:%s:%s", iterations, base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)), nil
}

func VerifySecret(encoded, secret string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || secret == "" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < MinHashIterations {
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
