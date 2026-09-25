package main

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The orchestrator pins the config-signing public key the first time it
// talks to the signer (ORC-L7). A signer that silently generated a new key
// (lost key file) would otherwise have every worker and client reject what
// it signs while the orchestrator kept advertising the old key. After an
// intentional rotation the operator clears the pin with
// `orchestrator signer-accept-key`.
var metaSignerPin = []byte("signer_public_key")

type signerPinRecord struct {
	PublicKey string    `json:"public_key"`
	PinnedAt  time.Time `json:"pinned_at"`
}

var errSignerKeyChanged = errors.New("signer public key differs from the pinned key (run `orchestrator signer-accept-key` after an intentional rotation)")

// checkSignerKey pins pub on first use and rejects any other key afterwards.
func (s *orchStore) checkSignerKey(pub string) error {
	if pub == "" {
		return errors.New("signer returned no public key")
	}
	var mismatch bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if raw := b.Get(metaSignerPin); raw != nil {
			var rec signerPinRecord
			if err := s.openJSON(bucketMeta, metaSignerPin, raw, &rec); err != nil {
				return err
			}
			mismatch = rec.PublicKey != pub
			return nil
		}
		sealed, err := s.sealJSON(bucketMeta, metaSignerPin, signerPinRecord{PublicKey: pub, PinnedAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		return b.Put(metaSignerPin, sealed)
	})
	if err != nil {
		return err
	}
	if mismatch {
		log.Printf("ALERT %v", errSignerKeyChanged)
		return errSignerKeyChanged
	}
	return nil
}

func clearSignerPin(stateDir string) error {
	db, err := bolt.Open(filepath.Join(stateDir, "orchestrator.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("open store (stop the orchestrator first): %w", err)
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if b == nil {
			return nil
		}
		return b.Delete(metaSignerPin)
	})
}

// sign signs a config and refuses to hand out anything signed by a key other
// than the pinned one.
func (s *server) sign(message string) (signedConfig, error) {
	signed, err := s.signer.sign(message)
	if err != nil {
		return signedConfig{}, err
	}
	if err := s.store.checkSignerKey(signed.PublicKey); err != nil {
		return signedConfig{}, err
	}
	return signed, nil
}
