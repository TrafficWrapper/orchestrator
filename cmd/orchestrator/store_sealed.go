package main

import (
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Typed helpers for sealed records. Every sealed read/write goes through
// openJSON/sealJSON with the record's own bucket and key, which binds the
// ciphertext to its location (see sealedRecordAD).

// getSealedTx decrypts bucket/key into a T, returning notFound when absent.
func getSealedTx[T any](s *orchStore, tx *bolt.Tx, bucket []byte, key string, notFound error) (T, error) {
	var rec T
	raw := tx.Bucket(bucket).Get([]byte(key))
	if raw == nil {
		return rec, notFound
	}
	err := s.openJSON(bucket, []byte(key), raw, &rec)
	return rec, err
}

// putSealedTx seals v and stores it at bucket/key.
func putSealedTx(s *orchStore, tx *bolt.Tx, bucket []byte, key string, v any) error {
	sealed, err := s.sealJSON(bucket, []byte(key), v)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put([]byte(key), sealed)
}

// getSealed reads one sealed record in its own read transaction.
func getSealed[T any](s *orchStore, bucket []byte, key string, notFound error) (T, error) {
	var rec T
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		rec, err = getSealedTx[T](s, tx, bucket, key, notFound)
		return err
	})
	return rec, err
}

// listSealed decrypts every record of a bucket, calling fn with its key.
func listSealed[T any](s *orchStore, bucket []byte, fn func(key string, rec T)) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(k, raw []byte) error {
			var rec T
			if err := s.openJSON(bucket, k, raw, &rec); err != nil {
				return err
			}
			fn(string(k), rec)
			return nil
		})
	})
}

// getMeta reads a sealed singleton from the meta bucket; ok is false when it
// has never been stored.
func getMeta[T any](s *orchStore, key []byte) (T, bool, error) {
	rec, err := getSealed[T](s, bucketMeta, string(key), errNotFound)
	if err == errNotFound {
		var zero T
		return zero, false, nil
	}
	return rec, err == nil, err
}

// putMeta stores a sealed singleton in the meta bucket.
func putMeta(s *orchStore, key []byte, v any) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putSealedTx(s, tx, bucketMeta, string(key), v)
	})
}

// updateDevice loads device id, applies fn and stores it; when bump is set
// the change is worker-visible and every worker's seq is bumped with it.
func (s *orchStore) updateDevice(id string, bump bool, fn func(*deviceRecord) error) (deviceRecord, error) {
	id = strings.TrimSpace(id)
	var out deviceRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		rec, err := getSealedTx[deviceRecord](s, tx, bucketDevices, id, errDeviceNotFound)
		if err != nil {
			return err
		}
		if err := fn(&rec); err != nil {
			return err
		}
		if err := putSealedTx(s, tx, bucketDevices, id, rec); err != nil {
			return err
		}
		out = rec
		if bump {
			return s.bumpWorkerSeqsTx(tx)
		}
		return nil
	})
	return out, err
}
