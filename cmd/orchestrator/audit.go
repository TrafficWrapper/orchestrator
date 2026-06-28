package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var errAuditChainBroken = errors.New("audit hash chain broken")

type auditEntry struct {
	Time     time.Time         `json:"time"`
	Event    string            `json:"event"`
	Actor    string            `json:"actor,omitempty"`
	IP       string            `json:"ip,omitempty"`
	Result   string            `json:"result"`
	Fields   map[string]string `json:"fields,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

type auditLog struct {
	mu       sync.Mutex
	file     *os.File
	prevHash string
}

func openAuditLog(path string) (*auditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := ensureAuditFile(path, 0o600); err != nil {
		return nil, err
	}
	prevHash := lastAuditHash(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLog{file: file, prevHash: prevHash}, nil
}

func ensureAuditFile(path string, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	return file.Close()
}

func lastAuditHash(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	last := ""
	for scanner.Scan() {
		var entry auditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) == nil && entry.Hash != "" {
			last = entry.Hash
		}
	}
	return last
}

func (l *auditLog) Log(entry auditEntry) {
	if l == nil || l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	}
	entry.PrevHash = l.prevHash
	entry.Hash = ""
	payload, err := json.Marshal(entry)
	if err != nil {
		return
	}
	sum := sha256.Sum256(append([]byte(entry.PrevHash+"\n"), payload...))
	entry.Hash = hex.EncodeToString(sum[:])
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if _, err := l.file.Write(append(raw, '\n')); err != nil {
		return
	}
	_ = l.file.Sync()
	l.prevHash = entry.Hash
}

func (l *auditLog) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (s *server) auditEvent(entry auditEntry) {
	if s == nil || s.audit == nil {
		return
	}
	s.audit.Log(entry)
}

func verifyAuditChain(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	prev := ""
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		var entry auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return err
		}
		hash := entry.Hash
		if entry.PrevHash != prev {
			return errAuditChainBroken
		}
		entry.Hash = ""
		payload, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(append([]byte(entry.PrevHash+"\n"), payload...))
		if hex.EncodeToString(sum[:]) != hash {
			return errAuditChainBroken
		}
		prev = hash
	}
	return scanner.Err()
}
