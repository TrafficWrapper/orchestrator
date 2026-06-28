package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var errAuditChainBroken = errors.New("audit hash chain broken")

const auditScannerMaxBytes = 16 * 1024 * 1024

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
	verifyErr := verifyAuditChain(path)
	prevHash, tailErr := lastAuditHash(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	logFile := &auditLog{file: file, prevHash: prevHash}
	if verifyErr != nil || tailErr != nil {
		log.Printf("AUDIT CHAIN BROKEN/TAMPER path=%s verify_error=%v tail_error=%v", path, verifyErr, tailErr)
		fields := map[string]string{}
		if verifyErr != nil {
			fields["verify_error"] = verifyErr.Error()
		}
		if tailErr != nil {
			fields["tail_error"] = tailErr.Error()
		}
		logFile.Log(auditEntry{Event: "audit_chain_break_detected", Result: "warning", Fields: fields})
	}
	return logFile, nil
}

func ensureAuditFile(path string, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	return file.Close()
}

func lastAuditHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, auditScannerMaxBytes)
	last := ""
	var firstErr error
	line := 0
	for scanner.Scan() {
		line++
		var entry auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w at line %d: %v", errAuditChainBroken, line, err)
			}
			continue
		}
		if entry.Hash == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w at line %d: missing hash", errAuditChainBroken, line)
			}
			continue
		}
		if entry.Hash != "" {
			last = entry.Hash
		}
	}
	if err := scanner.Err(); err != nil {
		return last, err
	}
	return last, firstErr
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
	scanner.Buffer(buf, auditScannerMaxBytes)
	line := 0
	for scanner.Scan() {
		line++
		var entry auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return fmt.Errorf("%w at line %d: %v", errAuditChainBroken, line, err)
		}
		hash := entry.Hash
		if entry.PrevHash != prev {
			return fmt.Errorf("%w at line %d: prev_hash mismatch", errAuditChainBroken, line)
		}
		entry.Hash = ""
		payload, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(append([]byte(entry.PrevHash+"\n"), payload...))
		if hex.EncodeToString(sum[:]) != hash {
			return fmt.Errorf("%w at line %d: hash mismatch", errAuditChainBroken, line)
		}
		prev = hash
	}
	return scanner.Err()
}
