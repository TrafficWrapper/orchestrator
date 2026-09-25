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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errAuditChainBroken = errors.New("audit hash chain broken")

const auditScannerMaxBytes = 16 * 1024 * 1024

const (
	// defaultAuditMaxBytes rotates the audit log once it reaches this size;
	// defaultAuditKeep rotated files (audit.log.1 is the newest) are kept
	// (ORC-M12).
	defaultAuditMaxBytes = 64 << 20
	defaultAuditKeep     = 5
	minAuditMaxBytes     = 1 << 20
	// auditRepeatWindow folds repeats of one event key into a single entry
	// with a counter per window; auditRepeatMaxKeys bounds the tracked keys.
	auditRepeatWindow  = time.Minute
	auditRepeatMaxKeys = 4096
	// auditRotatedEvent opens every file started by a rotation; its
	// prev_hash continues the chain of the previous file.
	auditRotatedEvent = "audit_log_rotated"
	// auditChainErrorMaxListed caps the breaks spelled out in the error
	// text; auditChainError.Breaks keeps all of them.
	auditChainErrorMaxListed = 50
)

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

// auditRotation sets size-based rotation; MaxBytes <= 0 disables it.
type auditRotation struct {
	MaxBytes int64
	Keep     int
}

type auditLog struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	size     int64
	prevHash string
	rotation auditRotation
	now      func() time.Time
	// repeats tracks the current window of each key logged through
	// LogRepeated; lastSweep throttles flushing expired windows.
	repeats   map[string]*auditRepeat
	lastSweep time.Time
}

type auditRepeat struct {
	windowStart time.Time
	suppressed  int
	last        auditEntry
}

// auditChainError lists every break found in the chain, not just the first.
type auditChainError struct {
	Breaks []string
}

func (e *auditChainError) Error() string {
	listed := e.Breaks
	if len(listed) > auditChainErrorMaxListed {
		listed = listed[:auditChainErrorMaxListed]
	}
	msg := fmt.Sprintf("%v: %d break(s): %s", errAuditChainBroken, len(e.Breaks), strings.Join(listed, "; "))
	if extra := len(e.Breaks) - len(listed); extra > 0 {
		msg += fmt.Sprintf("; and %d more", extra)
	}
	return msg
}

func (e *auditChainError) Unwrap() error { return errAuditChainBroken }

func openAuditLog(path string, rotation ...auditRotation) (*auditLog, error) {
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
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	logFile := &auditLog{
		path:     path,
		file:     file,
		size:     info.Size(),
		prevHash: prevHash,
		rotation: auditRotation{MaxBytes: defaultAuditMaxBytes, Keep: defaultAuditKeep},
		now:      time.Now,
		repeats:  map[string]*auditRepeat{},
	}
	if len(rotation) > 0 {
		logFile.rotation = rotation[0]
	}
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

// lastAuditHash returns the hash the next entry chains to: the last entry of
// the current file, or of the newest rotated file when the current one is
// still empty (a restart right after a rotation).
func lastAuditHash(path string) (string, error) {
	last, entries, err := lastAuditHashInFile(path)
	if err != nil || entries > 0 {
		return last, err
	}
	rotated := rotatedAuditPath(path, 1)
	if _, statErr := os.Stat(rotated); statErr != nil {
		return last, nil
	}
	last, _, err = lastAuditHashInFile(rotated)
	return last, err
}

func lastAuditHashInFile(path string) (string, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, auditScannerMaxBytes)
	last := ""
	var firstErr error
	line := 0
	entries := 0
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
		last = entry.Hash
		entries++
	}
	if err := scanner.Err(); err != nil {
		return last, entries, err
	}
	return last, entries, firstErr
}

func (l *auditLog) Log(entry auditEntry) {
	if l == nil || l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepRepeatsLocked(false)
	l.writeLocked(entry)
}

// LogRepeated writes the first entry for key in each auditRepeatWindow and
// only counts the rest; the count is written as a summary entry (field
// "repeats") when the window ends. Used for events a client can trigger at
// will, such as requests during a login lockout (ORC-M12).
func (l *auditLog) LogRepeated(key string, entry auditEntry) {
	if l == nil || l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepRepeatsLocked(false)
	now := l.now()
	if _, tracked := l.repeats[key]; !tracked && len(l.repeats) >= auditRepeatMaxKeys {
		key = "*overflow*"
	}
	if r := l.repeats[key]; r != nil && now.Sub(r.windowStart) < auditRepeatWindow {
		r.suppressed++
		r.last = entry
		return
	}
	l.writeLocked(entry)
	l.repeats[key] = &auditRepeat{windowStart: now}
}

// sweepRepeatsLocked writes the summaries of windows that have ended (all of
// them when final) and forgets those keys.
func (l *auditLog) sweepRepeatsLocked(final bool) {
	if len(l.repeats) == 0 {
		return
	}
	now := l.now()
	if !final && now.Sub(l.lastSweep) < auditRepeatWindow/4 {
		return
	}
	l.lastSweep = now
	keys := make([]string, 0, len(l.repeats))
	for key := range l.repeats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r := l.repeats[key]
		if !final && now.Sub(r.windowStart) < auditRepeatWindow {
			continue
		}
		delete(l.repeats, key)
		if r.suppressed == 0 {
			continue
		}
		summary := r.last
		summary.Time = time.Time{}
		fields := make(map[string]string, len(summary.Fields)+2)
		for k, v := range summary.Fields {
			fields[k] = v
		}
		fields["repeats"] = strconv.Itoa(r.suppressed)
		fields["window_start"] = r.windowStart.UTC().Format(time.RFC3339)
		summary.Fields = fields
		l.writeLocked(summary)
	}
}

func (l *auditLog) writeLocked(entry auditEntry) {
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	}
	raw, hash, ok := l.encodeLocked(entry)
	if !ok {
		return
	}
	if l.rotation.MaxBytes > 0 && l.size > 0 && l.size+int64(len(raw)) > l.rotation.MaxBytes {
		if err := l.rotateLocked(); err != nil {
			log.Printf("audit: rotation failed: %v", err)
		} else if raw, hash, ok = l.encodeLocked(entry); !ok {
			return
		}
	}
	l.appendLocked(entry.Event, raw, hash)
}

func (l *auditLog) encodeLocked(entry auditEntry) ([]byte, string, bool) {
	entry.PrevHash = l.prevHash
	entry.Hash = ""
	payload, err := json.Marshal(entry)
	if err != nil {
		log.Printf("audit: dropped %s event: marshal: %v", entry.Event, err)
		return nil, "", false
	}
	sum := sha256.Sum256(append([]byte(entry.PrevHash+"\n"), payload...))
	entry.Hash = hex.EncodeToString(sum[:])
	raw, err := json.Marshal(entry)
	if err != nil {
		log.Printf("audit: dropped %s event: marshal: %v", entry.Event, err)
		return nil, "", false
	}
	return append(raw, '\n'), entry.Hash, true
}

func (l *auditLog) appendLocked(event string, raw []byte, hash string) {
	// Security events must not vanish silently (e.g. on a full disk).
	n, err := l.file.Write(raw)
	l.size += int64(n)
	if err != nil {
		log.Printf("audit: failed to write %s event: %v", event, err)
		return
	}
	if err := l.file.Sync(); err != nil {
		log.Printf("audit: failed to sync %s event: %v", event, err)
	}
	l.prevHash = hash
}

// rotateLocked shifts audit.log to audit.log.1 (dropping the oldest beyond
// Keep) and starts a new file whose first entry continues the hash chain.
func (l *auditLog) rotateLocked() error {
	if l.path == "" {
		return errors.New("audit log path unknown")
	}
	keep := l.rotation.Keep
	if keep < 1 {
		keep = 1
	}
	if err := l.file.Close(); err != nil {
		log.Printf("audit: close before rotation: %v", err)
	}
	_ = os.Remove(rotatedAuditPath(l.path, keep))
	for i := keep - 1; i >= 1; i-- {
		if err := os.Rename(rotatedAuditPath(l.path, i), rotatedAuditPath(l.path, i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("audit: rotate %s: %v", rotatedAuditPath(l.path, i), err)
		}
	}
	renameErr := os.Rename(l.path, rotatedAuditPath(l.path, 1))
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.file = file
	l.size = 0
	if info, err := file.Stat(); err == nil {
		l.size = info.Size()
	}
	if renameErr != nil {
		return renameErr
	}
	marker := auditEntry{Time: time.Now().UTC(), Event: auditRotatedEvent, Result: "ok", Fields: map[string]string{"previous": filepath.Base(rotatedAuditPath(l.path, 1))}}
	if raw, hash, ok := l.encodeLocked(marker); ok {
		l.appendLocked(marker.Event, raw, hash)
	}
	return nil
}

func rotatedAuditPath(path string, n int) string {
	return path + "." + strconv.Itoa(n)
}

func (l *auditLog) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepRepeatsLocked(true)
	return l.file.Close()
}

func (s *server) auditEvent(entry auditEntry) {
	if s == nil || s.audit == nil {
		return
	}
	s.audit.Log(entry)
}

// auditRepeatedEvent aggregates repeats of entry under key (see
// auditLog.LogRepeated).
func (s *server) auditRepeatedEvent(key string, entry auditEntry) {
	if s == nil || s.audit == nil {
		return
	}
	s.audit.LogRepeated(key, entry)
}

// verifyAuditChain checks the hash chain of the current file and the rotated
// files kept next to it, oldest first. It does not stop at the first break:
// the returned *auditChainError lists all of them (ORC-L16). The oldest kept
// file may start mid-chain when it begins with a rotation marker.
func verifyAuditChain(path string) error {
	var files []string
	for i := 1; ; i++ {
		rotated := rotatedAuditPath(path, i)
		if _, err := os.Stat(rotated); err != nil {
			break
		}
		files = append([]string{rotated}, files...)
	}
	files = append(files, path)

	var breaks []string
	prev := ""
	for index, name := range files {
		var err error
		prev, breaks, err = verifyAuditFile(name, prev, index == 0, breaks)
		if err != nil {
			return err
		}
	}
	if len(breaks) > 0 {
		return &auditChainError{Breaks: breaks}
	}
	return nil
}

func verifyAuditFile(path, prev string, oldest bool, breaks []string) (string, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return prev, breaks, err
	}
	defer file.Close()

	name := filepath.Base(path)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, auditScannerMaxBytes)
	line := 0
	// resync accepts the next entry's prev_hash after an unreadable line so
	// one damaged line is reported once, not twice.
	resync := false
	for scanner.Scan() {
		line++
		var entry auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			breaks = append(breaks, fmt.Sprintf("%s line %d: %v", name, line, err))
			resync = true
			continue
		}
		hash := entry.Hash
		continuesRotated := oldest && line == 1 && entry.Event == auditRotatedEvent
		if entry.PrevHash != prev && !resync && !continuesRotated {
			breaks = append(breaks, fmt.Sprintf("%s line %d: prev_hash mismatch", name, line))
		}
		resync = false
		entry.Hash = ""
		payload, err := json.Marshal(entry)
		if err != nil {
			return prev, breaks, err
		}
		sum := sha256.Sum256(append([]byte(entry.PrevHash+"\n"), payload...))
		if hex.EncodeToString(sum[:]) != hash {
			breaks = append(breaks, fmt.Sprintf("%s line %d: hash mismatch", name, line))
		}
		prev = hash
	}
	return prev, breaks, scanner.Err()
}
