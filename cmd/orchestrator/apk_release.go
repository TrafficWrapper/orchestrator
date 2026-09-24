package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"
)

func (s *server) handleAdminAPKStatus(w http.ResponseWriter, r *http.Request) {
	rec, ok, err := s.store.currentAPKRelease()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{
		"ok":                       true,
		"update_pubkey_configured": strings.TrimSpace(s.cfg.UpdatePublicKey) != "",
		"server_update_key":        s.serverUpdateSigningAvailable(),
		"next_seq":                 mustNextAPKSeq(s.store),
		"release":                  optionalAPKRelease(rec, ok),
	})
}

func (s *server) handleAdminAPKDownload(w http.ResponseWriter, r *http.Request) {
	rec, ok, err := s.store.currentAPKRelease()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok || strings.TrimSpace(rec.APKPath) == "" {
		writeError(w, "apk release is not published", http.StatusNotFound)
		return
	}
	file, err := os.Open(rec.APKPath)
	if err != nil {
		writeStoreError(w, http.StatusNotFound, err)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	name := fmt.Sprintf("TrafficWrapper-%d.apk", rec.VersionCode)
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeContent(w, r, name, stat.ModTime(), file)
}

func (s *server) handleAdminAPKInspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(160 << 20); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	apkFile, apkHeader, err := r.FormFile("apk")
	if err != nil {
		writeError(w, "apk file is required", http.StatusBadRequest)
		return
	}
	defer apkFile.Close()
	sha, size, err := hashMultipartFile(apkFile)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	version, versionErr := inspectAPKVersion(apkFile, size)
	if _, err := apkFile.Seek(0, io.SeekStart); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	resp := map[string]any{
		"ok":         true,
		"apk_name":   safeAPKName(apkHeader.Filename, version.VersionCode),
		"apk_sha256": sha,
		"apk_size":   size,
	}
	if versionErr != nil {
		resp["version_detected"] = false
		resp["version_error"] = versionErr.Error()
	} else {
		resp["version_detected"] = true
		resp["version_code"] = version.VersionCode
		resp["version_name"] = version.VersionName
	}
	writeJSON(w, resp)
}

func (s *server) handleAdminAPKDraft(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		APKSHA256   string `json:"apk_sha256"`
		APKSize     int64  `json:"apk_size"`
		APKName     string `json:"apk_name"`
		MinVersion  int64  `json:"min_version"`
		Notes       string `json:"notes"`
		Seq         int64  `json:"seq"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	seq := req.Seq
	if seq <= 0 {
		var err error
		seq, err = s.store.nextAPKSeq()
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, err)
			return
		}
	}
	manifestJSON, err := buildAPKManifest(apkManifestInput{
		Seq:         seq,
		VersionCode: req.VersionCode,
		VersionName: req.VersionName,
		APKSHA256:   req.APKSHA256,
		APKSize:     req.APKSize,
		APKName:     req.APKName,
		MinVersion:  req.MinVersion,
		Notes:       req.Notes,
	})
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "seq": seq, "manifest_json": manifestJSON})
}

func (s *server) handleAdminAPKPublish(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(160 << 20); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	manifestJSON := strings.TrimSpace(r.FormValue("manifest_json"))
	minisig := strings.TrimSpace(r.FormValue("manifest_minisig"))
	apkFile, apkHeader, err := r.FormFile("apk")
	if err != nil {
		writeError(w, "apk file is required", http.StatusBadRequest)
		return
	}
	defer apkFile.Close()
	serverSigned := false
	var manifest apkReleaseRecord
	if manifestJSON == "" && minisig == "" {
		priv, pubText, err := s.loadServerUpdateSigningKey()
		if err != nil {
			writeError(w, "server update signing key unavailable: "+err.Error(), http.StatusBadRequest)
			return
		}
		sha, size, err := hashMultipartFile(apkFile)
		if err != nil {
			writeStoreError(w, http.StatusBadRequest, err)
			return
		}
		version, versionErr := inspectAPKVersion(apkFile, size)
		if _, err := apkFile.Seek(0, io.SeekStart); err != nil {
			writeStoreError(w, http.StatusBadRequest, err)
			return
		}
		if parsed := parseFormInt64(r, "version_code"); parsed > 0 {
			version.VersionCode = parsed
		}
		if value := strings.TrimSpace(r.FormValue("version_name")); value != "" {
			version.VersionName = value
		}
		if versionErr != nil && (version.VersionCode <= 0 || strings.TrimSpace(version.VersionName) == "") {
			writeError(w, "could not read APK version; fill version_code and version_name manually: "+versionErr.Error(), http.StatusBadRequest)
			return
		}
		seq, err := s.store.nextAPKSeq()
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, err)
			return
		}
		manifestJSON, err = buildAPKManifest(apkManifestInput{
			Seq:         seq,
			VersionCode: version.VersionCode,
			VersionName: version.VersionName,
			APKSHA256:   sha,
			APKSize:     size,
			APKName:     firstNotBlank(r.FormValue("apk_name"), apkHeader.Filename),
			MinVersion:  parseFormInt64(r, "min_version"),
			Notes:       r.FormValue("notes"),
		})
		if err != nil {
			writeStoreError(w, http.StatusBadRequest, err)
			return
		}
		minisig = string(minisign.Sign(priv, []byte(manifestJSON)))
		if err := verifyManifestSignature(manifestJSON, minisig, pubText); err != nil {
			writeStoreError(w, http.StatusInternalServerError, err)
			return
		}
		serverSigned = true
	} else {
		if manifestJSON == "" || minisig == "" {
			writeError(w, "manifest_json and manifest_minisig are required for offline signing", http.StatusBadRequest)
			return
		}
		if err := verifyManifestSignature(manifestJSON, minisig, s.cfg.UpdatePublicKey); err != nil {
			writeStoreError(w, http.StatusBadRequest, err)
			return
		}
	}
	manifest, err = parseAPKManifest(manifestJSON)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	release, err := s.storeAPKRelease(manifest, manifestJSON, minisig, apkFile, apkHeader)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	log.Printf("published APK update seq=%d version=%s(%d) sha256=%s server_signed=%t", release.Seq, release.VersionName, release.VersionCode, release.APKSHA256, serverSigned)
	s.auditEvent(auditEntry{Event: "apk_publish", IP: clientIP(r), Result: "ok", Fields: map[string]string{
		"seq":           strconv.FormatInt(release.Seq, 10),
		"version_code":  strconv.FormatInt(release.VersionCode, 10),
		"apk_sha256":    release.APKSHA256,
		"server_signed": strconv.FormatBool(serverSigned),
	}})
	writeJSON(w, map[string]any{"ok": true, "release": release})
}

type apkManifestInput struct {
	Seq         int64
	VersionCode int64
	VersionName string
	APKSHA256   string
	APKSize     int64
	APKName     string
	MinVersion  int64
	Notes       string
}

func buildAPKManifest(in apkManifestInput) (string, error) {
	if in.Seq <= 0 {
		return "", errors.New("seq must be positive")
	}
	if in.VersionCode <= 0 {
		return "", errors.New("version_code must be positive")
	}
	if strings.TrimSpace(in.VersionName) == "" {
		return "", errors.New("version_name is required")
	}
	if len(strings.TrimSpace(in.APKSHA256)) != 64 {
		return "", errors.New("apk_sha256 must be 64 hex chars")
	}
	if in.APKSize <= 0 {
		return "", errors.New("apk_size must be positive")
	}
	apkName := safeAPKName(in.APKName, in.VersionCode)
	payload := map[string]any{
		"schema":       1,
		"ns":           "apk-update-v1",
		"seq":          in.Seq,
		"version_code": in.VersionCode,
		"version_name": strings.TrimSpace(in.VersionName),
		"apk_sha256":   strings.ToLower(strings.TrimSpace(in.APKSHA256)),
		"apk_size":     in.APKSize,
		"apk_name":     apkName,
		"apk_url":      apkName,
		"min_version":  in.MinVersion,
		"notes":        strings.TrimSpace(in.Notes),
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	}
	return canonicalJSON(payload)
}

func parseAPKManifest(raw string) (apkReleaseRecord, error) {
	var root struct {
		Schema      int    `json:"schema"`
		Namespace   string `json:"ns"`
		Seq         int64  `json:"seq"`
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		APKSHA256   string `json:"apk_sha256"`
		APKSize     int64  `json:"apk_size"`
		APKName     string `json:"apk_name"`
		APKURL      string `json:"apk_url"`
		MinVersion  int64  `json:"min_version"`
		Notes       string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return apkReleaseRecord{}, err
	}
	if root.Schema != 1 || root.Namespace != "apk-update-v1" {
		return apkReleaseRecord{}, errors.New("unsupported apk manifest")
	}
	name := safeAPKName(firstNotBlank(root.APKName, root.APKURL), root.VersionCode)
	if root.Seq <= 0 || root.VersionCode <= 0 || root.APKSize <= 0 || len(strings.TrimSpace(root.APKSHA256)) != 64 {
		return apkReleaseRecord{}, errors.New("invalid apk manifest fields")
	}
	return apkReleaseRecord{
		Seq:         root.Seq,
		VersionCode: root.VersionCode,
		VersionName: strings.TrimSpace(root.VersionName),
		MinVersion:  root.MinVersion,
		Notes:       strings.TrimSpace(root.Notes),
		APKName:     name,
		APKSHA256:   strings.ToLower(strings.TrimSpace(root.APKSHA256)),
		APKSize:     root.APKSize,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func verifyManifestSignature(manifestJSON, minisigText, publicKey string) error {
	if strings.TrimSpace(publicKey) == "" {
		return errors.New("ORCH_UPDATE_PUBKEY is not configured")
	}
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(strings.TrimSpace(publicKey))); err != nil {
		return fmt.Errorf("invalid update public key: %w", err)
	}
	if !minisign.Verify(pub, []byte(manifestJSON), []byte(strings.TrimSpace(minisigText))) {
		return errors.New("update manifest signature invalid")
	}
	return nil
}

func (s *server) serverUpdateSigningAvailable() bool {
	_, _, err := s.loadServerUpdateSigningKey()
	return err == nil
}

// loadServerUpdateSigningKey returns the server-held update key. It is used
// for every discovery build and client bundle, so the parsed key is cached and
// only reloaded when update.key's size or mtime changes.
func (s *server) loadServerUpdateSigningKey() (minisign.PrivateKey, string, error) {
	path := filepath.Join(s.cfg.StateDir, "update.key")
	info, statErr := os.Stat(path)
	if statErr == nil {
		s.updateKeyMu.Lock()
		c := s.updateKeyCache
		s.updateKeyMu.Unlock()
		if c != nil && c.size == info.Size() && c.modTime.Equal(info.ModTime()) {
			return c.priv, c.pub, nil
		}
	}
	priv, pub, err := s.readServerUpdateSigningKey(path)
	if err == nil && statErr == nil {
		s.updateKeyMu.Lock()
		s.updateKeyCache = &updateKeyCacheEntry{priv: priv, pub: pub, size: info.Size(), modTime: info.ModTime()}
		s.updateKeyMu.Unlock()
	}
	return priv, pub, err
}

type updateKeyCacheEntry struct {
	priv    minisign.PrivateKey
	pub     string
	size    int64
	modTime time.Time
}

func (s *server) readServerUpdateSigningKey(path string) (minisign.PrivateKey, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return minisign.PrivateKey{}, "", errors.New("update.key is not present")
		}
		return minisign.PrivateKey{}, "", err
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(raw); err != nil {
		return minisign.PrivateKey{}, "", fmt.Errorf("invalid update key: %w", err)
	}
	pubText, err := updatePublicKeyText(priv)
	if err != nil {
		return minisign.PrivateKey{}, "", err
	}
	if configured := strings.TrimSpace(s.cfg.UpdatePublicKey); configured != "" && configured != strings.TrimSpace(pubText) {
		return minisign.PrivateKey{}, "", errors.New("update.key does not match ORCH_UPDATE_PUBKEY")
	}
	return priv, strings.TrimSpace(pubText), nil
}

func hashMultipartFile(file multipart.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func parseFormInt64(r *http.Request, key string) int64 {
	value := strings.TrimSpace(r.FormValue(key))
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

// storeAPKRelease publishes one release. Publishes are serialized, the seq is
// checked against the current release before anything touches disk, and files
// are staged in a private directory that is renamed into place, so a racing or
// stale publish can never overwrite the manifest of the live release.
func (s *server) storeAPKRelease(manifest apkReleaseRecord, manifestJSON, minisig string, apk multipart.File, _ *multipart.FileHeader) (apkReleaseRecord, error) {
	s.apkPublishMu.Lock()
	defer s.apkPublishMu.Unlock()
	if current, ok, err := s.store.currentAPKRelease(); err != nil {
		return apkReleaseRecord{}, err
	} else if ok && manifest.Seq <= current.Seq {
		return apkReleaseRecord{}, fmt.Errorf("apk release rollback: seq=%d current=%d", manifest.Seq, current.Seq)
	}
	releasesDir := filepath.Join(s.cfg.StateDir, "apk", "releases")
	if err := os.MkdirAll(releasesDir, 0o700); err != nil {
		return apkReleaseRecord{}, err
	}
	stagingDir, err := os.MkdirTemp(releasesDir, ".staging-")
	if err != nil {
		return apkReleaseRecord{}, err
	}
	defer os.RemoveAll(stagingDir)
	out, err := os.OpenFile(filepath.Join(stagingDir, manifest.APKName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return apkReleaseRecord{}, err
	}
	digest := sha256.New()
	size, copyErr := io.Copy(out, io.TeeReader(apk, digest))
	syncErr := out.Sync()
	closeErr := out.Close()
	for _, err := range []error{copyErr, syncErr, closeErr} {
		if err != nil {
			return apkReleaseRecord{}, err
		}
	}
	actualSHA := hex.EncodeToString(digest.Sum(nil))
	if size != manifest.APKSize || !actualSHAEquals(actualSHA, manifest.APKSHA256) {
		return apkReleaseRecord{}, fmt.Errorf("apk mismatch sha=%s size=%d", actualSHA, size)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "update-manifest.json"), []byte(strings.TrimSpace(manifestJSON)), 0o600); err != nil {
		return apkReleaseRecord{}, err
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "update-manifest.json.minisig"), []byte(strings.TrimSpace(minisig)), 0o600); err != nil {
		return apkReleaseRecord{}, err
	}
	releaseDir := filepath.Join(releasesDir, fmt.Sprintf("%d", manifest.Seq))
	// A directory for this seq can only be a leftover of a failed publish:
	// the seq is newer than the live release, so nothing references it.
	if err := os.RemoveAll(releaseDir); err != nil {
		return apkReleaseRecord{}, err
	}
	if err := os.Rename(stagingDir, releaseDir); err != nil {
		return apkReleaseRecord{}, err
	}
	manifest.APKPath = filepath.Join(releaseDir, manifest.APKName)
	manifest.ManifestPath = filepath.Join(releaseDir, "update-manifest.json")
	manifest.MinisigPath = filepath.Join(releaseDir, "update-manifest.json.minisig")
	if err := s.store.setAPKRelease(manifest); err != nil {
		_ = os.RemoveAll(releaseDir)
		return apkReleaseRecord{}, err
	}
	if err := s.pruneOldAPKReleases(s.cfg.APKKeepReleases, manifest.Seq); err != nil {
		log.Printf("apk release prune failed: %v", err)
	}
	return manifest, nil
}

const (
	// maxConcurrentAPKShipments bounds pulls that carry the APK at once: each
	// one is JSON-encoded, encrypted and base64-encoded again (several times
	// the APK size in memory), and a release sends every worker to pull.
	maxConcurrentAPKShipments = 2
)

// apkShipmentWait is how long a pull waits for a free APK shipment slot (a
// var so tests can shorten it).
var apkShipmentWait = 30 * time.Second

// updateArtifactForPull returns the APK update only when the worker has not
// yet acknowledged the current release (or reports no applied state), so
// config-only bumps do not re-ship the whole APK. The returned release func
// must run after the response is written. When all shipment slots stay busy
// the pull goes out without the APK; since it is not marked sent, the next
// pull ships it.
func (s *server) updateArtifactForPull(worker workerRecord, haveSeq int64) (*updateArtifact, func(), error) {
	rel, ok, err := s.store.currentAPKRelease()
	if err != nil || !ok {
		return nil, nil, err
	}
	if haveSeq > 0 && worker.APKAppliedSeq == rel.Seq {
		return nil, nil, nil
	}
	release, acquired := s.acquireAPKShipment(apkShipmentWait)
	if !acquired {
		// The worker would otherwise stay on the old APK until an unrelated
		// seq bump: bump its own seq so its next nudge pulls again.
		log.Printf("apk shipment slots busy; worker %s will retry the update", worker.ID)
		if err := s.store.updateWorker(worker.ID, func(rec *workerRecord) error {
			if rec.DesiredSeq <= worker.DesiredSeq {
				rec.DesiredSeq = worker.DesiredSeq + 1
			}
			return nil
		}); err != nil {
			return nil, nil, err
		}
		return nil, nil, nil
	}
	update, err := s.cachedUpdateArtifact(rel)
	if err != nil {
		release()
		return nil, nil, err
	}
	if err := s.store.markWorkerAPKSent(worker.ID, rel.Seq, worker.DesiredSeq); err != nil {
		release()
		return nil, nil, err
	}
	return update, release, nil
}

func (s *server) acquireAPKShipment(wait time.Duration) (func(), bool) {
	s.apkShipOnce.Do(func() { s.apkShipSem = make(chan struct{}, maxConcurrentAPKShipments) })
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case s.apkShipSem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.apkShipSem }) }, true
	case <-timer.C:
		return nil, false
	}
}

// cachedUpdateArtifact reads and base64-encodes a release once; the artifact
// is shared read-only by all pulls of that release.
func (s *server) cachedUpdateArtifact(rel apkReleaseRecord) (*updateArtifact, error) {
	s.apkArtifactMu.Lock()
	defer s.apkArtifactMu.Unlock()
	if s.apkArtifact != nil && s.apkArtifactSeq == rel.Seq {
		return s.apkArtifact, nil
	}
	update, err := readUpdateArtifact(rel)
	if err != nil {
		return nil, err
	}
	s.apkArtifact, s.apkArtifactSeq = update, rel.Seq
	return update, nil
}

func readUpdateArtifact(rec apkReleaseRecord) (*updateArtifact, error) {
	manifestJSON, err := os.ReadFile(rec.ManifestPath)
	if err != nil {
		return nil, err
	}
	minisig, err := os.ReadFile(rec.MinisigPath)
	if err != nil {
		return nil, err
	}
	apk, err := os.ReadFile(rec.APKPath)
	if err != nil {
		return nil, err
	}
	return &updateArtifact{
		ManifestJSON:    strings.TrimSpace(string(manifestJSON)),
		ManifestMinisig: strings.TrimSpace(string(minisig)),
		APKName:         rec.APKName,
		APKSHA256:       rec.APKSHA256,
		APKBase64:       base64.StdEncoding.EncodeToString(apk),
	}, nil
}

func loadOrCreateUpdateSigningKey(cfg *orchConfig) (minisign.PrivateKey, error) {
	keyPath := filepath.Join(cfg.StateDir, "update.key")
	pubPath := filepath.Join(cfg.StateDir, "update.pub")
	if raw, err := os.ReadFile(keyPath); err == nil {
		var priv minisign.PrivateKey
		if err := priv.UnmarshalText(raw); err != nil {
			return minisign.PrivateKey{}, fmt.Errorf("invalid update key: %w", err)
		}
		if strings.TrimSpace(cfg.UpdatePublicKey) == "" {
			pubText, err := updatePublicKeyText(priv)
			if err != nil {
				return minisign.PrivateKey{}, err
			}
			cfg.UpdatePublicKey = pubText
		}
		return priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return minisign.PrivateKey{}, err
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	privText, err := priv.MarshalText()
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	if err := os.WriteFile(keyPath, privText, 0o600); err != nil {
		return minisign.PrivateKey{}, err
	}
	if err := os.WriteFile(pubPath, pubText, 0o644); err != nil {
		return minisign.PrivateKey{}, err
	}
	if strings.TrimSpace(cfg.UpdatePublicKey) == "" {
		cfg.UpdatePublicKey = string(pubText)
	}
	log.Printf("generated update minisign key public_key=%s", strings.TrimSpace(string(pubText)))
	return priv, nil
}

func updatePublicKeyText(priv minisign.PrivateKey) (string, error) {
	pub, ok := priv.Public().(minisign.PublicKey)
	if !ok {
		return "", errors.New("unexpected update public key type")
	}
	raw, err := pub.MarshalText()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *server) seedUpdateAPKIfPresent(updatePrivate minisign.PrivateKey) error {
	path := strings.TrimSpace(s.cfg.SeedAPKPath)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("SEED_APK_PATH points to a directory: %s", path)
	}
	if _, ok, err := s.store.currentAPKRelease(); err != nil || ok {
		return err
	}
	localPub, err := updatePublicKeyText(updatePrivate)
	if err != nil {
		return err
	}
	if strings.TrimSpace(s.cfg.UpdatePublicKey) != strings.TrimSpace(localPub) {
		return errors.New("seed apk requires ORCH_UPDATE_PUBKEY to match the local update key, or ORCH_UPDATE_PUBKEY must be empty")
	}
	sha, size, err := fileSHA256AndSize(path)
	if err != nil {
		return err
	}
	manifestJSON, err := buildAPKManifest(apkManifestInput{
		Seq:         1,
		VersionCode: s.cfg.SeedVersionCode,
		VersionName: s.cfg.SeedVersionName,
		APKSHA256:   sha,
		APKSize:     size,
		APKName:     filepath.Base(path),
		Notes:       "seed-on-first-run",
	})
	if err != nil {
		return err
	}
	minisigText := string(minisign.Sign(updatePrivate, []byte(manifestJSON)))
	manifest, err := parseAPKManifest(manifestJSON)
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := s.storeAPKRelease(manifest, manifestJSON, minisigText, file, nil); err != nil {
		return err
	}
	log.Printf("seeded APK update artifact seq=1 apk=%s sha256=%s", filepath.Base(path), sha)
	return nil
}

func fileSHA256AndSize(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func optionalAPKRelease(rec apkReleaseRecord, ok bool) any {
	if !ok {
		return nil
	}
	return rec
}

func mustNextAPKSeq(st *orchStore) int64 {
	seq, err := st.nextAPKSeq()
	if err != nil {
		return 0
	}
	return seq
}

func safeAPKName(value string, versionCode int64) string {
	name := filepath.Base(strings.TrimSpace(value))
	if name == "." || name == "/" || name == "" {
		name = fmt.Sprintf("app-public-%d.apk", versionCode)
	}
	if !strings.HasSuffix(strings.ToLower(name), ".apk") {
		name += ".apk"
	}
	return name
}

func actualSHAEquals(actual, expected string) bool {
	return strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected))
}
