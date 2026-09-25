package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type adminSession struct {
	Token      string
	CSRFToken  string
	ExpiresAt  time.Time
	MustChange bool
}

func (s *server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A cross-site "simple" POST could otherwise burn the owner's login
	// budget from any web page (ORC-L18).
	if !loginRequestSameSite(r) {
		writeError(w, "login requires a same-site JSON request", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	limiter := s.adminLoginLimiter()
	var req struct {
		Secret   string `json:"secret"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	attempt := limiter.reserveAttempt(ip)
	if !attempt.Allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
		s.auditEvent(auditEntry{
			Event:  "admin_login",
			IP:     ip,
			Result: "locked",
			Fields: map[string]string{"locked_until": attempt.LockedUntil.UTC().Format(time.RFC3339)},
		})
		writeError(w, "too many failed login attempts", http.StatusTooManyRequests)
		return
	}
	ok, mustChange, err := s.store.verifyAdminPassword(req.Secret)
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: map[string]string{"reason": "verify_error"}})
		writeStoreError(w, http.StatusForbidden, err)
		return
	}
	if !ok {
		fields := map[string]string{"reason": "bad_secret"}
		if attempt.LockedAfterAttempt {
			fields["locked_until"] = attempt.LockedUntil.UTC().Format(time.RFC3339)
			w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
			s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "locked", Fields: fields})
			writeError(w, "too many failed login attempts", http.StatusTooManyRequests)
			return
		}
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: fields})
		writeError(w, "invalid credentials", http.StatusForbidden)
		return
	}
	if enabled, totpOK, err := s.store.verifyAdminTOTP(req.TOTPCode, time.Now().UTC()); err != nil {
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: map[string]string{"reason": "totp_error"}})
		writeStoreError(w, http.StatusForbidden, err)
		return
	} else if enabled && !totpOK {
		fields := map[string]string{"reason": "bad_totp"}
		if attempt.LockedAfterAttempt {
			fields["locked_until"] = attempt.LockedUntil.UTC().Format(time.RFC3339)
			w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
			s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "locked", Fields: fields})
			writeError(w, "too many failed login attempts", http.StatusTooManyRequests)
			return
		}
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: fields})
		writeError(w, "invalid credentials", http.StatusForbidden)
		return
	}
	if mustChange {
		limiter.recordSuccess(ip)
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "ok", Fields: map[string]string{"must_change": "true"}})
		s.createAdminSession(w, r, true)
		return
	}
	// Credentials are right; the login only counts as a success once the
	// owner approves, and denials or timeouts count as failures (ORC-L4).
	approved, err := s.ownerApproval(r, "")
	if err != nil {
		limiter.chargeFailure(ip)
		s.auditEvent(auditEntry{Event: "admin_login_approval", IP: ip, Result: "failed", Fields: map[string]string{"reason": "approval_error"}})
		writeStoreError(w, http.StatusForbidden, err)
		return
	}
	if !approved {
		limiter.chargeFailure(ip)
		s.auditEvent(auditEntry{Event: "admin_login_approval", IP: ip, Result: "denied"})
		writeError(w, "admin login approval denied", http.StatusForbidden)
		return
	}
	limiter.recordSuccess(ip)
	s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "ok"})
	s.createAdminSession(w, r, false)
}

func (s *server) createAdminSession(w http.ResponseWriter, r *http.Request, mustChange bool) {
	token := randID() + randID() + randID()
	csrf := randID() + randID()
	expires := time.Now().UTC().Add(12 * time.Hour)
	s.adminSessions.Store(token, adminSession{Token: token, CSRFToken: csrf, ExpiresAt: expires, MustChange: mustChange})
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	writeJSON(w, map[string]any{
		"ok":            true,
		"session_token": token,
		"csrf_token":    csrf,
		"expires_at":    expires.Format(time.RFC3339),
		"must_change":   mustChange,
	})
}

// revokeAdminSessions ends every admin session, e.g. after a password change,
// so a stolen session cannot outlive the credential it was issued for.
func (s *server) revokeAdminSessions() {
	s.adminSessions.Range(func(key, _ any) bool {
		s.adminSessions.Delete(key)
		return true
	})
}

func (s *server) pruneExpiredAdminSessions(now time.Time) {
	s.adminSessions.Range(func(key, value any) bool {
		if session, ok := value.(adminSession); !ok || now.After(session.ExpiresAt) {
			s.adminSessions.Delete(key)
		}
		return true
	})
}

func (s *server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, source, session, ok := s.lookupAdminSession(r)
	if ok && source == "cookie" && !csrfTokenMatches(session.CSRFToken, r.Header.Get("x-csrf-token")) {
		writeError(w, "csrf token required", http.StatusForbidden)
		return
	}
	if token != "" {
		s.adminSessions.Delete(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	if ok {
		s.auditEvent(auditEntry{Event: "admin_logout", IP: clientIP(r), Result: "ok"})
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditEvent(auditEntry{Event: "admin_totp_enroll", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{
		"ok":          true,
		"secret":      rec.Secret,
		"otpauth_url": totpProvisioningURL(rec.Secret),
	})
}

func (s *server) handleAdminTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
		// CurrentCode proves possession of the factor being replaced; it
		// is required when 2FA is already on (ORC-M4).
		CurrentCode string `json:"current_code,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	enabled, currentOK, err := s.store.verifyAdminTOTP(req.CurrentCode, time.Now().UTC())
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	if enabled && !currentOK {
		s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "failed", Fields: map[string]string{"reason": "bad_current_totp"}})
		writeError(w, "a valid code of the current authenticator (current_code) is required", http.StatusForbidden)
		return
	}
	if err := s.store.enableAdminTOTP(req.Code, time.Now().UTC()); err != nil {
		s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "failed"})
		writeStoreError(w, http.StatusForbidden, err)
		return
	}
	s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "ok"})
	if enabled {
		// The second factor changed: end every other session, like a
		// password change, and keep the caller logged in.
		s.revokeAdminSessions()
		s.createAdminSession(w, r, false)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	// Turning 2FA off must prove possession of the second factor, otherwise a
	// stolen session could strip it with a single request.
	if enabled, ok, err := s.store.verifyAdminTOTP(req.Code, time.Now().UTC()); err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	} else if enabled && !ok {
		s.auditEvent(auditEntry{Event: "admin_totp_disable", IP: clientIP(r), Result: "failed", Fields: map[string]string{"reason": "bad_totp"}})
		writeError(w, "valid totp code required", http.StatusForbidden)
		return
	}
	if err := s.store.disableAdminTOTP(); err != nil {
		writeStoreError(w, http.StatusInternalServerError, err)
		return
	}
	s.revokeAdminSessions()
	s.auditEvent(auditEntry{Event: "admin_totp_disable", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) lookupAdminSession(r *http.Request) (string, string, adminSession, bool) {
	token := ""
	source := ""
	auth := r.Header.Get("authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[len("bearer "):])
		source = "bearer"
	}
	if token == "" {
		if cookie, err := r.Cookie(adminSessionCookie); err == nil {
			token = cookie.Value
			source = "cookie"
		}
	}
	if token == "" {
		return "", "", adminSession{}, false
	}
	session, ok := s.sessionByToken(token)
	return token, source, session, ok
}

// adminSessionCookie names the admin session cookie (web UI and API).
const adminSessionCookie = "tw_admin_session"

// sessionByToken returns the live session for token, dropping it if expired.
func (s *server) sessionByToken(token string) (adminSession, bool) {
	if strings.TrimSpace(token) == "" {
		return adminSession{}, false
	}
	value, ok := s.adminSessions.Load(token)
	if !ok {
		return adminSession{}, false
	}
	session := value.(adminSession)
	if time.Now().UTC().After(session.ExpiresAt) {
		s.adminSessions.Delete(token)
		return adminSession{}, false
	}
	return session, true
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	token, source, session, ok := s.lookupAdminSession(r)
	if token == "" {
		writeError(w, "admin session required", http.StatusUnauthorized)
		return false
	}
	if !ok {
		writeError(w, "admin session invalid", http.StatusForbidden)
		return false
	}
	if session.MustChange {
		writeError(w, "password change required", http.StatusForbidden)
		return false
	}
	if source == "cookie" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !csrfTokenMatches(session.CSRFToken, r.Header.Get("x-csrf-token")) {
			writeError(w, "csrf token required", http.StatusForbidden)
			return false
		}
	}
	return true
}

func (s *server) handleAdminPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	token, source, session, ok := s.lookupAdminSession(r)
	if token == "" {
		writeError(w, "admin session required", http.StatusUnauthorized)
		return
	}
	if !ok {
		writeError(w, "admin session invalid", http.StatusForbidden)
		return
	}
	if source == "cookie" && !csrfTokenMatches(session.CSRFToken, r.Header.Get("x-csrf-token")) {
		writeError(w, "csrf token required", http.StatusForbidden)
		return
	}
	var req struct {
		CurrentSecret string `json:"current_secret"`
		NewSecret     string `json:"new_secret"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	okPassword, _, err := s.store.verifyAdminPassword(req.CurrentSecret)
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "verify_error"}})
		writeStoreError(w, http.StatusForbidden, err)
		return
	}
	if !okPassword {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "bad_current_secret"}})
		writeError(w, "invalid current admin secret", http.StatusForbidden)
		return
	}
	if err := validateAdminPassword(req.NewSecret); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Ask for the out-of-band approval before touching the credential: a denial
	// must leave the old password and sessions intact, not lock the owner out.
	// The owner sees what is being approved (ORC-L4).
	approved, err := s.ownerApproval(r, "change the admin password")
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "approval_error"}})
		writeStoreError(w, http.StatusForbidden, err)
		return
	}
	if !approved {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "denied"})
		writeError(w, "admin login approval denied", http.StatusForbidden)
		return
	}
	if err := s.store.setAdminPassword(req.NewSecret); err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "set_failed"}})
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	log.Printf("admin password changed at=%s remote=%s", time.Now().UTC().Format(time.RFC3339), r.RemoteAddr)
	s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "ok"})
	s.revokeAdminSessions()
	s.createAdminSession(w, r, false)
}

func csrfTokenMatches(expected, provided string) bool {
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	return expected != "" && subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

// handleAdminPasswordForceSet sets the password with the same proof as a
// change (current secret, TOTP, owner approval): a stolen session alone must
// not take the account over (ORC-M3). With the orchestrator stopped, the CLI
// sets it directly in the database.
func (s *server) handleAdminPasswordForceSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewSecret string `json:"new_secret"`
		stepUpProof
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validateAdminPassword(req.NewSecret); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.stepUp(w, r, "admin_password_force_set", "set a new admin password", req.stepUpProof) {
		return
	}
	if err := s.store.setAdminPassword(req.NewSecret); err != nil {
		writeStoreError(w, http.StatusBadRequest, err)
		return
	}
	s.revokeAdminSessions()
	s.auditEvent(auditEntry{Event: "admin_password_force_set", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{"ok": true, "status": "admin_password_set"})
}

// secureCookies reports whether the admin session cookie must be Secure:
// always when TLS terminates here or the public URL is https (TLS on a
// proxy in front, the recommended production setup; ORC-M10).
func (s *server) secureCookies(r *http.Request) bool {
	return s.cfg.TLS || r.TLS != nil || strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.cfg.PublicURL)), "https://")
}

// minAdminPasswordLength is enforced wherever a new admin password is set
// (ORC-L13).
const minAdminPasswordLength = 12

func validateAdminPassword(secret string) error {
	if len([]rune(strings.TrimSpace(secret))) < minAdminPasswordLength {
		return fmt.Errorf("admin password must be at least %d characters", minAdminPasswordLength)
	}
	return nil
}

// loginRequestSameSite accepts a login only as a JSON request that browsers
// do not send cross-site without CORS (and not flagged cross-site).
func loginRequestSameSite(r *http.Request) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" {
		return false
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "cross-site", "same-site":
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		if u, err := url.Parse(origin); err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}
