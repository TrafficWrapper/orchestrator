package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	limiter := s.adminLoginLimiter()
	var req struct {
		Secret   string `json:"secret"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
		return
	}
	ok, mustChange, err := s.store.verifyAdminPassword(req.Secret)
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: map[string]string{"reason": "verify_error"}})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !ok {
		fields := map[string]string{"reason": "bad_secret"}
		if attempt.LockedAfterAttempt {
			fields["locked_until"] = attempt.LockedUntil.UTC().Format(time.RFC3339)
			w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
			s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "locked", Fields: fields})
			http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
			return
		}
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: fields})
		http.Error(w, "invalid admin secret", http.StatusForbidden)
		return
	}
	if enabled, totpOK, err := s.store.verifyAdminTOTP(req.TOTPCode, time.Now().UTC()); err != nil {
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: map[string]string{"reason": "totp_error"}})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	} else if enabled && !totpOK {
		fields := map[string]string{"reason": "bad_totp"}
		if attempt.LockedAfterAttempt {
			fields["locked_until"] = attempt.LockedUntil.UTC().Format(time.RFC3339)
			w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
			s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "locked", Fields: fields})
			http.Error(w, "too many failed login attempts", http.StatusTooManyRequests)
			return
		}
		s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "failed", Fields: fields})
		http.Error(w, "invalid totp code", http.StatusForbidden)
		return
	}
	limiter.recordSuccess(ip)
	s.auditEvent(auditEntry{Event: "admin_login", IP: ip, Result: "ok"})
	if mustChange {
		s.createAdminSession(w, r, true)
		return
	}
	if approver := s.currentAuthApprover(); approver != nil && approver.enabled() {
		approved, err := approver.requestLoginApproval(r.Context(), loginApprovalRequest{
			RemoteAddr: ip,
			UserAgent:  r.UserAgent(),
			CreatedAt:  time.Now().UTC(),
		})
		if err != nil {
			s.auditEvent(auditEntry{Event: "admin_login_approval", IP: ip, Result: "failed", Fields: map[string]string{"reason": "approval_error"}})
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !approved {
			s.auditEvent(auditEntry{Event: "admin_login_approval", IP: ip, Result: "denied"})
			http.Error(w, "admin login approval denied", http.StatusForbidden)
			return
		}
	}
	s.createAdminSession(w, r, false)
}

func (s *server) createAdminSession(w http.ResponseWriter, r *http.Request, mustChange bool) {
	token := randID() + randID() + randID()
	csrf := randID() + randID()
	expires := time.Now().UTC().Add(12 * time.Hour)
	s.adminSessions.Store(token, adminSession{Token: token, CSRFToken: csrf, ExpiresAt: expires, MustChange: mustChange})
	http.SetCookie(w, &http.Cookie{
		Name:     "tw_admin_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLS || r.TLS != nil,
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, source, session, ok := s.lookupAdminSession(r)
	if ok && source == "cookie" && !csrfTokenMatches(session.CSRFToken, r.Header.Get("x-csrf-token")) {
		http.Error(w, "csrf token required", http.StatusForbidden)
		return
	}
	if token != "" {
		s.adminSessions.Delete(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "tw_admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLS || r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	if ok {
		s.auditEvent(auditEntry{Event: "admin_logout", IP: clientIP(r), Result: "ok"})
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.enableAdminTOTP(req.Code, time.Now().UTC()); err != nil {
		s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "failed"})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.auditEvent(auditEntry{Event: "admin_totp_enable", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Turning 2FA off must prove possession of the second factor, otherwise a
	// stolen session could strip it with a single request.
	if enabled, ok, err := s.store.verifyAdminTOTP(req.Code, time.Now().UTC()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if enabled && !ok {
		s.auditEvent(auditEntry{Event: "admin_totp_disable", IP: clientIP(r), Result: "failed", Fields: map[string]string{"reason": "bad_totp"}})
		http.Error(w, "valid totp code required", http.StatusForbidden)
		return
	}
	if err := s.store.disableAdminTOTP(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		if cookie, err := r.Cookie("tw_admin_session"); err == nil {
			token = cookie.Value
			source = "cookie"
		}
	}
	if token == "" {
		return "", "", adminSession{}, false
	}
	value, ok := s.adminSessions.Load(token)
	if !ok {
		return token, source, adminSession{}, false
	}
	session := value.(adminSession)
	if time.Now().UTC().After(session.ExpiresAt) {
		s.adminSessions.Delete(token)
		return token, source, adminSession{}, false
	}
	return token, source, session, true
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	token, source, session, ok := s.lookupAdminSession(r)
	if token == "" {
		http.Error(w, "admin session required", http.StatusUnauthorized)
		return false
	}
	if !ok {
		http.Error(w, "admin session invalid", http.StatusForbidden)
		return false
	}
	if session.MustChange {
		http.Error(w, "password change required", http.StatusForbidden)
		return false
	}
	if source == "cookie" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !csrfTokenMatches(session.CSRFToken, r.Header.Get("x-csrf-token")) {
			http.Error(w, "csrf token required", http.StatusForbidden)
			return false
		}
	}
	return true
}

func (s *server) handleAdminPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	token, source, session, ok := s.lookupAdminSession(r)
	if token == "" {
		http.Error(w, "admin session required", http.StatusUnauthorized)
		return
	}
	if !ok {
		http.Error(w, "admin session invalid", http.StatusForbidden)
		return
	}
	if source == "cookie" && !csrfTokenMatches(session.CSRFToken, r.Header.Get("x-csrf-token")) {
		http.Error(w, "csrf token required", http.StatusForbidden)
		return
	}
	var req struct {
		CurrentSecret string `json:"current_secret"`
		NewSecret     string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	okPassword, _, err := s.store.verifyAdminPassword(req.CurrentSecret)
	if err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "verify_error"}})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !okPassword {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "bad_current_secret"}})
		http.Error(w, "invalid current admin secret", http.StatusForbidden)
		return
	}
	if err := s.store.setAdminPassword(req.NewSecret); err != nil {
		s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "failed", Fields: map[string]string{"reason": "set_failed"}})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("admin password changed at=%s remote=%s", time.Now().UTC().Format(time.RFC3339), r.RemoteAddr)
	s.auditEvent(auditEntry{Event: "admin_password_change", IP: ip, Result: "ok"})
	s.revokeAdminSessions()
	if approver := s.currentAuthApprover(); approver != nil && approver.enabled() {
		approved, err := approver.requestLoginApproval(r.Context(), loginApprovalRequest{
			RemoteAddr: ip,
			UserAgent:  r.UserAgent(),
			CreatedAt:  time.Now().UTC(),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !approved {
			http.Error(w, "admin login approval denied", http.StatusForbidden)
			return
		}
	}
	s.createAdminSession(w, r, false)
}

func csrfTokenMatches(expected, provided string) bool {
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	return expected != "" && subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

func (s *server) handleAdminPasswordForceSet(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NewSecret string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.setAdminPassword(req.NewSecret); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.revokeAdminSessions()
	s.auditEvent(auditEntry{Event: "admin_password_force_set", IP: clientIP(r), Result: "ok"})
	writeJSON(w, map[string]any{"ok": true, "status": "admin_password_set"})
}
