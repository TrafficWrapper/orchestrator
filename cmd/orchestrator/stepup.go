package main

import (
	"errors"
	"net/http"
	"time"
)

// stepUpProof is what a sensitive admin action must carry beyond the
// session: the current admin secret and, when 2FA is on, a TOTP code.
type stepUpProof struct {
	CurrentSecret string `json:"current_secret"`
	TOTPCode      string `json:"totp_code,omitempty"`
}

// stepUp re-authenticates the operator for a sensitive action: current
// secret, TOTP when enabled, and owner approval through the bot when it is
// configured. Failures count against the login limiter. It writes the error
// response and returns false when the action must not proceed.
func (s *server) stepUp(w http.ResponseWriter, r *http.Request, event, action string, proof stepUpProof) bool {
	ip := clientIP(r)
	limiter := s.adminLoginLimiter()
	attempt := limiter.reserveAttempt(ip)
	if !attempt.Allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(attempt.LockedUntil, limiter.clock()))
		s.auditEvent(auditEntry{Event: event, IP: ip, Result: "locked"})
		writeError(w, "too many failed login attempts", http.StatusTooManyRequests)
		return false
	}
	ok, _, err := s.store.verifyAdminPassword(proof.CurrentSecret)
	if err == nil && ok {
		var enabled, totpOK bool
		enabled, totpOK, err = s.store.verifyAdminTOTP(proof.TOTPCode, time.Now().UTC())
		ok = !enabled || totpOK
	}
	if err != nil || !ok {
		s.auditEvent(auditEntry{Event: event, IP: ip, Result: "failed", Fields: map[string]string{"reason": "step_up"}})
		writeError(w, "re-authentication required: current_secret (and totp_code) invalid", http.StatusForbidden)
		return false
	}
	if approved, err := s.ownerApproval(r, action); err != nil || !approved {
		limiter.chargeFailure(ip)
		s.auditEvent(auditEntry{Event: event, IP: ip, Result: "denied"})
		writeError(w, "owner approval denied", http.StatusForbidden)
		return false
	}
	limiter.recordSuccess(ip)
	return true
}

// ownerApproval asks the owner through the bot when one is configured. It
// fails closed: with bot settings stored but no approver running (restart
// in progress, settings unreadable) the action is refused rather than let
// through unapproved (ORC-I3). action "" is a login.
func (s *server) ownerApproval(r *http.Request, action string) (bool, error) {
	if approver := s.currentAuthApprover(); approver != nil && approver.enabled() {
		return approver.requestLoginApproval(r.Context(), loginApprovalRequest{
			Action:     action,
			RemoteAddr: clientIP(r),
			UserAgent:  r.UserAgent(),
			CreatedAt:  time.Now().UTC(),
		})
	}
	_, configured, err := s.store.botSettings()
	if err != nil {
		return false, err
	}
	if configured && s.hasBotFactory() {
		return false, errors.New("owner approval temporarily unavailable; retry")
	}
	return true, nil
}
