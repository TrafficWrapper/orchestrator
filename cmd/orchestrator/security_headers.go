package main

import "net/http"

// baseContentSecurityPolicy covers every response that is not an admin page
// (JSON, text, downloads): nothing may load from them (ORC-L15).
const baseContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// webContentSecurityPolicy is the admin page policy: only the page's own
// script carrying nonce runs. Inline style attributes stay allowed; they
// cannot execute code.
func webContentSecurityPolicy(nonce string) string {
	return "default-src 'self'; script-src 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
}

// withSecurityHeaders sets response headers that stop the admin UI from being
// framed (clickjacking against its one-click actions), MIME sniffing, and
// leaking URLs through Referer. No response is cacheable: admin, login,
// token and enrollment answers carry secrets, and the discovery feed sets
// no-store itself (ORC-L15).
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", baseContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
