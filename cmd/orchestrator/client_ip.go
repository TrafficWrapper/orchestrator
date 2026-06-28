package main

import (
	"net"
	"net/http"
	"strings"
)

func clientIP(r *http.Request) string {
	host := remoteIP(r.RemoteAddr)
	if trustedProxyHost(host) {
		if realIP := validIPString(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
		// Assumes a single trusted co-located proxy hop. Appending proxies add
		// the peer they observed at the right edge of X-Forwarded-For.
		if forwarded := rightmostForwardedIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
	}
	return host
}

func trustedProxyHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func rightmostForwardedIP(value string) string {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if ip := validIPString(part); ip != "" {
			return ip
		}
	}
	return ""
}

func validIPString(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	return ip.String()
}
