package main

import (
	"net"
	"net/http"
	"net/netip"
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

func rateLimitKey(value string) string {
	value = strings.TrimSpace(value)
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	if addr.Is4() {
		return addr.String()
	}
	if addr.Is4In6() {
		return addr.Unmap().String()
	}
	raw := addr.As16()
	for i := 8; i < len(raw); i++ {
		raw[i] = 0
	}
	return netip.AddrFrom16(raw).String() + "/64"
}
