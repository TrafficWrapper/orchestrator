package main

import (
	"net"
	"net/http"
	"strings"
)

func clientIP(r *http.Request) string {
	host := remoteIP(r.RemoteAddr)
	if trustedProxyHost(host) {
		if forwarded := firstForwardedIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
		if realIP := validIPString(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return host
}

func trustedProxyHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func firstForwardedIP(value string) string {
	for _, part := range strings.Split(value, ",") {
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
