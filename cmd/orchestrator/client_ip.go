package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

// Client IP header modes (ORCH_CLIENT_IP_HEADER). Only a header the local
// proxy always overwrites is safe to trust: with "auto", a proxy that sets just
// X-Forwarded-For lets clients forge X-Real-IP, and vice versa.
const (
	clientIPHeaderAuto         = "auto"
	clientIPHeaderRealIP       = "x-real-ip"
	clientIPHeaderForwardedFor = "x-forwarded-for"
	clientIPHeaderNone         = "none"
)

var (
	clientIPHeaderMode     atomic.Value // string
	clientIPAutoWarnedOnce sync.Once
)

func setClientIPHeaderMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "":
		mode = clientIPHeaderAuto
	case clientIPHeaderAuto, clientIPHeaderRealIP, clientIPHeaderForwardedFor, clientIPHeaderNone:
	default:
		return fmt.Errorf("ORCH_CLIENT_IP_HEADER must be one of auto, x-real-ip, x-forwarded-for, none; got %q", mode)
	}
	clientIPHeaderMode.Store(mode)
	return nil
}

func currentClientIPHeaderMode() string {
	if mode, ok := clientIPHeaderMode.Load().(string); ok && mode != "" {
		return mode
	}
	return clientIPHeaderAuto
}

func clientIP(r *http.Request) string {
	host := remoteIP(r.RemoteAddr)
	if !trustedProxyHost(host) {
		return host
	}
	realIP := validIPString(r.Header.Get("X-Real-IP"))
	// Assumes a single trusted co-located proxy hop. Appending proxies add
	// the peer they observed at the right edge of X-Forwarded-For.
	forwarded := rightmostForwardedIP(r.Header.Get("X-Forwarded-For"))
	switch currentClientIPHeaderMode() {
	case clientIPHeaderNone:
		return host
	case clientIPHeaderRealIP:
		if realIP != "" {
			return realIP
		}
		return host
	case clientIPHeaderForwardedFor:
		if forwarded != "" {
			return forwarded
		}
		return host
	}
	// auto trusts no header: a proxy that forwards one client-set header
	// while overwriting the other would let clients pick their address
	// (ORC-L12). Name the header the proxy overwrites explicitly.
	if realIP != "" || forwarded != "" {
		clientIPAutoWarnedOnce.Do(func() {
			log.Printf("client ip: ignoring X-Real-IP/X-Forwarded-For from a loopback proxy in auto mode; set ORCH_CLIENT_IP_HEADER=x-real-ip or x-forwarded-for to the header your proxy overwrites")
		})
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
