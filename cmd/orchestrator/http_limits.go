package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultRequestBodyMaxBytes = 1 << 20
	noiseRequestBodyMaxBytes   = 2 << 20
	loginRequestBodyMaxBytes   = 64 << 10
	uploadRequestBodyMaxBytes  = 256 << 20

	bufferedBodyReadTimeout = 30 * time.Second
	uploadBodyReadTimeout   = 30 * time.Minute
)

type requestBodyPolicy struct {
	maxBytes    int64
	readTimeout time.Duration
	stream      bool
}

func requestBodyPolicyFor(path string) requestBodyPolicy {
	switch {
	case path == "/admin/v1/apk/inspect" || path == "/admin/v1/apk/publish":
		return requestBodyPolicy{maxBytes: uploadRequestBodyMaxBytes, readTimeout: uploadBodyReadTimeout, stream: true}
	case path == "/admin/v1/login" || path == "/login":
		return requestBodyPolicy{maxBytes: loginRequestBodyMaxBytes, readTimeout: bufferedBodyReadTimeout}
	case strings.HasPrefix(path, "/w/") || strings.HasPrefix(path, "/d/"):
		return requestBodyPolicy{maxBytes: noiseRequestBodyMaxBytes, readTimeout: bufferedBodyReadTimeout}
	default:
		return requestBodyPolicy{maxBytes: defaultRequestBodyMaxBytes, readTimeout: bufferedBodyReadTimeout}
	}
}

// withRequestBodyLimits caps request body size and the time a client may take
// to send it. Small bodies are read up front under a read deadline that is then
// cleared, so long-poll handlers are not cancelled by a lingering deadline (the
// reason http.Server.ReadTimeout stays disabled).
func withRequestBodyLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		policy := requestBodyPolicyFor(r.URL.Path)
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(policy.readTimeout))
		if r.ContentLength > policy.maxBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		body := http.MaxBytesReader(w, r.Body, policy.maxBytes)
		if policy.stream {
			r.Body = body
			next.ServeHTTP(w, r)
			return
		}
		// Buffering happens before any limiter or authentication, so bound
		// how many bodies are being read at once (ORC-L37).
		if !acquireBodySlot(r) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		raw, err := io.ReadAll(body)
		releaseBodySlot()
		_ = body.Close()
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		_ = rc.SetReadDeadline(time.Time{})
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
		next.ServeHTTP(w, r)
	})
}

// bufferedBodySlots bounds concurrent buffered body reads; a slow sender holds
// a slot for at most bufferedBodyReadTimeout.
var bufferedBodySlots = make(chan struct{}, 512)

const bodySlotWait = 5 * time.Second

func acquireBodySlot(r *http.Request) bool {
	select {
	case bufferedBodySlots <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(bodySlotWait)
	defer timer.Stop()
	select {
	case bufferedBodySlots <- struct{}{}:
		return true
	case <-timer.C:
		return false
	case <-r.Context().Done():
		return false
	}
}

func releaseBodySlot() { <-bufferedBodySlots }
