package main

import (
	"net/http"
	"testing"
	"time"
)

func TestOrchestratorHTTPServerTimeoutsPreserveLongPoll(t *testing.T) {
	srv := newOrchestratorHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if srv.ReadHeaderTimeout != 15*time.Second {
		t.Fatalf("read header timeout=%s want 15s", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Fatalf("idle timeout=%s want 120s", srv.IdleTimeout)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Fatalf("global read/write timeouts must stay disabled for long-poll: read=%s write=%s", srv.ReadTimeout, srv.WriteTimeout)
	}
}
