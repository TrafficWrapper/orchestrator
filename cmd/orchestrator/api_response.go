package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// errNotFound marks store lookups of records that do not exist; admin API
// handlers map it to 404.
var errNotFound = errors.New("not found")

var (
	errDeviceNotFound = fmt.Errorf("device %w", errNotFound)
	errWorkerNotFound = fmt.Errorf("worker %w", errNotFound)
)

// apiError is the admin API error body.
type apiError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// writeError answers with a JSON error body and the given status (argument
// order mirrors http.Error).
func writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiError{OK: false, Error: message})
}

// writeStoreError reports a store/handler error: not-found errors become 404,
// everything else uses the handler's status.
func writeStoreError(w http.ResponseWriter, status int, err error) {
	if errors.Is(err, errNotFound) {
		status = http.StatusNotFound
	}
	writeError(w, err.Error(), status)
}

// decodeJSON reads the request body into v, answering 400 on malformed JSON.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// admin wraps an admin API handler: the method is checked first (405 before
// any auth answer), then the session and CSRF token via requireAdmin.
func (s *server) admin(methods []string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed := false
		for _, m := range methods {
			if r.Method == m {
				allowed = true
				break
			}
		}
		if !allowed {
			writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.requireAdmin(w, r) {
			return
		}
		h(w, r)
	}
}

var (
	adminGET  = []string{http.MethodGet}
	adminPOST = []string{http.MethodPost}
)
