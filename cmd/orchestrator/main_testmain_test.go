package main

import (
	"os"
	"testing"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func TestMain(m *testing.M) {
	// Secrets are hashed and verified in many tests; the production work
	// factor makes every login ~80ms. Use the minimum VerifySecret accepts.
	protocol.HashIterations = protocol.MinHashIterations
	os.Exit(m.Run())
}
