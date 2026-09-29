package main

import (
	"testing"
	"time"
)

// R2 ORC-I4: a non-repeating alert sent by this process stays once per
// episode even after the repeat cooldown has passed on the monotonic clock.
func TestBotOfflineAlertOncePerEpisodeWithMonotonicStamp(t *testing.T) {
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	entry := botProblemEntry{Scope: "device", ID: "twpk_a", Kind: "device_offline", Label: "twpk_a"}
	key := botProblemKey(entry)
	sent := time.Now()
	prev := botProblemState{
		Active:       map[string]botProblemEntry{key: entry},
		PendingPolls: map[string]int{key: botProblemPollsBeforeAlert},
		LastNotified: map[string]time.Time{key: now.Add(-botProblemRepeatCooldown - time.Minute)},
		sentMono:     map[string]time.Time{key: sent},
	}
	current := buildBotProblemState(prev, map[string]botProblemEntry{key: entry}, now)
	current.monoNow = sent.Add(botProblemRepeatCooldown + time.Minute)
	if !botProblemNoticeOnCooldown(prev, current, key) {
		t.Fatal("device_offline alert repeats after the cooldown within one episode")
	}
}

// R2 ORC-L8: the policy fields must be unambiguous: a duplicate or a
// case variant of ns, seq or worker_id is refused, since other parsers may
// pick a different one than the signer checked.
func TestSignerPolicyRejectsAmbiguousPolicyKeys(t *testing.T) {
	p, _ := loadSignerPolicy("")
	for _, msg := range []string{
		`{"ns":"client-config-v1","seq":1,"NS":"other"}`,
		`{"ns":"client-config-v1","seq":1,"Seq":999999999}`,
		`{"ns":"client-config-v1","seq":1,"seq":999999999}`,
		`{"ns":"worker-config-v1","seq":1,"worker_id":"a","Worker_ID":"b"}`,
	} {
		if err := p.admit(msg, nsClientConfig, nsWorkerConfig); err == nil {
			t.Fatalf("ambiguous document signed: %s", msg)
		}
	}
	if err := p.admit(`{"ns":"client-config-v1","seq":2,"workers":[{"ns":"x"}]}`, nsClientConfig); err != nil {
		t.Fatalf("nested keys are not policy keys: %v", err)
	}
}
