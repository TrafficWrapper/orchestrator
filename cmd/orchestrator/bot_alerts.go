package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

const (
	botProblemDeviceOfflineAfter      = 10 * time.Minute
	botProblemWorkerDownAfter         = workerFreshTTL
	botProblemPollsBeforeAlert        = 2
	botProblemRecoveryPollsBeforeNote = 2
	botProblemRecoveryMaxPolls        = botProblemRecoveryPollsBeforeNote + 10
	botProblemRepeatCooldown          = 3 * time.Hour
	botProblemMaxNoticesPerPoll       = 16
	botProblemQuotaNearPercent        = 90
)

type botProblemState struct {
	Version       int                        `json:"version"`
	Active        map[string]botProblemEntry `json:"active,omitempty"`
	PendingPolls  map[string]int             `json:"pending_polls,omitempty"`
	Recovering    map[string]botProblemEntry `json:"recovering,omitempty"`
	RecoveryPolls map[string]int             `json:"recovery_polls,omitempty"`
	LastNotified  map[string]time.Time       `json:"last_notified,omitempty"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

type botProblemEntry struct {
	Scope  string `json:"scope"`
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Level  string `json:"level,omitempty"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
}

type botProblemNotice struct {
	Key      string
	Text     string
	Recovery bool
}

func (b *telegramBot) notifyProblemTransitions(ctx context.Context) {
	if b == nil || b.client == nil || b.ownerID <= 0 || b.server == nil || b.server.store == nil {
		return
	}
	now := time.Now().UTC()
	currentProblems, err := b.server.botProblemSnapshot(now)
	if err != nil {
		log.Printf("telegram problem notify snapshot failed: %v", err)
		return
	}
	prev, found, err := b.server.store.getBotProblemState()
	if err != nil {
		log.Printf("telegram problem notify state read failed: %v", err)
		return
	}
	current := buildBotProblemState(prev, currentProblems, now)
	notices := botProblemNotices(prev, current, found)
	if len(notices) > 0 {
		if err := b.sendProblemNotices(ctx, notices); err != nil {
			log.Printf("telegram problem notify send failed: %v", err)
			return
		}
		markBotProblemNoticesSent(&current, notices)
	}
	cleanupRecoveredBotProblems(&current)
	if err := b.server.store.putBotProblemState(current); err != nil {
		log.Printf("telegram problem notify state save failed: %v", err)
	}
}

func (s *server) botProblemSnapshot(now time.Time) (map[string]botProblemEntry, error) {
	devices, err := s.store.devices()
	if err != nil {
		return nil, err
	}
	telemetry, err := s.store.telemetrySnapshots()
	if err != nil {
		return nil, err
	}
	workers, err := s.store.workers()
	if err != nil {
		return nil, err
	}
	out := map[string]botProblemEntry{}
	for _, device := range devices {
		for _, entry := range botDeviceProblemEntries(device, telemetry[device.ID], now) {
			out[botProblemKey(entry)] = entry
		}
	}
	for _, worker := range workers {
		if entry, ok := botWorkerProblemEntry(worker, now); ok {
			out[botProblemKey(entry)] = entry
		}
	}
	return out, nil
}

func botDeviceProblemEntries(device deviceRecord, telemetry telemetrySnapshotRecord, now time.Time) []botProblemEntry {
	id := strings.TrimSpace(device.ID)
	if id == "" {
		return nil
	}
	label := firstNotBlank(device.Alias, device.Model, shortString(id, 12), id)
	var out []botProblemEntry
	if entry, ok := botDeviceQuotaProblem(device, label); ok {
		out = append(out, entry)
	}
	if device.Status == "approved" && botDeviceTelemetryOffline(telemetry, now) {
		detail := "last_seen=" + telemetry.ReceivedAt.UTC().Format(time.RFC3339)
		out = append(out, botProblemEntry{
			Scope:  "device",
			ID:     id,
			Kind:   "device_offline",
			Label:  label,
			Detail: detail,
		})
	}
	return out
}

func botDeviceQuotaProblem(device deviceRecord, label string) (botProblemEntry, bool) {
	id := strings.TrimSpace(device.ID)
	quota := device.Limits.TrafficQuotaBytes
	if id == "" || quota == 0 {
		return botProblemEntry{}, false
	}
	usage := saturatingAddUint64(device.UsageRxBytes, device.UsageTxBytes)
	level := ""
	switch {
	case strings.TrimSpace(device.BlockedReason) == "traffic_quota_bytes" || usage >= quota:
		level = "exhausted"
	case quotaUsagePercent(usage, quota) >= botProblemQuotaNearPercent:
		level = "near"
	default:
		return botProblemEntry{}, false
	}
	return botProblemEntry{
		Scope:  "device",
		ID:     id,
		Kind:   "quota",
		Level:  level,
		Label:  label,
		Detail: fmt.Sprintf("%s / %s", humanBytes(usage), humanBytes(quota)),
	}, true
}

func quotaUsagePercent(usage, quota uint64) int {
	if quota == 0 {
		return 0
	}
	if usage >= quota {
		return 100
	}
	if usage > ^uint64(0)/100 {
		return 100
	}
	return int((usage * 100) / quota)
}

func botDeviceTelemetryOffline(telemetry telemetrySnapshotRecord, now time.Time) bool {
	if !telemetry.ReceivedAt.IsZero() {
		return now.Sub(telemetry.ReceivedAt.UTC()) >= botProblemDeviceOfflineAfter
	}
	return false
}

func botWorkerProblemEntry(worker workerRecord, now time.Time) (botProblemEntry, bool) {
	if worker.Disabled || worker.Status == "pending" {
		return botProblemEntry{}, false
	}
	id := strings.TrimSpace(worker.ID)
	if id == "" {
		return botProblemEntry{}, false
	}
	lastSeen := workerLastSeenAt(worker)
	down := worker.Status == "inactive"
	if !lastSeen.IsZero() && now.Sub(lastSeen.UTC()) >= botProblemWorkerDownAfter {
		down = true
	}
	if !down {
		return botProblemEntry{}, false
	}
	detail := "status=" + firstNotBlank(worker.Status, "-")
	if !lastSeen.IsZero() {
		detail += " last_seen=" + lastSeen.UTC().Format(time.RFC3339)
	}
	return botProblemEntry{
		Scope:  "worker",
		ID:     id,
		Kind:   "worker_down",
		Label:  firstNotBlank(stringFromMap(worker.SelfDescribe, "label"), shortString(id, 12), id),
		Detail: detail,
	}, true
}

func workerLastSeenAt(worker workerRecord) time.Time {
	if worker.LastAckAt != nil {
		return *worker.LastAckAt
	}
	if worker.ApprovedAt != nil {
		return *worker.ApprovedAt
	}
	return worker.CreatedAt
}

func buildBotProblemState(prev botProblemState, problems map[string]botProblemEntry, now time.Time) botProblemState {
	current := botProblemState{
		Version:       1,
		Active:        map[string]botProblemEntry{},
		PendingPolls:  map[string]int{},
		Recovering:    map[string]botProblemEntry{},
		RecoveryPolls: map[string]int{},
		LastNotified:  copyBotProblemTimeMap(prev.LastNotified),
		UpdatedAt:     now.UTC(),
	}
	for key, entry := range problems {
		if strings.TrimSpace(key) == "" {
			continue
		}
		current.PendingPolls[key] = prev.PendingPolls[key] + 1
		if current.PendingPolls[key] >= botProblemPollsBeforeAlert {
			current.Active[key] = entry
		}
	}
	for key, old := range prev.Active {
		if _, ok := problems[key]; !ok {
			current.Recovering[key] = old
			current.RecoveryPolls[key] = prev.RecoveryPolls[key] + 1
		}
	}
	for key, old := range prev.Recovering {
		if _, ok := problems[key]; !ok {
			current.Recovering[key] = old
			current.RecoveryPolls[key] = prev.RecoveryPolls[key] + 1
		}
	}
	return current
}

func botProblemNotices(prev, current botProblemState, initialized bool) []botProblemNotice {
	if !initialized {
		return nil
	}
	var notices []botProblemNotice
	sent := 0
	recoveryKeys := sortedBotProblemKeys(current.Recovering)
	recoveryBudget := botProblemMaxNoticesPerPoll / 4
	if recoveryBudget < 1 {
		recoveryBudget = 1
	}
	for _, key := range recoveryKeys {
		if sent >= recoveryBudget || current.RecoveryPolls[key] < botProblemRecoveryPollsBeforeNote {
			continue
		}
		entry := current.Recovering[key]
		notices = append(notices, botProblemNotice{Key: key, Text: botProblemRecoveredText(entry), Recovery: true})
		sent++
	}
	for _, key := range sortedBotProblemKeys(current.Active) {
		entry := current.Active[key]
		if botProblemNoticeOnCooldown(prev, current, key) {
			continue
		}
		notices = append(notices, botProblemNotice{Key: key, Text: botProblemIssueText(entry)})
		sent++
		if sent >= botProblemMaxNoticesPerPoll {
			return notices
		}
	}
	for _, key := range recoveryKeys {
		if sent >= botProblemMaxNoticesPerPoll {
			return notices
		}
		if current.RecoveryPolls[key] < botProblemRecoveryPollsBeforeNote {
			continue
		}
		if containsBotProblemNotice(notices, key) {
			continue
		}
		entry := current.Recovering[key]
		notices = append(notices, botProblemNotice{Key: key, Text: botProblemRecoveredText(entry), Recovery: true})
		sent++
	}
	return notices
}

func (b *telegramBot) sendProblemNotices(ctx context.Context, notices []botProblemNotice) error {
	if len(notices) > botProblemMaxNoticesPerPoll {
		notices = notices[:botProblemMaxNoticesPerPoll]
	}
	lines := []string{"Проблемы платформы"}
	for _, notice := range notices {
		lines = append(lines, notice.Text)
	}
	return b.sendOwnerMessage(ctx, strings.Join(lines, "\n"), nil)
}

func botProblemIssueText(entry botProblemEntry) string {
	switch entry.Kind {
	case "device_offline":
		return fmt.Sprintf("Device %s offline: %s", entry.Label, dashText(entry.Detail))
	case "quota":
		if entry.Level == "exhausted" {
			return fmt.Sprintf("Device %s quota exhausted: %s", entry.Label, dashText(entry.Detail))
		}
		return fmt.Sprintf("Device %s quota near limit: %s", entry.Label, dashText(entry.Detail))
	case "worker_down":
		return fmt.Sprintf("Worker %s down: %s", entry.Label, dashText(entry.Detail))
	default:
		return fmt.Sprintf("%s %s: %s", entry.Scope, entry.Label, entry.Kind)
	}
}

func botProblemRecoveredText(entry botProblemEntry) string {
	switch entry.Kind {
	case "device_offline":
		return "Device " + entry.Label + " recovered"
	case "quota":
		return "Device " + entry.Label + " quota recovered"
	case "worker_down":
		return "Worker " + entry.Label + " recovered"
	default:
		return entry.Label + " recovered"
	}
}

func botProblemNoticeOnCooldown(prev, current botProblemState, key string) bool {
	if botProblemEscalated(prev.Active[key], current.Active[key]) {
		return false
	}
	last := prev.LastNotified[key]
	if last.IsZero() {
		return false
	}
	return current.UpdatedAt.Sub(last.UTC()) < botProblemRepeatCooldown
}

func botProblemEscalated(old, current botProblemEntry) bool {
	if old.Kind != "quota" || current.Kind != "quota" {
		return false
	}
	return quotaProblemLevelRank(current.Level) > quotaProblemLevelRank(old.Level)
}

func quotaProblemLevelRank(level string) int {
	switch strings.TrimSpace(level) {
	case "exhausted":
		return 2
	case "near":
		return 1
	default:
		return 0
	}
}

func markBotProblemNoticesSent(state *botProblemState, notices []botProblemNotice) {
	if state.LastNotified == nil {
		state.LastNotified = map[string]time.Time{}
	}
	now := state.UpdatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, notice := range notices {
		if strings.TrimSpace(notice.Key) == "" {
			continue
		}
		if notice.Recovery {
			delete(state.Recovering, notice.Key)
			delete(state.RecoveryPolls, notice.Key)
			delete(state.LastNotified, notice.Key)
			continue
		}
		state.LastNotified[notice.Key] = now.UTC()
	}
}

func cleanupRecoveredBotProblems(state *botProblemState) {
	if state == nil {
		return
	}
	for key := range state.Recovering {
		if state.RecoveryPolls[key] < botProblemRecoveryMaxPolls {
			continue
		}
		delete(state.Recovering, key)
		delete(state.RecoveryPolls, key)
		delete(state.LastNotified, key)
	}
}

func containsBotProblemNotice(notices []botProblemNotice, key string) bool {
	for _, notice := range notices {
		if notice.Key == key {
			return true
		}
	}
	return false
}

func botProblemKey(entry botProblemEntry) string {
	return strings.Join([]string{strings.TrimSpace(entry.Scope), strings.TrimSpace(entry.ID), strings.TrimSpace(entry.Kind)}, ":")
}

func sortedBotProblemKeys(entries map[string]botProblemEntry) []string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func copyBotProblemTimeMap(in map[string]time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for key, value := range in {
		if strings.TrimSpace(key) == "" || value.IsZero() {
			continue
		}
		out[key] = value.UTC()
	}
	return out
}

func dashText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
