package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	telegramAPIBaseURL        = "https://api.telegram.org"
	botPollTimeoutSeconds     = 25
	botPollErrorBackoff       = 5 * time.Second
	botLoginApprovalTTL       = 2 * time.Minute
	botMessageMaxDevices      = 12
	botMessageMaxWorkers      = 12
	botPendingNotifyInterval  = 30 * time.Second
	botLimitStateTTL          = 2 * time.Minute
	telegramMaxDocumentSize   = 50 << 20
	telegramMaxQuotaBytes     = 100 * 1024 * 1024 * 1024 * 1024
	telegramMaxLimitDuration  = 3650 * 24 * time.Hour
	botCallbackApprovePrefix  = "login:approve:"
	botCallbackDenyPrefix     = "login:deny:"
	botCallbackWorkerPrefix   = "worker:"
	botCallbackDevicePrefix   = "device:"
	botCallbackProtocolPrefix = "worker:proto:"
)

type authApprover interface {
	enabled() bool
	requestLoginApproval(context.Context, loginApprovalRequest) (bool, error)
}

type loginApprovalRequest struct {
	RemoteAddr string
	UserAgent  string
	CreatedAt  time.Time
}

type telegramClientFactory func(token string) telegramAPI

type telegramAPI interface {
	getUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]telegramUpdate, error)
	sendMessage(ctx context.Context, chatID int64, text string, keyboard *telegramInlineKeyboard) error
	sendDocument(ctx context.Context, chatID int64, path, filename, caption string) error
	answerCallback(ctx context.Context, callbackID, text string) error
}

type telegramBot struct {
	server   *server
	ownerID  int64
	client   telegramAPI
	approver *botAuthApprover
	limitMu  sync.Mutex
	limits   map[int64]telegramLimitState
}

type botAuthApprover struct {
	bot     *telegramBot
	ttl     time.Duration
	mu      sync.Mutex
	pending map[string]chan bool
}

type telegramLimitState struct {
	DeviceID  string
	ExpiresAt time.Time
}

type telegramUpdate struct {
	UpdateID      int64                  `json:"update_id"`
	Message       *telegramMessage       `json:"message,omitempty"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query,omitempty"`
}

type telegramUser struct {
	ID       int64  `json:"id"`
	UserName string `json:"username,omitempty"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}

type telegramMessage struct {
	MessageID int64        `json:"message_id,omitempty"`
	From      telegramUser `json:"from"`
	Chat      telegramChat `json:"chat"`
	Text      string       `json:"text,omitempty"`
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	From    telegramUser     `json:"from"`
	Message *telegramMessage `json:"message,omitempty"`
	Data    string           `json:"data,omitempty"`
}

type telegramInlineKeyboard struct {
	InlineKeyboard [][]telegramInlineButton `json:"inline_keyboard"`
}

type telegramInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type telegramHTTPClient struct {
	token  string
	apiURL string
	client *http.Client
}

func botCommand(cfg orchConfig, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: orchestrator bot set-token (--stdin | --env VAR | --file PATH) --owner-id ID | status")
	}
	switch args[0] {
	case "set-token":
		fs := flag.NewFlagSet("bot set-token", flag.ContinueOnError)
		token := fs.String("token", "", "deprecated unsafe telegram bot token")
		stdin := fs.Bool("stdin", false, "read telegram bot token from stdin")
		envName := fs.String("env", "", "read telegram bot token from environment variable")
		filePath := fs.String("file", "", "read telegram bot token from file")
		ownerID := fs.Int64("owner-id", 0, "owner telegram id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		secret, err := readSecretInput(secretInputOptions{
			Value:       *token,
			Stdin:       *stdin,
			EnvName:     *envName,
			FilePath:    *filePath,
			UnsafeLabel: "--token",
		})
		if err != nil {
			return err
		}
		st, err := openOrchStore(cfg)
		if err != nil {
			return err
		}
		defer st.close()
		if err := st.setBotSettings(secret, *ownerID); err != nil {
			return err
		}
		fmt.Printf("bot_configured owner_id=%d\n", *ownerID)
		return nil
	case "status":
		st, err := openOrchStore(cfg)
		if err != nil {
			return err
		}
		defer st.close()
		rec, ok, err := st.botSettings()
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("bot_configured=false")
			return nil
		}
		fmt.Printf("bot_configured=true owner_id=%d updated_at=%s\n", rec.OwnerID, rec.UpdatedAt.Format(time.RFC3339))
		return nil
	default:
		return fmt.Errorf("unknown bot command %q", args[0])
	}
}

func (s *server) startOptionalBot(ctx context.Context, factory telegramClientFactory) error {
	s.botMu.Lock()
	s.botFactory = factory
	s.botMu.Unlock()
	return s.restartOptionalBot(ctx)
}

func (s *server) restartOptionalBot(ctx context.Context) error {
	s.botMu.Lock()
	if s.botCancel != nil {
		s.botCancel()
		s.botCancel = nil
	}
	s.bot = nil
	s.authApprover = nil
	factory := s.botFactory
	s.botMu.Unlock()
	settings, ok, err := s.store.botSettings()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if factory == nil {
		return nil
	}
	botCtx, cancel := context.WithCancel(ctx)
	bot := newTelegramBot(s, settings, factory(settings.Token))
	s.botMu.Lock()
	s.bot = bot
	s.botCancel = cancel
	s.authApprover = bot.approver
	s.botMu.Unlock()
	go bot.run(botCtx)
	log.Printf("telegram bot enabled owner_id=%d", settings.OwnerID)
	return nil
}

func (s *server) currentAuthApprover() authApprover {
	s.botMu.Lock()
	defer s.botMu.Unlock()
	return s.authApprover
}

func (s *server) setAuthApproverForTest(approver authApprover) {
	s.botMu.Lock()
	s.authApprover = approver
	s.botMu.Unlock()
}

func (s *server) hasBotFactory() bool {
	s.botMu.Lock()
	defer s.botMu.Unlock()
	return s.botFactory != nil
}

func newTelegramBot(s *server, settings botSettingsRecord, client telegramAPI) *telegramBot {
	b := &telegramBot{
		server:  s,
		ownerID: settings.OwnerID,
		client:  client,
		limits:  map[int64]telegramLimitState{},
	}
	b.approver = &botAuthApprover{
		bot:     b,
		ttl:     botLoginApprovalTTL,
		pending: map[string]chan bool{},
	}
	return b
}

func newTelegramHTTPClient(token string) telegramAPI {
	return &telegramHTTPClient{
		token:  strings.TrimSpace(token),
		apiURL: telegramAPIBaseURL,
		client: &http.Client{Timeout: 35 * time.Second},
	}
}

func (b *telegramBot) run(ctx context.Context) {
	var offset int64
	nextNotify := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !time.Now().Before(nextNotify) {
			b.notifyPendingWorkers(ctx)
			nextNotify = time.Now().Add(botPendingNotifyInterval)
		}
		updates, err := b.client.getUpdates(ctx, offset, botPollTimeoutSeconds)
		if err != nil {
			log.Printf("telegram bot poll failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(botPollErrorBackoff):
				continue
			}
		}
		for _, update := range updates {
			if update.UpdateID >= offset {
				offset = update.UpdateID + 1
			}
			b.handleUpdate(ctx, update)
		}
	}
}

func (b *telegramBot) handleUpdate(ctx context.Context, update telegramUpdate) {
	if update.Message != nil {
		if update.Message.From.ID != b.ownerID {
			log.Printf("telegram bot ignored non-owner message from=%d", update.Message.From.ID)
			return
		}
		b.handleMessage(ctx, *update.Message)
		return
	}
	if update.CallbackQuery != nil {
		if update.CallbackQuery.From.ID != b.ownerID {
			log.Printf("telegram bot ignored non-owner callback from=%d", update.CallbackQuery.From.ID)
			return
		}
		b.handleCallback(ctx, *update.CallbackQuery)
	}
}

func (b *telegramBot) handleMessage(ctx context.Context, msg telegramMessage) {
	text := strings.TrimSpace(msg.Text)
	if !strings.HasPrefix(text, "/") {
		if state, ok := b.takeLimitState(msg.From.ID); ok {
			limits, err := parseTelegramDeviceLimits(text, time.Now().UTC())
			if err != nil {
				_ = b.sendOwnerMessage(ctx, "Лимиты не применены: "+err.Error(), nil)
				return
			}
			if err := b.server.store.setDeviceLimits(state.DeviceID, limits); err != nil {
				_ = b.sendOwnerMessage(ctx, "Лимиты не применены: "+err.Error(), nil)
				return
			}
			_ = b.sendOwnerMessage(ctx, "Лимиты заданы: "+telegramLimitsSummary(limits), nil)
			return
		}
	}
	command := strings.Fields(text)
	if len(command) == 0 {
		_ = b.sendOwnerMessage(ctx, botHelpText(), nil)
		return
	}
	switch strings.ToLower(command[0]) {
	case "/start", "/help":
		_ = b.sendOwnerMessage(ctx, botHelpText(), nil)
	case "/status":
		_ = b.sendOwnerMessage(ctx, b.statusText(), nil)
	case "/workers":
		text, keyboard := b.workersText()
		_ = b.sendOwnerMessage(ctx, text, keyboard)
	case "/devices":
		text, keyboard := b.devicesText()
		_ = b.sendOwnerMessage(ctx, text, keyboard)
	case "/config":
		_ = b.sendOwnerMessage(ctx, b.configText(), nil)
	case "/publish_apk":
		_ = b.sendOwnerMessage(ctx, b.apkText(), nil)
	case "/get_apk":
		if err := b.sendCurrentAPK(ctx); err != nil {
			_ = b.sendOwnerMessage(ctx, "APK: "+err.Error(), nil)
		}
	case "/approve":
		text, keyboard := b.approveText()
		_ = b.sendOwnerMessage(ctx, text, keyboard)
	case "/limit":
		_ = b.handleLimitCommand(ctx, command)
	default:
		_ = b.sendOwnerMessage(ctx, "Неизвестная команда.\n\n"+botHelpText(), nil)
	}
}

func (b *telegramBot) handleCallback(ctx context.Context, cb telegramCallbackQuery) {
	data := strings.TrimSpace(cb.Data)
	switch {
	case strings.HasPrefix(data, botCallbackApprovePrefix):
		nonce := strings.TrimPrefix(data, botCallbackApprovePrefix)
		if b.approver.resolve(nonce, true) {
			_ = b.client.answerCallback(ctx, cb.ID, "Вход подтверждён")
			return
		}
		_ = b.client.answerCallback(ctx, cb.ID, "Запрос входа уже истёк")
	case strings.HasPrefix(data, botCallbackDenyPrefix):
		nonce := strings.TrimPrefix(data, botCallbackDenyPrefix)
		if b.approver.resolve(nonce, false) {
			_ = b.client.answerCallback(ctx, cb.ID, "Вход отклонён")
			return
		}
		_ = b.client.answerCallback(ctx, cb.ID, "Запрос входа уже истёк")
	case strings.HasPrefix(data, botCallbackProtocolPrefix):
		parts := strings.Split(data, ":")
		if len(parts) != 5 {
			_ = b.client.answerCallback(ctx, cb.ID, "Неверная команда")
			return
		}
		enabled := parts[4] == "1"
		if err := b.server.store.updateWorkerPolicy(parts[2], workerPolicyPatch{Protocols: map[string]*bool{parts[3]: &enabled}}); err != nil {
			_ = b.client.answerCallback(ctx, cb.ID, err.Error())
			return
		}
		_ = b.client.answerCallback(ctx, cb.ID, "Протокол обновлён")
	case strings.HasPrefix(data, botCallbackWorkerPrefix):
		b.handleWorkerCallback(ctx, cb)
	case strings.HasPrefix(data, botCallbackDevicePrefix):
		parts := strings.Split(data, ":")
		if len(parts) != 3 || parts[1] != "revoke" {
			_ = b.client.answerCallback(ctx, cb.ID, "Неверная команда")
			return
		}
		if err := b.server.store.revokeDevice(parts[2]); err != nil {
			_ = b.client.answerCallback(ctx, cb.ID, err.Error())
			return
		}
		_ = b.client.answerCallback(ctx, cb.ID, "Устройство отозвано")
	default:
		_ = b.client.answerCallback(ctx, cb.ID, "Неизвестная команда")
	}
}

func (b *telegramBot) handleWorkerCallback(ctx context.Context, cb telegramCallbackQuery) {
	parts := strings.Split(strings.TrimSpace(cb.Data), ":")
	if len(parts) != 3 {
		_ = b.client.answerCallback(ctx, cb.ID, "Неверная команда")
		return
	}
	action, id := parts[1], parts[2]
	switch action {
	case "enable", "disable":
		enabled := action == "enable"
		if err := b.server.store.updateWorkerPolicy(id, workerPolicyPatch{Enabled: &enabled}); err != nil {
			_ = b.client.answerCallback(ctx, cb.ID, err.Error())
			return
		}
		_ = b.client.answerCallback(ctx, cb.ID, "Worker обновлён")
	case "approve":
		if err := b.server.store.approveWorker(id); err != nil {
			_ = b.client.answerCallback(ctx, cb.ID, err.Error())
			return
		}
		_ = b.client.answerCallback(ctx, cb.ID, "Worker одобрен")
	default:
		_ = b.client.answerCallback(ctx, cb.ID, "Неверная команда")
	}
}

func (b *telegramBot) sendOwnerMessage(ctx context.Context, text string, keyboard *telegramInlineKeyboard) error {
	return b.client.sendMessage(ctx, b.ownerID, text, keyboard)
}

func (b *telegramBot) statusText() string {
	workers, _ := b.server.store.workers()
	devices, _ := b.server.store.devices()
	activeWorkers := 0
	for _, worker := range workers {
		if !worker.Disabled && (worker.Status == "active" || worker.Status == "approved") {
			activeWorkers++
		}
	}
	approvedDevices := 0
	for _, device := range devices {
		if device.Status == "approved" {
			approvedDevices++
		}
	}
	return fmt.Sprintf(
		"Статус платформы\nWorkers: %d/%d активны\nDevices: %d/%d approved\nConfig seq: %d",
		activeWorkers,
		len(workers),
		approvedDevices,
		len(devices),
		maxWorkerDesiredSeq(workers),
	)
}

func (b *telegramBot) workersText() (string, *telegramInlineKeyboard) {
	workers, err := b.server.store.workers()
	if err != nil {
		return "Workers: " + err.Error(), nil
	}
	var out strings.Builder
	out.WriteString("Workers\n")
	keyboard := &telegramInlineKeyboard{}
	for i, worker := range workers {
		if i >= botMessageMaxWorkers {
			out.WriteString("…\n")
			break
		}
		enabled := !worker.Disabled
		fmt.Fprintf(&out, "%s · %s · enabled=%t · seq %d/%d · prio=%d weight=%d\n",
			shortString(worker.ID, 8),
			worker.Status,
			enabled,
			worker.AppliedSeq,
			worker.DesiredSeq,
			effectiveWorkerPriority(worker),
			effectiveWorkerWeight(worker),
		)
		row := []telegramInlineButton{{
			Text:         map[bool]string{true: "Disable", false: "Enable"}[enabled],
			CallbackData: fmt.Sprintf("worker:%s:%s", map[bool]string{true: "disable", false: "enable"}[enabled], worker.ID),
		}}
		realityEnabled := workerProtocolEnabled(worker, "reality")
		awgEnabled := workerProtocolEnabled(worker, "awg")
		row = append(row,
			telegramInlineButton{Text: fmt.Sprintf("REALITY %s", onOffText(!realityEnabled)), CallbackData: fmt.Sprintf("worker:proto:%s:reality:%d", worker.ID, boolInt(!realityEnabled))},
			telegramInlineButton{Text: fmt.Sprintf("AWG %s", onOffText(!awgEnabled)), CallbackData: fmt.Sprintf("worker:proto:%s:awg:%d", worker.ID, boolInt(!awgEnabled))},
		)
		if worker.Status == "pending" {
			row = append(row, telegramInlineButton{Text: "Approve", CallbackData: fmt.Sprintf("worker:approve:%s", worker.ID)})
		}
		keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, row)
	}
	return out.String(), keyboard
}

func (b *telegramBot) devicesText() (string, *telegramInlineKeyboard) {
	devices, err := b.server.store.devices()
	if err != nil {
		return "Devices: " + err.Error(), nil
	}
	var out strings.Builder
	out.WriteString("Devices\n")
	keyboard := &telegramInlineKeyboard{}
	for i, device := range devices {
		if i >= botMessageMaxDevices {
			out.WriteString("…\n")
			break
		}
		fmt.Fprintf(&out, "%s · %s · %s · %s\n",
			shortString(device.ID, 8),
			device.Status,
			firstNotBlank(device.ClientVersion, "-"),
			firstNotBlank(device.InternalIP, "-"),
		)
		if !deviceLimitsEmpty(device.Limits) {
			fmt.Fprintf(&out, "  limits: %s\n", telegramLimitsSummary(device.Limits))
		}
		if device.Status != "revoked" {
			keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, []telegramInlineButton{{
				Text:         "Revoke " + shortString(device.ID, 8),
				CallbackData: fmt.Sprintf("device:revoke:%s", device.ID),
			}})
		}
	}
	return out.String(), keyboard
}

func (b *telegramBot) handleLimitCommand(ctx context.Context, command []string) error {
	if len(command) < 2 {
		return b.sendOwnerMessage(ctx, "Формат: /limit <device_id> <quota|-|reset> <rate|-|0> <expiry|-|нет>\nПример: /limit twpk_abcd 10GB 20mbit 30d", nil)
	}
	deviceID := strings.TrimSpace(command[1])
	if _, err := b.server.store.device(deviceID); err != nil {
		return b.sendOwnerMessage(ctx, "Device: "+err.Error(), nil)
	}
	if len(command) == 2 {
		b.putLimitState(b.ownerID, deviceID)
		return b.sendOwnerMessage(ctx, "Отправьте лимиты для "+shortString(deviceID, 12)+": quota rate expiry\nПример: 10GB 20mbit 30d\nСброс: reset", nil)
	}
	limits, err := parseTelegramDeviceLimits(strings.Join(command[2:], " "), time.Now().UTC())
	if err != nil {
		return b.sendOwnerMessage(ctx, "Лимиты не применены: "+err.Error(), nil)
	}
	if err := b.server.store.setDeviceLimits(deviceID, limits); err != nil {
		return b.sendOwnerMessage(ctx, "Лимиты не применены: "+err.Error(), nil)
	}
	return b.sendOwnerMessage(ctx, "Лимиты заданы: "+telegramLimitsSummary(limits), nil)
}

func (b *telegramBot) putLimitState(ownerID int64, deviceID string) {
	b.limitMu.Lock()
	defer b.limitMu.Unlock()
	if b.limits == nil {
		b.limits = map[int64]telegramLimitState{}
	}
	b.limits[ownerID] = telegramLimitState{DeviceID: strings.TrimSpace(deviceID), ExpiresAt: time.Now().UTC().Add(botLimitStateTTL)}
}

func (b *telegramBot) takeLimitState(ownerID int64) (telegramLimitState, bool) {
	b.limitMu.Lock()
	defer b.limitMu.Unlock()
	state, ok := b.limits[ownerID]
	if !ok {
		return telegramLimitState{}, false
	}
	delete(b.limits, ownerID)
	if time.Now().UTC().After(state.ExpiresAt) {
		return telegramLimitState{}, false
	}
	return state, true
}

func (b *telegramBot) configText() string {
	workers, err := b.server.store.workers()
	if err != nil {
		return "Config: " + err.Error()
	}
	var out strings.Builder
	out.WriteString("Config workers\n")
	for _, worker := range workers {
		fmt.Fprintf(&out, "%s priority=%d weight=%d enabled=%t reality=%t awg=%t\n",
			shortString(worker.ID, 8),
			effectiveWorkerPriority(worker),
			effectiveWorkerWeight(worker),
			!worker.Disabled,
			workerProtocolEnabled(worker, "reality"),
			workerProtocolEnabled(worker, "awg"),
		)
	}
	return out.String()
}

func (b *telegramBot) apkText() string {
	rec, ok, err := b.server.store.currentAPKRelease()
	if err != nil {
		return "APK: " + err.Error()
	}
	if !ok {
		return "APK: релиз не опубликован"
	}
	return fmt.Sprintf("APK: seq=%d version=%s(%d) size=%d sha=%s",
		rec.Seq,
		rec.VersionName,
		rec.VersionCode,
		rec.APKSize,
		shortString(rec.APKSHA256, 12),
	)
}

func (b *telegramBot) sendCurrentAPK(ctx context.Context) error {
	rec, ok, err := b.server.store.currentAPKRelease()
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(rec.APKPath) == "" {
		return errors.New("релиз не опубликован")
	}
	stat, err := os.Stat(rec.APKPath)
	if err != nil {
		return err
	}
	if stat.Size() > telegramMaxDocumentSize {
		return fmt.Errorf("APK больше лимита Telegram Bot API: %s", humanBytes(uint64(stat.Size())))
	}
	filename := strings.TrimSpace(rec.APKName)
	if filename == "" {
		filename = filepath.Base(rec.APKPath)
	}
	if strings.TrimSpace(rec.VersionName) != "" && rec.VersionCode > 0 {
		filename = fmt.Sprintf("TrafficWrapper-app-v%s-code%d.apk", rec.VersionName, rec.VersionCode)
	}
	return b.client.sendDocument(ctx, b.ownerID, rec.APKPath, filename, "Текущий опубликованный APK")
}

func (b *telegramBot) approveText() (string, *telegramInlineKeyboard) {
	workers, err := b.server.store.workers()
	if err != nil {
		return "Approve: " + err.Error(), nil
	}
	keyboard := &telegramInlineKeyboard{}
	var out strings.Builder
	out.WriteString("Pending approve\n")
	count := 0
	for _, worker := range workers {
		if worker.Status != "pending" {
			continue
		}
		count++
		fmt.Fprintf(&out, "worker %s\n", shortString(worker.ID, 8))
		keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, []telegramInlineButton{{
			Text:         "Approve " + shortString(worker.ID, 8),
			CallbackData: fmt.Sprintf("worker:approve:%s", worker.ID),
		}})
	}
	if count == 0 {
		out.WriteString("Нет pending worker/device.\n")
	}
	return out.String(), keyboard
}

func (b *telegramBot) notifyPendingWorkers(ctx context.Context) {
	workers, err := b.server.store.workers()
	if err != nil {
		log.Printf("telegram pending worker notify list failed: %v", err)
		return
	}
	for _, worker := range workers {
		if worker.Status != "pending" {
			continue
		}
		notified, err := b.server.store.botPendingWorkerNotified(worker.ID)
		if err != nil || notified {
			continue
		}
		if err := b.sendPendingWorkerNotice(ctx, worker); err != nil {
			log.Printf("telegram pending worker notify send failed: %v", err)
			continue
		}
		_ = b.server.store.markBotPendingWorkerNotified(worker.ID)
	}
}

func (b *telegramBot) sendPendingWorkerNotice(ctx context.Context, worker workerRecord) error {
	text := fmt.Sprintf(
		"Новый pending worker\nid: %s\ncreated: %s\naddress: %s",
		worker.ID,
		worker.CreatedAt.UTC().Format(time.RFC3339),
		firstNotBlank(stringFromMap(worker.SelfDescribe, "public_address"), "-"),
	)
	keyboard := &telegramInlineKeyboard{InlineKeyboard: [][]telegramInlineButton{{
		{Text: "Approve " + shortString(worker.ID, 8), CallbackData: "worker:approve:" + worker.ID},
	}}}
	return b.sendOwnerMessage(ctx, text, keyboard)
}

func botHelpText() string {
	return strings.Join([]string{
		"Команды:",
		"/status — обзор",
		"/workers — workers и протоколы",
		"/devices — устройства",
		"/config — priority/weight",
		"/publish_apk — статус APK",
		"/get_apk — отправить текущий APK",
		"/approve — pending approvals",
		"/limit <device_id> <quota> <rate> <expiry> — задать лимиты",
	}, "\n")
}

func maxWorkerDesiredSeq(workers []workerRecord) int64 {
	var out int64
	for _, worker := range workers {
		if worker.DesiredSeq > out {
			out = worker.DesiredSeq
		}
	}
	return out
}

func onOffText(on bool) string {
	if on {
		return "ON"
	}
	return "OFF"
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func parseTelegramDeviceLimits(input string, now time.Time) (deviceLimits, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return deviceLimits{}, errors.New("пустая строка; формат: квота скорость срок")
	}
	if isResetLimitsToken(value) {
		return deviceLimits{}, nil
	}
	fields := strings.Fields(value)
	if len(fields) > 3 {
		return deviceLimits{}, errors.New("нужно не больше трёх полей: квота скорость срок")
	}
	var limits deviceLimits
	var err error
	if len(fields) >= 1 {
		limits.TrafficQuotaBytes, err = parseTelegramQuotaBytes(fields[0])
		if err != nil {
			return deviceLimits{}, fmt.Errorf("квота: %w", err)
		}
	}
	if len(fields) >= 2 {
		limits.RateLimit, err = parseTelegramRateLimit(fields[1])
		if err != nil {
			return deviceLimits{}, fmt.Errorf("скорость: %w", err)
		}
	}
	if len(fields) >= 3 {
		limits.ExpiresAt, err = parseTelegramLimitExpiry(fields[2], now)
		if err != nil {
			return deviceLimits{}, fmt.Errorf("срок: %w", err)
		}
	}
	return limits, nil
}

func parseTelegramQuotaBytes(token string) (uint64, error) {
	token = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(token, ",", ".")))
	if isNoLimitToken(token) {
		return 0, nil
	}
	units := []struct {
		suffix     string
		multiplier float64
	}{
		{"gib", 1024 * 1024 * 1024},
		{"gb", 1024 * 1024 * 1024},
		{"gi", 1024 * 1024 * 1024},
		{"g", 1024 * 1024 * 1024},
		{"mib", 1024 * 1024},
		{"mb", 1024 * 1024},
		{"mi", 1024 * 1024},
		{"m", 1024 * 1024},
		{"kib", 1024},
		{"kb", 1024},
		{"ki", 1024},
		{"k", 1024},
		{"bytes", 1},
		{"byte", 1},
		{"b", 1},
	}
	multiplier := float64(1)
	number := token
	for _, unit := range units {
		if strings.HasSuffix(token, unit.suffix) {
			multiplier = unit.multiplier
			number = strings.TrimSpace(strings.TrimSuffix(token, unit.suffix))
			break
		}
	}
	amount, err := strconv.ParseFloat(number, 64)
	if err != nil || math.IsNaN(amount) || math.IsInf(amount, 0) {
		return 0, errors.New("пример: 10GB, 500MB, 1.5G или -")
	}
	if amount <= 0 {
		return 0, errors.New("должна быть больше 0 или '-'")
	}
	bytes := math.Round(amount * multiplier)
	if bytes <= 0 || bytes > telegramMaxQuotaBytes {
		return 0, fmt.Errorf("должна быть в пределах %s", humanBytes(uint64(telegramMaxQuotaBytes)))
	}
	return uint64(bytes), nil
}

func parseTelegramRateLimit(token string) (string, error) {
	token = strings.ToLower(strings.TrimSpace(token))
	if isNoLimitToken(token) {
		return "", nil
	}
	if len([]rune(token)) > 32 || strings.ContainsAny(token, "\r\n\t ") {
		return "", errors.New("пример: 20mbit, 50mbps или -")
	}
	return token, nil
}

func parseTelegramLimitExpiry(token string, now time.Time) (*string, error) {
	token = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(token, ",", ".")))
	if isNoLimitToken(token) {
		return nil, nil
	}
	if len(token) < 2 {
		return nil, errors.New("пример: 24h, 7d, 30d или -")
	}
	unit := token[len(token)-1:]
	number := strings.TrimSpace(token[:len(token)-1])
	amount, err := strconv.ParseFloat(number, 64)
	if err != nil || math.IsNaN(amount) || math.IsInf(amount, 0) || amount <= 0 {
		return nil, errors.New("пример: 24h, 7d, 30d или -")
	}
	var duration time.Duration
	switch unit {
	case "h":
		duration = time.Duration(amount * float64(time.Hour))
	case "d":
		duration = time.Duration(amount * float64(24*time.Hour))
	default:
		return nil, errors.New("единица срока должна быть h или d")
	}
	if duration <= 0 || duration > telegramMaxLimitDuration {
		return nil, fmt.Errorf("срок должен быть от 1с до %s", telegramMaxLimitDuration)
	}
	expiresAt := now.UTC().Add(duration).Format(time.RFC3339)
	return &expiresAt, nil
}

func telegramLimitsSummary(limits deviceLimits) string {
	quota := "нет"
	if limits.TrafficQuotaBytes > 0 {
		quota = humanBytes(limits.TrafficQuotaBytes)
	}
	rate := "нет"
	if strings.TrimSpace(limits.RateLimit) != "" {
		rate = strings.TrimSpace(limits.RateLimit) + " (hint)"
	}
	expires := "нет"
	if limits.ExpiresAt != nil && strings.TrimSpace(*limits.ExpiresAt) != "" {
		expires = strings.TrimSpace(*limits.ExpiresAt) + " (enforced)"
	}
	return fmt.Sprintf("квота %s (TODO), скорость %s, срок %s", quota, rate, expires)
}

func isNoLimitToken(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "", "-", "0", "нет", "none", "no":
		return true
	default:
		return false
	}
}

func isResetLimitsToken(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "reset", "сброс", "clear":
		return true
	default:
		return false
	}
}

func humanBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func (a *botAuthApprover) enabled() bool {
	return a != nil && a.bot != nil && a.bot.ownerID > 0
}

func (a *botAuthApprover) requestLoginApproval(ctx context.Context, req loginApprovalRequest) (bool, error) {
	if !a.enabled() {
		return true, nil
	}
	nonce := shortString(randID(), 8)
	ch := make(chan bool, 1)
	a.mu.Lock()
	a.pending[nonce] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, nonce)
		a.mu.Unlock()
	}()
	text := fmt.Sprintf("Подтвердить вход в админку?\nnonce: %s\naddr: %s\nua: %s",
		nonce,
		firstNotBlank(req.RemoteAddr, "-"),
		shortString(firstNotBlank(req.UserAgent, "-"), 80),
	)
	keyboard := &telegramInlineKeyboard{InlineKeyboard: [][]telegramInlineButton{{
		{Text: "Да", CallbackData: botCallbackApprovePrefix + nonce},
		{Text: "Нет", CallbackData: botCallbackDenyPrefix + nonce},
	}}}
	if err := a.bot.sendOwnerMessage(ctx, text, keyboard); err != nil {
		return false, err
	}
	timer := time.NewTimer(a.ttl)
	defer timer.Stop()
	select {
	case approved := <-ch:
		return approved, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, errors.New("admin login approval timeout")
	}
}

func (a *botAuthApprover) resolve(nonce string, approved bool) bool {
	a.mu.Lock()
	ch, ok := a.pending[strings.TrimSpace(nonce)]
	if ok {
		delete(a.pending, strings.TrimSpace(nonce))
	}
	a.mu.Unlock()
	if !ok {
		return false
	}
	ch <- approved
	return true
}

func (c *telegramHTTPClient) getUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]telegramUpdate, error) {
	var resp struct {
		OK     bool             `json:"ok"`
		Result []telegramUpdate `json:"result"`
		Error  string           `json:"description,omitempty"`
	}
	if err := c.call(ctx, "getUpdates", map[string]any{
		"offset":  offset,
		"timeout": timeoutSeconds,
	}, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(firstNotBlank(resp.Error, "telegram getUpdates failed"))
	}
	return resp.Result, nil
}

func (c *telegramHTTPClient) sendMessage(ctx context.Context, chatID int64, text string, keyboard *telegramInlineKeyboard) error {
	req := map[string]any{
		"chat_id": chatID,
		"text":    text,
	}
	if keyboard != nil && len(keyboard.InlineKeyboard) > 0 {
		req["reply_markup"] = keyboard
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"description,omitempty"`
	}
	if err := c.call(ctx, "sendMessage", req, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(firstNotBlank(resp.Error, "telegram sendMessage failed"))
	}
	return nil
}

func (c *telegramHTTPClient) sendDocument(ctx context.Context, chatID int64, path, filename, caption string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		_ = writer.WriteField("chat_id", strconv.FormatInt(chatID, 10))
		if strings.TrimSpace(caption) != "" {
			_ = writer.WriteField("caption", caption)
		}
		part, err := writer.CreateFormFile("document", filename)
		if err == nil {
			_, err = io.Copy(part, file)
		}
		closeErr := writer.Close()
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if closeErr != nil {
			_ = pw.CloseWithError(closeErr)
		}
	}()
	url := strings.TrimRight(c.apiURL, "/") + "/bot" + c.token + "/sendDocument"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		OK    bool   `json:"ok"`
		Error string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !env.OK {
		return errors.New(firstNotBlank(env.Error, "telegram sendDocument failed"))
	}
	return nil
}

func (c *telegramHTTPClient) answerCallback(ctx context.Context, callbackID, text string) error {
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"description,omitempty"`
	}
	err := c.call(ctx, "answerCallbackQuery", map[string]any{
		"callback_query_id": callbackID,
		"text":              text,
	}, &resp)
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(firstNotBlank(resp.Error, "telegram answerCallbackQuery failed"))
	}
	return nil
}

func (c *telegramHTTPClient) call(ctx context.Context, method string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := strings.TrimRight(c.apiURL, "/") + "/bot" + c.token + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram %s http=%d", method, resp.StatusCode)
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func parseTelegramOwnerID(value string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("owner telegram id must be positive integer")
	}
	return id, nil
}
