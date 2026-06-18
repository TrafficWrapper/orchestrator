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
	"net/http"
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
	answerCallback(ctx context.Context, callbackID, text string) error
}

type telegramBot struct {
	server   *server
	ownerID  int64
	client   telegramAPI
	approver *botAuthApprover
}

type botAuthApprover struct {
	bot     *telegramBot
	ttl     time.Duration
	mu      sync.Mutex
	pending map[string]chan bool
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
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
	case "/approve":
		text, keyboard := b.approveText()
		_ = b.sendOwnerMessage(ctx, text, keyboard)
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
		if device.Status != "revoked" {
			keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, []telegramInlineButton{{
				Text:         "Revoke " + shortString(device.ID, 8),
				CallbackData: fmt.Sprintf("device:revoke:%s", device.ID),
			}})
		}
	}
	return out.String(), keyboard
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

func botHelpText() string {
	return strings.Join([]string{
		"Команды:",
		"/status — обзор",
		"/workers — workers и протоколы",
		"/devices — устройства",
		"/config — priority/weight",
		"/publish_apk — статус APK",
		"/approve — pending approvals",
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
