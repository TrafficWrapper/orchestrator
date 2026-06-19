package main

import (
	"embed"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed web/templates/*.html
var webTemplateFS embed.FS

var webTemplates = template.Must(template.New("web").Funcs(template.FuncMap{
	"short": shortString,
	"dash": func(value string) string {
		if strings.TrimSpace(value) == "" {
			return "-"
		}
		return value
	},
}).ParseFS(webTemplateFS, "web/templates/*.html"))

type webPageData struct {
	Template       string
	Title          string
	Path           string
	Authenticated  bool
	CSRFToken      string
	SessionExpires string
	Workers        []webWorker
	Devices        []webDevice
	ConfigSeq      int64
	WorkerTotal    int
	WorkerActive   int
	DeviceTotal    int
	DeviceApproved int
	Health         string
	Now            string
	MustChange     bool
	BotConfigured  bool
	BotOwnerID     int64
	BotUpdatedAt   string
}

type webWorker struct {
	ID             string
	Status         string
	Enabled        bool
	LastSeen       string
	DesiredSeq     int64
	AppliedSeq     int64
	ConfigSyncOK   bool
	ConfigSyncText string
	APKSyncState   string
	APKSyncText    string
	Egress         string
	Priority       int
	Weight         int
	Reality        bool
	AWG            bool
}

type webDevice struct {
	ID               string
	Alias            string
	Status           string
	ClientVersion    string
	Model            string
	AndroidID        string
	EnrolledAt       string
	InternalIP       string
	ConfigSeq        int64
	TelemetryOn      bool
	LiveVersion      string
	InstalledVersion string
	VersionSource    string
	UpdateAvailable  bool
	PublishedVersion string
	LiveRoute        string
	LiveHealth       string
	LiveCarry        bool
	LiveLastSeen     string
	LiveWorkerID     string
	LiveError        string
	Recent           []telemetryEvent
}

func (s *server) registerWebRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", s.handleWebLogin)
	mux.HandleFunc("/change-password", s.handleWebChangePassword)
	mux.HandleFunc("/", s.handleWebDashboard)
	mux.HandleFunc("/workers", s.handleWebWorkers)
	mux.HandleFunc("/devices", s.handleWebDevices)
	mux.HandleFunc("/config", s.handleWebConfig)
	mux.HandleFunc("/settings", s.handleWebSettings)
}

func (s *server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if session, ok := s.webSession(r); ok {
		if session.MustChange {
			http.Redirect(w, r, "/change-password", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.renderWeb(w, webPageData{
		Template: "login",
		Title:    "Вход",
		Path:     "/login",
		Now:      time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *server) handleWebChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/change-password" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.webSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !session.MustChange {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.renderWeb(w, webPageData{
		Template:       "change_password",
		Title:          "Смена пароля",
		Path:           "/change-password",
		Authenticated:  false,
		CSRFToken:      session.CSRFToken,
		SessionExpires: session.ExpiresAt.Format(time.RFC3339),
		MustChange:     true,
		Now:            time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *server) handleWebDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderWebPage(w, r, "dashboard", "Обзор", "/")
}

func (s *server) handleWebWorkers(w http.ResponseWriter, r *http.Request) {
	s.renderWebPage(w, r, "workers", "Workers", "/workers")
}

func (s *server) handleWebDevices(w http.ResponseWriter, r *http.Request) {
	s.renderWebPage(w, r, "devices", "Устройства", "/devices")
}

func (s *server) handleWebConfig(w http.ResponseWriter, r *http.Request) {
	s.renderWebPage(w, r, "config", "Конфигурация", "/config")
}

func (s *server) handleWebSettings(w http.ResponseWriter, r *http.Request) {
	s.renderWebPage(w, r, "settings", "Настройки", "/settings")
}

func (s *server) renderWebPage(w http.ResponseWriter, r *http.Request, name, title, path string) {
	if r.URL.Path != path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.webSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if session.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusFound)
		return
	}
	data, err := s.webData(name, title, path, session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWeb(w, data)
}

func (s *server) renderWeb(w http.ResponseWriter, data webPageData) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	if err := webTemplates.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *server) webSession(r *http.Request) (adminSession, bool) {
	cookie, err := r.Cookie("tw_admin_session")
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return adminSession{}, false
	}
	value, ok := s.adminSessions.Load(cookie.Value)
	if !ok {
		return adminSession{}, false
	}
	session := value.(adminSession)
	if time.Now().UTC().After(session.ExpiresAt) {
		s.adminSessions.Delete(cookie.Value)
		return adminSession{}, false
	}
	return session, true
}

func (s *server) webData(templateName, title, path string, session adminSession) (webPageData, error) {
	workers, err := s.store.workers()
	if err != nil {
		return webPageData{}, err
	}
	devices, err := s.store.devices()
	if err != nil {
		return webPageData{}, err
	}
	telemetry, err := s.store.telemetrySnapshots()
	if err != nil {
		return webPageData{}, err
	}
	apkRelease, apkPublished, err := s.store.currentAPKRelease()
	if err != nil {
		return webPageData{}, err
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].ID < workers[j].ID })
	sort.Slice(devices, func(i, j int) bool { return devices[i].CreatedAt.After(devices[j].CreatedAt) })

	page := webPageData{
		Template:       templateName,
		Title:          title,
		Path:           path,
		Authenticated:  true,
		CSRFToken:      session.CSRFToken,
		SessionExpires: session.ExpiresAt.Format(time.RFC3339),
		ConfigSeq:      webConfigSeq(workers),
		WorkerTotal:    len(workers),
		DeviceTotal:    len(devices),
		Health:         "ok",
		Now:            time.Now().UTC().Format(time.RFC3339),
	}
	if bot, ok, err := s.store.botSettings(); err == nil && ok {
		page.BotConfigured = true
		page.BotOwnerID = bot.OwnerID
		page.BotUpdatedAt = bot.UpdatedAt.UTC().Format(time.RFC3339)
	}
	for _, worker := range workers {
		item := webWorker{
			ID:             worker.ID,
			Status:         worker.Status,
			Enabled:        !worker.Disabled,
			LastSeen:       formatOptionalTime(worker.LastAckAt),
			DesiredSeq:     worker.DesiredSeq,
			AppliedSeq:     worker.AppliedSeq,
			ConfigSyncOK:   worker.AppliedSeq == worker.DesiredSeq,
			ConfigSyncText: configSyncText(worker),
			APKSyncState:   "unknown",
			APKSyncText:    apkSyncText(worker, apkRelease, apkPublished),
			Egress:         firstNotBlank(worker.EgressIPObserved, worker.EgressIPProbe),
			Priority:       effectiveWorkerPriority(worker),
			Weight:         effectiveWorkerWeight(worker),
			Reality:        workerProtocolEnabled(worker, "reality"),
			AWG:            workerProtocolEnabled(worker, "awg"),
		}
		item.APKSyncState = apkSyncState(worker, apkRelease, apkPublished)
		if item.Enabled && item.Status == "active" {
			page.WorkerActive++
		}
		page.Workers = append(page.Workers, item)
	}
	for _, device := range devices {
		live, hasLive := telemetry[device.ID]
		installedVersion, versionSource := resolveInstalledVersion(device, live, hasLive)
		updateAvailable, publishedVersion := computeUpdateAvailable(hasLive, live.ClientVC, apkPublished, apkRelease)
		item := webDevice{
			ID:               device.ID,
			Alias:            device.Alias,
			Status:           device.Status,
			ClientVersion:    device.ClientVersion,
			Model:            device.Model,
			AndroidID:        device.AndroidID,
			EnrolledAt:       device.CreatedAt.UTC().Format(time.RFC3339),
			InternalIP:       device.InternalIP,
			ConfigSeq:        device.ConfigSeq,
			TelemetryOn:      hasLive,
			InstalledVersion: installedVersion,
			VersionSource:    versionSource,
			UpdateAvailable:  updateAvailable,
			PublishedVersion: publishedVersion,
		}
		if hasLive {
			item.LiveVersion = live.ClientVersion
			if live.ClientVC > 0 {
				item.LiveVersion = firstNotBlank(item.LiveVersion, "vc "+strconv.FormatInt(live.ClientVC, 10))
			}
			item.LiveRoute = live.Route
			item.LiveHealth = live.Health
			item.LiveCarry = live.Carry
			item.LiveLastSeen = live.ReceivedAt.UTC().Format(time.RFC3339)
			item.LiveWorkerID = live.WorkerID
			item.LiveError = live.LastError
			item.Recent = live.Recent
		}
		if item.Status == "approved" {
			page.DeviceApproved++
		}
		page.Devices = append(page.Devices, item)
	}
	if page.WorkerActive == 0 {
		page.Health = "needs_attention"
	}
	return page, nil
}

func webConfigSeq(workers []workerRecord) int64 {
	seq := int64(1)
	for _, worker := range workers {
		if worker.Status != "approved" && worker.Status != "active" {
			continue
		}
		if worker.DesiredSeq > seq {
			seq = worker.DesiredSeq
		}
	}
	return seq
}

func configSyncText(worker workerRecord) string {
	if worker.AppliedSeq == worker.DesiredSeq {
		return "конфиг актуален"
	}
	return "отстаёт (applied " + strconv.FormatInt(worker.AppliedSeq, 10) + " / desired " + strconv.FormatInt(worker.DesiredSeq, 10) + ")"
}

func resolveInstalledVersion(device deviceRecord, live telemetrySnapshotRecord, hasLive bool) (string, string) {
	if hasLive {
		if version := strings.TrimSpace(live.ClientVersion); version != "" {
			return version, "telemetry"
		}
		if live.ClientVC > 0 {
			return "vc " + strconv.FormatInt(live.ClientVC, 10), "telemetry"
		}
	}
	if version := strings.TrimSpace(device.ClientVersion); version != "" {
		return version, "enroll"
	}
	return "", ""
}

func computeUpdateAvailable(hasLive bool, liveVC int64, apkPublished bool, release apkReleaseRecord) (bool, string) {
	if !apkPublished || !hasLive || liveVC <= 0 || liveVC >= release.VersionCode {
		return false, ""
	}
	return true, release.VersionName
}

func apkSyncState(worker workerRecord, release apkReleaseRecord, published bool) string {
	if !published {
		return "unknown"
	}
	apk, ok := worker.SelfDescribe["distributed_apk"].(map[string]any)
	if !ok || len(apk) == 0 {
		return "unknown"
	}
	sha := stringFromMap(apk, "apk_sha256")
	versionCode := int64FromAny(apk["version_code"])
	if sha != "" {
		if strings.EqualFold(sha, release.APKSHA256) {
			return "ok"
		}
		return "lag"
	}
	if versionCode > 0 && versionCode == release.VersionCode {
		return "ok"
	}
	return "lag"
}

func apkSyncText(worker workerRecord, release apkReleaseRecord, published bool) string {
	if !published {
		return "нет published APK"
	}
	apk, ok := worker.SelfDescribe["distributed_apk"].(map[string]any)
	if !ok || len(apk) == 0 {
		return "нет данных"
	}
	versionCode := int64FromAny(apk["version_code"])
	if apkSyncState(worker, release, published) == "ok" {
		return "APK актуален"
	}
	if sha := stringFromMap(apk, "apk_sha256"); sha != "" {
		return "отстаёт (worker sha " + shortString(sha, 12) + " / published " + shortString(release.APKSHA256, 12) + ")"
	}
	if versionCode > 0 {
		return "отстаёт (worker v" + strconv.FormatInt(versionCode, 10) + " / published v" + strconv.FormatInt(release.VersionCode, 10) + ")"
	}
	return "отстаёт"
}

func firstNotBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
