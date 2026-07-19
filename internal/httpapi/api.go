package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/H0n3yb0t/OpencodeProxy/internal/config"
	"github.com/H0n3yb0t/OpencodeProxy/internal/cryptox"
	"github.com/H0n3yb0t/OpencodeProxy/internal/identity"
	"github.com/H0n3yb0t/OpencodeProxy/internal/proxy"
	"github.com/H0n3yb0t/OpencodeProxy/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type API struct {
	cfg         config.Config
	store       *store.Store
	identity    *identity.Manager
	proxy       *proxy.Service
	sessions    *sessionStore
	enrollments *enrollmentStore
}

func New(cfg config.Config, db *store.Store, identityManager *identity.Manager, proxyService *proxy.Service) *API {
	return &API{cfg: cfg, store: db, identity: identityManager, proxy: proxyService, sessions: newSessionStore(), enrollments: newEnrollmentStore()}
}

func (a *API) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.RequestID, middleware.Recoverer)
	r.Use(a.securityHeaders)
	r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"status": "ok"}) })
	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.store.GetSettings(r.Context()); err != nil {
			writeJSON(w, 503, map[string]any{"status": "not_ready"})
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ready", "initialized": a.identity.Initialized()})
	})
	r.Get("/api/setup/status", a.setupStatus)
	r.Post("/api/setup/initialize", a.setupInitialize)
	r.Get("/api/client/install.ps1", a.clientInstallPowerShell)
	r.Get("/api/client/install.sh", a.clientInstallShell)
	r.Post("/api/client/enroll", a.clientEnroll)
	r.Group(func(p chi.Router) {
		p.Use(a.proxyAuth)
		p.Get("/v1/models", a.proxy.HandleModels)
		p.Post("/v1/chat/completions", a.proxy.HandleInference("openai"))
		p.Post("/v1/messages", a.proxy.HandleInference("anthropic"))
	})
	r.Post("/api/admin/login", a.login)
	r.Group(func(admin chi.Router) {
		admin.Use(a.adminAuth)
		admin.Get("/api/admin/me", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"authenticated": true}) })
		admin.Post("/api/admin/logout", a.logout)
		admin.Get("/api/admin/keys", a.listKeys)
		admin.Post("/api/admin/keys", a.createKey)
		admin.Post("/api/admin/keys/import", a.importKeys)
		admin.Patch("/api/admin/keys/{id}", a.updateKey)
		admin.Delete("/api/admin/keys/{id}", a.deleteKey)
		admin.Post("/api/admin/keys/{id}/activate", a.activateKey)
		admin.Post("/api/admin/keys/{id}/test", a.testKey)
		admin.Get("/api/admin/settings", a.getSettings)
		admin.Put("/api/admin/settings", a.updateSettings)
		admin.Post("/api/admin/proxy-token/rotate", a.rotateProxyToken)
		admin.Get("/api/admin/client-tokens", a.listClientTokens)
		admin.Post("/api/admin/client-enrollments", a.createClientEnrollment)
		admin.Delete("/api/admin/client-tokens/{id}", a.revokeClientToken)
		admin.Get("/api/admin/requests", a.requests)
		admin.Get("/api/admin/dashboard", a.dashboard)
		admin.Get("/api/admin/stream", a.events)
	})
	r.Handle("/*", a.webHandler())
	return r
}

func (a *API) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if !a.identity.Initialized() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "instance setup is required", "setup_required": true})
		return
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || !a.identity.VerifyAdmin(input.Password) {
		writeJSON(w, 401, map[string]any{"error": "invalid password"})
		return
	}
	token := a.sessions.create()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int((12 * time.Hour).Seconds())})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) setupStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"initialized": a.identity.Initialized()})
}

func (a *API) setupInitialize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Hide the bootstrap endpoint completely after an identity exists. This
	// check is only an early rejection; Manager.Initialize performs the
	// authoritative check while holding its lock to close concurrent races.
	if a.identity.Initialized() {
		http.NotFound(w, r)
		return
	}
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
		return
	}
	secrets, err := a.identity.Initialize()
	if errors.Is(err, identity.ErrAlreadyInitialized) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	token := a.sessions.create()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int((12 * time.Hour).Seconds())})
	writeJSON(w, http.StatusCreated, map[string]any{"initialized": true, "secrets": secrets})
}

func (a *API) rotateProxyToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, err := a.identity.RotateProxyToken()
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxy_token": token})
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.store.ListKeys(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"keys": keys})
}
func (a *API) createKey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name          string `json:"name"`
		Key           string `json:"key"`
		Priority      int    `json:"priority"`
		TestInference bool   `json:"test_inference"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || strings.TrimSpace(input.Key) == "" {
		writeJSON(w, 400, map[string]any{"error": "key is required"})
		return
	}
	if input.Priority == 0 {
		input.Priority = 100
	}
	key, err := a.persistKey(r.Context(), input.Name, input.Key, input.Priority)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, 409, map[string]any{"error": "key already exists"})
			return
		}
		serverError(w, err)
		return
	}
	result, testErr := a.proxy.TestKey(r.Context(), key, input.TestInference)
	if testErr != nil {
		result = map[string]any{"ok": false, "message": testErr.Error()}
	}
	fresh, _ := a.store.KeyByID(r.Context(), key.ID)
	writeJSON(w, 201, map[string]any{"key": fresh, "test": result})
}

const maxImportKeys = 100

type keyImportResult struct {
	Line        int            `json:"line"`
	Name        string         `json:"name"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Key         *store.Key     `json:"key,omitempty"`
	Test        map[string]any `json:"test,omitempty"`
}

func (a *API) importKeys(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Keys          []string `json:"keys"`
		NamePrefix    string   `json:"name_prefix"`
		Priority      int      `json:"priority"`
		Validate      bool     `json:"validate"`
		TestInference bool     `json:"test_inference"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if len(input.Keys) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "at least one key is required"})
		return
	}
	if len(input.Keys) > maxImportKeys {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "at most 100 keys can be imported at once"})
		return
	}
	if input.Priority == 0 {
		input.Priority = 100
	}
	prefix := strings.TrimSpace(input.NamePrefix)
	seen := make(map[string]struct{}, len(input.Keys))
	results := make([]keyImportResult, 0, len(input.Keys))
	imported, duplicates, failed := 0, 0, 0

	for index, raw := range input.Keys {
		line := index + 1
		secret := strings.TrimSpace(raw)
		result := keyImportResult{Line: line, Status: "failed"}
		if secret == "" {
			result.Error = "empty key"
			failed++
			results = append(results, result)
			continue
		}
		if len(secret) > 4096 {
			result.Error = "key is too long"
			failed++
			results = append(results, result)
			continue
		}
		result.Fingerprint = cryptox.Fingerprint(secret)
		if _, exists := seen[result.Fingerprint]; exists {
			result.Status = "duplicate"
			result.Error = "duplicate key in this import"
			duplicates++
			results = append(results, result)
			continue
		}
		seen[result.Fingerprint] = struct{}{}
		name := prefix
		if name == "" {
			name = "Key " + result.Fingerprint
		} else if len(input.Keys) > 1 {
			name = fmt.Sprintf("%s %02d", name, line)
		}
		result.Name = name
		key, err := a.persistKey(r.Context(), name, secret, input.Priority+index)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				result.Status = "duplicate"
				result.Error = "key already exists"
				duplicates++
			} else {
				result.Error = "could not save key"
				failed++
			}
			results = append(results, result)
			continue
		}
		result.Status = "imported"
		if input.Validate || input.TestInference {
			testResult, testErr := a.proxy.TestKey(r.Context(), key, input.TestInference)
			if testErr != nil {
				result.Test = map[string]any{"ok": false, "message": testErr.Error()}
			} else {
				result.Test = testResult
			}
		}
		fresh, err := a.store.KeyByID(r.Context(), key.ID)
		if err == nil {
			result.Key = &fresh
		}
		imported++
		results = append(results, result)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(input.Keys),
		"imported":   imported,
		"duplicates": duplicates,
		"failed":     failed,
		"results":    results,
	})
}

func (a *API) persistKey(ctx context.Context, name, rawKey string, priority int) (store.Key, error) {
	secret := strings.TrimSpace(rawKey)
	fingerprint := cryptox.Fingerprint(secret)
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Key " + fingerprint
	}
	encrypted, err := a.identity.Encrypt(secret)
	if err != nil {
		return store.Key{}, err
	}
	return a.store.CreateKey(ctx, store.Key{
		Name:         name,
		EncryptedKey: encrypted,
		Fingerprint:  fingerprint,
		Priority:     priority,
		AdminEnabled: true,
		AuthState:    "unknown",
		QuotaState:   "unknown",
		ControlState: "unknown",
	})
}

func (a *API) updateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	current, err := a.store.KeyByID(r.Context(), id)
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	var input struct {
		Name          *string `json:"name"`
		Priority      *int    `json:"priority"`
		AdminEnabled  *bool   `json:"admin_enabled"`
		AutoProbeMode *string `json:"auto_probe_mode"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	name, priority, enabled := current.Name, current.Priority, current.AdminEnabled
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
	}
	if input.Priority != nil {
		priority = *input.Priority
	}
	if input.AdminEnabled != nil {
		enabled = *input.AdminEnabled
	}
	override := current.AutoProbeOverride
	if input.AutoProbeMode != nil {
		switch *input.AutoProbeMode {
		case "inherit":
			override = nil
		case "enabled":
			v := true
			override = &v
		case "disabled":
			v := false
			override = &v
		default:
			writeJSON(w, 400, map[string]any{"error": "auto_probe_mode must be inherit, enabled, or disabled"})
			return
		}
	}
	updated, err := a.store.UpdateKey(r.Context(), id, name, priority, enabled, override)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"key": updated})
}
func (a *API) deleteKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.store.DeleteKey(r.Context(), id); err != nil {
		serverError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) activateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	key, err := a.store.KeyByID(r.Context(), id)
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	if !key.AdminEnabled || key.AuthState == "invalid" || key.QuotaState == "cooling" {
		writeJSON(w, 409, map[string]any{"error": "key is not eligible for activation"})
		return
	}
	if err := a.store.SetActive(r.Context(), id); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (a *API) testKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	key, err := a.store.KeyByID(r.Context(), id)
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	var input struct {
		Inference bool `json:"inference"`
	}
	_ = json.NewDecoder(r.Body).Decode(&input)
	result, err := a.proxy.TestKey(r.Context(), key, input.Inference)
	if err != nil {
		writeJSON(w, 502, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}
func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.GetSettings(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (a *API) updateSettings(w http.ResponseWriter, r *http.Request) {
	var v store.Settings
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if v.ProbeModel == "" || v.ProbeIntervalSec < 60 || v.ModelsCacheSec < 30 {
		writeJSON(w, 400, map[string]any{"error": "invalid settings"})
		return
	}
	if err := a.store.UpdateSettings(r.Context(), v); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (a *API) requests(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	keyID, _ := strconv.ParseInt(r.URL.Query().Get("key_id"), 10, 64)
	items, err := a.store.RecentRequests(r.Context(), limit, keyID, r.URL.Query().Get("model"))
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"requests": items})
}
func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	duration := 5 * time.Hour
	switch r.URL.Query().Get("window") {
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	}
	d, err := a.store.Dashboard(r.Context(), time.Now().Add(-duration))
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, d)
}
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]any{"error": "streaming unsupported"})
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		_, _ = w.Write([]byte("event: tick\ndata: {}\n\n"))
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *API) webHandler() http.Handler {
	root := a.cfg.WebDir
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(filepath.Clean(r.URL.Path), string(filepath.Separator))
		if path == "." || path == "" {
			path = "index.html"
		}
		full := filepath.Join(root, path)
		if info, err := os.Stat(full); err != nil || info.IsDir() {
			full = filepath.Join(root, "index.html")
		}
		if ext := filepath.Ext(full); ext != "" {
			if t := mime.TypeByExtension(ext); t != "" {
				w.Header().Set("Content-Type", t)
			}
		}
		http.ServeFile(w, r, full)
	})
}
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid id"})
		return 0, false
	}
	return id, true
}
func notFoundOrError(w http.ResponseWriter, err error) {
	if store.IsNotFound(err) {
		writeJSON(w, 404, map[string]any{"error": "not found"})
	} else {
		serverError(w, err)
	}
}
func serverError(w http.ResponseWriter, err error) {
	slog.Error("admin API", "error", err)
	writeJSON(w, 500, map[string]any{"error": "internal server error"})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
