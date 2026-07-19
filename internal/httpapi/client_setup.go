package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
)

const enrollmentTTL = 10 * time.Minute

//go:embed client-install.ps1
var clientInstallPowerShellScript []byte

//go:embed client-install.sh
var clientInstallShellScript []byte

type enrollment struct {
	name      string
	expiresAt time.Time
}

type enrollmentStore struct {
	mu      sync.Mutex
	tickets map[[32]byte]enrollment
}

func newEnrollmentStore() *enrollmentStore {
	return &enrollmentStore{tickets: make(map[[32]byte]enrollment)}
}

func (s *enrollmentStore) create(name string) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(ticket))
	expiresAt := time.Now().UTC().Add(enrollmentTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, item := range s.tickets {
		if time.Now().UTC().After(item.expiresAt) {
			delete(s.tickets, key)
		}
	}
	s.tickets[hash] = enrollment{name: name, expiresAt: expiresAt}
	return ticket, expiresAt, nil
}

func (s *enrollmentStore) consume(ticket string) (enrollment, bool) {
	hash := sha256.Sum256([]byte(ticket))
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.tickets[hash]
	if !ok {
		return enrollment{}, false
	}
	delete(s.tickets, hash)
	if time.Now().UTC().After(item.expiresAt) {
		return enrollment{}, false
	}
	return item, true
}

func (a *API) clientInstallPowerShell(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(clientInstallPowerShellScript)
}

func (a *API) clientInstallShell(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(clientInstallShellScript)
}

func (a *API) createClientEnrollment(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		input.Name = "OpenCode client"
	}
	if utf8.RuneCountInString(input.Name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "client name is too long"})
		return
	}
	ticket, expiresAt, err := a.enrollments.create(input.Name)
	if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": ticket, "expires_at": expiresAt})
}

func (a *API) clientEnroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.identity.Initialized() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "instance setup is required"})
		return
	}
	var input struct {
		Ticket  string `json:"ticket"`
		BaseURL string `json:"base_url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	baseURL, err := normalizeClientBaseURL(input.BaseURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "base_url must be an HTTP or HTTPS origin"})
		return
	}
	item, ok := a.enrollments.consume(strings.TrimSpace(input.Ticket))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "pairing ticket is invalid, expired, or already used"})
		return
	}
	client, token, err := a.identity.IssueClientToken(item.name)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client":        client,
		"proxy_token":   token,
		"default_model": "opencodeproxy-openai/mimo-v2.5",
		"providers":     clientProviders(baseURL + "/v1"),
	})
}

func normalizeClientBaseURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", http.ErrNotSupported
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (a *API) listClientTokens(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tokens": a.identity.ListClientTokens()})
}

func (a *API) createClientToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || utf8.RuneCountInString(name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "client name must contain 1 to 80 characters"})
		return
	}
	client, token, err := a.identity.IssueClientToken(name)
	if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"client": client, "proxy_token": token})
}

func (a *API) renameClientToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	client, err := a.identity.RenameClientToken(chi.URLParam(r, "id"), input.Name)
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client token not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := a.store.RenameRequestClient(r.Context(), client.ID, client.Name); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (a *API) revokeClientToken(w http.ResponseWriter, r *http.Request) {
	err := a.identity.RevokeClientToken(chi.URLParam(r, "id"))
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client token not found"})
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type clientDashboardItem struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	Requests      int64     `json:"requests"`
	Successes     int64     `json:"successes"`
	Failures      int64     `json:"failures"`
	Failovers     int64     `json:"failovers"`
	InputUncached int64     `json:"input_uncached"`
	CacheRead     int64     `json:"cache_read"`
	CacheWrite    int64     `json:"cache_write"`
	OutputTokens  int64     `json:"output_tokens"`
	UsageComplete int64     `json:"usage_complete"`
	AvgLatencyMS  int64     `json:"avg_latency_ms"`
}

func (a *API) clientDashboard(w http.ResponseWriter, r *http.Request) {
	aggregates, err := a.store.ClientAggregates(r.Context(), time.Now().Add(-dashboardWindow(r.URL.Query().Get("window"))))
	if err != nil {
		serverError(w, err)
		return
	}
	byID := make(map[string]clientDashboardItem, len(aggregates))
	for _, aggregate := range aggregates {
		byID[aggregate.ClientID] = clientDashboardItem{
			ID: aggregate.ClientID, Name: aggregate.ClientName, Kind: "client",
			Requests: aggregate.Requests, Successes: aggregate.Successes, Failures: aggregate.Failures, Failovers: aggregate.Failovers,
			InputUncached: aggregate.InputUncached, CacheRead: aggregate.CacheRead, CacheWrite: aggregate.CacheWrite,
			OutputTokens: aggregate.OutputTokens, UsageComplete: aggregate.UsageComplete, AvgLatencyMS: aggregate.AvgLatencyMS,
		}
	}
	master := byID["master"]
	master.ID, master.Name, master.Kind, master.Active = "master", "主访问密钥", "master", true
	delete(byID, "master")
	items := []clientDashboardItem{master}
	for _, client := range a.identity.ListClientTokens() {
		item := byID[client.ID]
		item.ID, item.Name, item.Kind, item.Active, item.CreatedAt = client.ID, client.Name, "client", true, client.CreatedAt
		items = append(items, item)
		delete(byID, client.ID)
	}
	for _, item := range byID {
		item.Kind = "client"
		item.Active = false
		items = append(items, item)
	}
	sort.SliceStable(items[1:], func(i, j int) bool {
		return items[i+1].Name < items[j+1].Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"clients": items})
}

func clientProviders(baseURL string) map[string]any {
	openAIModels := map[string]any{}
	for id, name := range map[string]string{
		"grok-4.5": "Grok 4.5", "glm-5.2": "GLM-5.2", "glm-5.1": "GLM-5.1",
		"kimi-k3": "Kimi K3", "kimi-k2.7-code": "Kimi K2.7 Code", "kimi-k2.6": "Kimi K2.6",
		"deepseek-v4-pro": "DeepSeek V4 Pro", "deepseek-v4-flash": "DeepSeek V4 Flash",
		"mimo-v2.5": "MiMo-V2.5", "mimo-v2.5-pro": "MiMo-V2.5-Pro",
	} {
		openAIModels[id] = map[string]any{"name": name}
	}
	anthropicModels := map[string]any{}
	for id, name := range map[string]string{
		"minimax-m3": "MiniMax M3", "minimax-m2.7": "MiniMax M2.7", "minimax-m2.5": "MiniMax M2.5",
		"qwen3.7-max": "Qwen3.7 Max", "qwen3.7-plus": "Qwen3.7 Plus", "qwen3.6-plus": "Qwen3.6 Plus",
	} {
		anthropicModels[id] = map[string]any{"name": name}
	}
	options := func() map[string]any {
		return map[string]any{
			"baseURL": baseURL,
			"apiKey":  "{file:~/.config/opencode/opencodeproxy.token}",
			"timeout": 600000,
		}
	}
	return map[string]any{
		"opencodeproxy-openai": map[string]any{
			"npm": "@ai-sdk/openai-compatible", "name": "OpencodeProxy", "options": options(), "models": openAIModels,
		},
		"opencodeproxy-anthropic": map[string]any{
			"npm": "@ai-sdk/anthropic", "name": "OpencodeProxy (Messages)", "options": options(), "models": anthropicModels,
		},
	}
}
