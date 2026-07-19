package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/local/opencode-keypool/internal/config"
	"github.com/local/opencode-keypool/internal/cryptox"
	"github.com/local/opencode-keypool/internal/identity"
	"github.com/local/opencode-keypool/internal/store"
)

func TestFailoverAndModelsDuringQuotaCooling(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if r.URL.Path == "/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"mimo-v2.5"}]}`)
			return
		}
		if secret == "first-key" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"message":"5 hour usage limit reached. It will reset in 2 hours 16 minutes."}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":80},"completion_tokens":2,"total_tokens":102}}`)
	}))
	defer upstream.Close()

	db, identityManager, service := testService(t, upstream.URL)
	first := addTestKey(t, db, identityManager, "First", "first-key", 1)
	second := addTestKey(t, db, identityManager, "Second", "second-key", 2)
	if err := db.SetActive(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"mimo-v2.5","messages":[{"role":"user","content":"OK"}]}`))
	response := httptest.NewRecorder()
	service.HandleInference("openai")(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"OK"`) {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	firstAfter, _ := db.KeyByID(context.Background(), first.ID)
	secondAfter, _ := db.KeyByID(context.Background(), second.ID)
	if firstAfter.QuotaState != "cooling" || firstAfter.QuotaWindow != "5h" || firstAfter.CoolingUntil == nil {
		t.Fatalf("first state=%#v", firstAfter)
	}
	if secondAfter.PoolRole != "active" || secondAfter.QuotaState != "available" {
		t.Fatalf("second state=%#v", secondAfter)
	}
	requests, err := db.RecentRequests(context.Background(), 10, 0, "")
	if err != nil || len(requests) != 1 {
		t.Fatalf("requests=%#v err=%v", requests, err)
	}
	if requests[0].AttemptCount != 2 || value(requests[0].CacheRead) != 80 || value(requests[0].InputUncached) != 20 {
		t.Fatalf("telemetry=%#v", requests[0])
	}

	// The only credential used for this call is cooling. Models must still work.
	if _, err := db.UpdateKey(context.Background(), second.ID, secondAfter.Name, secondAfter.Priority, false, nil); err != nil {
		t.Fatal(err)
	}
	modelsResponse := httptest.NewRecorder()
	service.HandleModels(modelsResponse, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if modelsResponse.Code != http.StatusOK || !strings.Contains(modelsResponse.Body.String(), "mimo-v2.5") {
		t.Fatalf("models=%d %s", modelsResponse.Code, modelsResponse.Body.String())
	}
}

func TestStreamingFirstErrorFailsOverBeforeClientBytes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if secret == "stream-first" {
			_, _ = io.WriteString(w, "data: {\"error\":{\"message\":\"5 hour usage limit reached. It will reset in 1 hour.\"}}\n\n")
			return
		}
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"prompt_tokens_details\":{\"cached_tokens\":40},\"completion_tokens\":2,\"total_tokens\":52}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	db, identityManager, service := testService(t, upstream.URL)
	first := addTestKey(t, db, identityManager, "Stream first", "stream-first", 1)
	second := addTestKey(t, db, identityManager, "Stream second", "stream-second", 2)
	if err := db.SetActive(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"mimo-v2.5","stream":true,"messages":[{"role":"user","content":"OK"}]}`))
	response := httptest.NewRecorder()
	service.HandleInference("openai")(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"content":"OK"`) || strings.Contains(response.Body.String(), "limit reached") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	firstAfter, _ := db.KeyByID(context.Background(), first.ID)
	secondAfter, _ := db.KeyByID(context.Background(), second.ID)
	if firstAfter.QuotaState != "cooling" || secondAfter.PoolRole != "active" {
		t.Fatalf("first=%#v second=%#v", firstAfter, secondAfter)
	}
	requests, err := db.RecentRequests(context.Background(), 10, 0, "")
	if err != nil || len(requests) != 1 || requests[0].AttemptCount != 2 || value(requests[0].CacheRead) != 40 {
		t.Fatalf("requests=%#v err=%v", requests, err)
	}
}

func testService(t *testing.T, upstream string) (*store.Store, *identity.Manager, *Service) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	identityManager, err := identity.Open(filepath.Join(t.TempDir(), "instance.json"), key, "test-admin", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{UpstreamBaseURL: upstream, RequestTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxRequestBytes: 1 << 20, MasterKey: key, AdminPassword: "test", BootstrapToken: "test", DatabasePath: filepath.Join(t.TempDir(), "unused.db")}
	return db, identityManager, NewService(cfg, db, identityManager)
}

func addTestKey(t *testing.T, db *store.Store, identityManager *identity.Manager, name, secret string, priority int) store.Key {
	t.Helper()
	encrypted, err := identityManager.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	key, err := db.CreateKey(context.Background(), store.Key{Name: name, EncryptedKey: encrypted, Fingerprint: cryptox.Fingerprint(secret), Priority: priority, AdminEnabled: true, AuthState: "valid", QuotaState: "available", ControlState: "reachable"})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
