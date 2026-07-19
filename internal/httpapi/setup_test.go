package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/H0n3yb0t/OpencodeProxy/internal/config"
	"github.com/H0n3yb0t/OpencodeProxy/internal/identity"
	"github.com/H0n3yb0t/OpencodeProxy/internal/proxy"
	"github.com/H0n3yb0t/OpencodeProxy/internal/store"
)

func TestWebSetupPersistsAndRotatesProxyToken(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DatabasePath:    filepath.Join(dir, "opencodeproxy.db"),
		InstancePath:    filepath.Join(dir, "instance.json"),
		UpstreamBaseURL: "https://opencode.ai/zen/go/v1",
		RequestTimeout:  time.Second,
		IdleTimeout:     time.Minute,
		MaxRequestBytes: 1 << 20,
		EventRetention:  time.Hour,
		WebDir:          dir,
	}
	db, err := store.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	identityManager, err := identity.Open(cfg.InstancePath, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	router := New(cfg, db, identityManager, proxy.NewService(cfg, db, identityManager)).Router()

	status := httptest.NewRecorder()
	router.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"initialized":false`)) {
		t.Fatalf("status=%d %s", status.Code, status.Body.String())
	}

	initialized := httptest.NewRecorder()
	router.ServeHTTP(initialized, httptest.NewRequest(http.MethodPost, "/api/setup/initialize", nil))
	if initialized.Code != http.StatusCreated {
		t.Fatalf("initialize=%d %s", initialized.Code, initialized.Body.String())
	}
	var payload struct {
		Secrets identity.Secrets `json:"secrets"`
	}
	if err := json.Unmarshal(initialized.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Secrets.AdminPassword == "" || payload.Secrets.ProxyToken == "" {
		t.Fatalf("missing secrets: %#v", payload)
	}

	// Refreshing or calling the bootstrap endpoint directly must neither rotate
	// nor disclose any credential once initialization has succeeded.
	repeated := httptest.NewRecorder()
	router.ServeHTTP(repeated, httptest.NewRequest(http.MethodPost, "/api/setup/initialize", nil))
	if repeated.Code != http.StatusNotFound {
		t.Fatalf("repeated initialize=%d %s", repeated.Code, repeated.Body.String())
	}
	if bytes.Contains(repeated.Body.Bytes(), []byte("admin_password")) ||
		bytes.Contains(repeated.Body.Bytes(), []byte("proxy_token")) ||
		bytes.Contains(repeated.Body.Bytes(), []byte("recovery_key")) {
		t.Fatalf("repeated initialization disclosed credentials: %s", repeated.Body.String())
	}
	if !identityManager.VerifyAdmin(payload.Secrets.AdminPassword) || !identityManager.VerifyProxy(payload.Secrets.ProxyToken) {
		t.Fatal("repeated initialization changed the original credentials")
	}
	cookies := initialized.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setup did not create an admin session")
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/api/admin/me", nil)
	meRequest.AddCookie(cookies[0])
	me := httptest.NewRecorder()
	router.ServeHTTP(me, meRequest)
	if me.Code != http.StatusOK {
		t.Fatalf("me=%d %s", me.Code, me.Body.String())
	}

	// Empty collections are encoded as JSON arrays rather than null so a fresh
	// installation can render the dashboard before its first key or request.
	for path, fields := range map[string][]string{
		"/api/admin/dashboard?window=5h": {`"timeline":[]`, `"by_key":[]`},
		"/api/admin/keys":                {`"keys":[]`},
		"/api/admin/requests?limit=100":  {`"requests":[]`},
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.AddCookie(cookies[0])
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s=%d %s", path, response.Code, response.Body.String())
		}
		for _, field := range fields {
			if !bytes.Contains(response.Body.Bytes(), []byte(field)) {
				t.Fatalf("GET %s did not encode empty array %s: %s", path, field, response.Body.String())
			}
		}
	}

	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/admin/proxy-token/rotate", nil)
	rotateRequest.AddCookie(cookies[0])
	rotatedResponse := httptest.NewRecorder()
	router.ServeHTTP(rotatedResponse, rotateRequest)
	if rotatedResponse.Code != http.StatusOK {
		t.Fatalf("rotate=%d %s", rotatedResponse.Code, rotatedResponse.Body.String())
	}
	var rotated struct {
		ProxyToken string `json:"proxy_token"`
	}
	_ = json.Unmarshal(rotatedResponse.Body.Bytes(), &rotated)
	if rotated.ProxyToken == "" || rotated.ProxyToken == payload.Secrets.ProxyToken {
		t.Fatal("token was not rotated")
	}

	oldTokenRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	oldTokenRequest.Header.Set("Authorization", "Bearer "+payload.Secrets.ProxyToken)
	oldTokenResponse := httptest.NewRecorder()
	router.ServeHTTP(oldTokenResponse, oldTokenRequest)
	if oldTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old token status=%d", oldTokenResponse.Code)
	}
	newTokenRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	newTokenRequest.Header.Set("Authorization", "Bearer "+rotated.ProxyToken)
	newTokenResponse := httptest.NewRecorder()
	router.ServeHTTP(newTokenResponse, newTokenRequest)
	if newTokenResponse.Code == http.StatusUnauthorized {
		t.Fatal("new token was rejected")
	}

	reloadedIdentity, err := identity.Open(cfg.InstancePath, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(cfg, db, reloadedIdentity, proxy.NewService(cfg, db, reloadedIdentity)).Router()
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBufferString(`{"password":"`+payload.Secrets.AdminPassword+`"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	restarted.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("restart login=%d %s", loginResponse.Code, loginResponse.Body.String())
	}
	loginCookies := loginResponse.Result().Cookies()
	if len(loginCookies) == 0 {
		t.Fatal("login did not create a session")
	}

	batchBody := []byte(`{"keys":["batch-secret-one","batch-secret-two","batch-secret-one"],"name_prefix":"Imported","priority":20,"validate":false}`)
	batchRequest := httptest.NewRequest(http.MethodPost, "/api/admin/keys/import", bytes.NewReader(batchBody))
	batchRequest.Header.Set("Content-Type", "application/json")
	batchRequest.AddCookie(loginCookies[0])
	batchResponse := httptest.NewRecorder()
	restarted.ServeHTTP(batchResponse, batchRequest)
	if batchResponse.Code != http.StatusOK {
		t.Fatalf("batch import=%d %s", batchResponse.Code, batchResponse.Body.String())
	}
	if bytes.Contains(batchResponse.Body.Bytes(), []byte("batch-secret")) {
		t.Fatalf("batch response disclosed a plaintext key: %s", batchResponse.Body.String())
	}
	var batchResult struct {
		Total      int `json:"total"`
		Imported   int `json:"imported"`
		Duplicates int `json:"duplicates"`
		Failed     int `json:"failed"`
		Results    []struct {
			Line   int    `json:"line"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(batchResponse.Body.Bytes(), &batchResult); err != nil {
		t.Fatal(err)
	}
	if batchResult.Total != 3 || batchResult.Imported != 2 || batchResult.Duplicates != 1 || batchResult.Failed != 0 {
		t.Fatalf("unexpected batch result: %#v", batchResult)
	}
	keys, err := db.ListKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Name != "Imported 01" || keys[0].Priority != 20 || keys[1].Name != "Imported 02" || keys[1].Priority != 21 {
		t.Fatalf("unexpected imported keys: %#v", keys)
	}
}
