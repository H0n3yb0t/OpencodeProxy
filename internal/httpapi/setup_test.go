package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/local/opencode-keypool/internal/config"
	"github.com/local/opencode-keypool/internal/identity"
	"github.com/local/opencode-keypool/internal/proxy"
	"github.com/local/opencode-keypool/internal/store"
)

func TestWebSetupPersistsAndRotatesProxyToken(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DatabasePath:    filepath.Join(dir, "openpool.db"),
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
}
