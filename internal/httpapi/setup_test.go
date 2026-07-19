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

func TestWebSetupPersistsUnifiedAccessAndClientTokens(t *testing.T) {
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
	if payload.Secrets.AccessKey == "" || payload.Secrets.RecoveryKey == "" {
		t.Fatalf("missing secrets: %#v", payload)
	}

	// Refreshing or calling the bootstrap endpoint directly must neither rotate
	// nor disclose any credential once initialization has succeeded.
	repeated := httptest.NewRecorder()
	router.ServeHTTP(repeated, httptest.NewRequest(http.MethodPost, "/api/setup/initialize", nil))
	if repeated.Code != http.StatusNotFound {
		t.Fatalf("repeated initialize=%d %s", repeated.Code, repeated.Body.String())
	}
	if bytes.Contains(repeated.Body.Bytes(), []byte("access_key")) ||
		bytes.Contains(repeated.Body.Bytes(), []byte("recovery_key")) {
		t.Fatalf("repeated initialization disclosed credentials: %s", repeated.Body.String())
	}
	if !identityManager.VerifyAdmin(payload.Secrets.AccessKey) || !identityManager.VerifyProxy(payload.Secrets.AccessKey) {
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

	enrollmentRequest := httptest.NewRequest(http.MethodPost, "/api/admin/client-enrollments", bytes.NewBufferString(`{"name":"Windows workstation"}`))
	enrollmentRequest.Header.Set("Content-Type", "application/json")
	enrollmentRequest.AddCookie(cookies[0])
	enrollmentResponse := httptest.NewRecorder()
	router.ServeHTTP(enrollmentResponse, enrollmentRequest)
	if enrollmentResponse.Code != http.StatusCreated {
		t.Fatalf("create client enrollment=%d %s", enrollmentResponse.Code, enrollmentResponse.Body.String())
	}
	var enrollment struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(enrollmentResponse.Body.Bytes(), &enrollment); err != nil || enrollment.Ticket == "" {
		t.Fatalf("invalid enrollment response: %v %s", err, enrollmentResponse.Body.String())
	}

	enrollBody, _ := json.Marshal(map[string]string{"ticket": enrollment.Ticket, "base_url": "http://proxy.test:8080"})
	enrollRequest := httptest.NewRequest(http.MethodPost, "/api/client/enroll", bytes.NewReader(enrollBody))
	enrollRequest.Header.Set("Content-Type", "application/json")
	enrollResponse := httptest.NewRecorder()
	router.ServeHTTP(enrollResponse, enrollRequest)
	if enrollResponse.Code != http.StatusCreated {
		t.Fatalf("client enroll=%d %s", enrollResponse.Code, enrollResponse.Body.String())
	}
	var clientPayload struct {
		ProxyToken string               `json:"proxy_token"`
		Client     identity.ClientToken `json:"client"`
		Providers  map[string]any       `json:"providers"`
	}
	if err := json.Unmarshal(enrollResponse.Body.Bytes(), &clientPayload); err != nil {
		t.Fatal(err)
	}
	if clientPayload.ProxyToken == "" || clientPayload.Client.ID == "" || len(clientPayload.Providers) != 2 || !identityManager.VerifyProxy(clientPayload.ProxyToken) {
		t.Fatalf("invalid client enrollment payload: %#v", clientPayload)
	}

	reusedRequest := httptest.NewRequest(http.MethodPost, "/api/client/enroll", bytes.NewReader(enrollBody))
	reusedResponse := httptest.NewRecorder()
	router.ServeHTTP(reusedResponse, reusedRequest)
	if reusedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("reused enrollment=%d %s", reusedResponse.Code, reusedResponse.Body.String())
	}

	clientAuthRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	clientAuthRequest.Header.Set("Authorization", "Bearer "+clientPayload.ProxyToken)
	clientAuthResponse := httptest.NewRecorder()
	router.ServeHTTP(clientAuthResponse, clientAuthRequest)
	if clientAuthResponse.Code == http.StatusUnauthorized {
		t.Fatal("issued client token was rejected")
	}

	revokeRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/client-tokens/"+clientPayload.Client.ID, nil)
	revokeRequest.AddCookie(cookies[0])
	revokeResponse := httptest.NewRecorder()
	router.ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke client token=%d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	clientAuthAfterRevoke := httptest.NewRecorder()
	router.ServeHTTP(clientAuthAfterRevoke, clientAuthRequest)
	if clientAuthAfterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked client token status=%d", clientAuthAfterRevoke.Code)
	}

	manualRequest := httptest.NewRequest(http.MethodPost, "/api/admin/client-tokens", bytes.NewBufferString(`{"name":"manual client"}`))
	manualRequest.Header.Set("Content-Type", "application/json")
	manualRequest.AddCookie(cookies[0])
	manualResponse := httptest.NewRecorder()
	router.ServeHTTP(manualResponse, manualRequest)
	if manualResponse.Code != http.StatusCreated {
		t.Fatalf("manual client=%d %s", manualResponse.Code, manualResponse.Body.String())
	}
	var manualClient struct {
		Client     identity.ClientToken `json:"client"`
		ProxyToken string               `json:"proxy_token"`
	}
	if err := json.Unmarshal(manualResponse.Body.Bytes(), &manualClient); err != nil || manualClient.ProxyToken == "" {
		t.Fatalf("invalid manual client response: %v %s", err, manualResponse.Body.String())
	}
	renameRequest := httptest.NewRequest(http.MethodPatch, "/api/admin/client-tokens/"+manualClient.Client.ID, bytes.NewBufferString(`{"name":"renamed client"}`))
	renameRequest.Header.Set("Content-Type", "application/json")
	renameRequest.AddCookie(cookies[0])
	renameResponse := httptest.NewRecorder()
	router.ServeHTTP(renameResponse, renameRequest)
	if renameResponse.Code != http.StatusOK || !bytes.Contains(renameResponse.Body.Bytes(), []byte("renamed client")) {
		t.Fatalf("rename client=%d %s", renameResponse.Code, renameResponse.Body.String())
	}
	clientInference := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"mimo-v2.5","messages":[{"role":"user","content":"OK"}]}`))
	clientInference.Header.Set("Authorization", "Bearer "+manualClient.ProxyToken)
	clientInferenceResponse := httptest.NewRecorder()
	router.ServeHTTP(clientInferenceResponse, clientInference)
	clientDashboardRequest := httptest.NewRequest(http.MethodGet, "/api/admin/client-dashboard?window=5h", nil)
	clientDashboardRequest.AddCookie(cookies[0])
	clientDashboardResponse := httptest.NewRecorder()
	router.ServeHTTP(clientDashboardResponse, clientDashboardRequest)
	if clientDashboardResponse.Code != http.StatusOK || !bytes.Contains(clientDashboardResponse.Body.Bytes(), []byte(`"name":"renamed client"`)) || !bytes.Contains(clientDashboardResponse.Body.Bytes(), []byte(`"requests":1`)) {
		t.Fatalf("client dashboard=%d %s", clientDashboardResponse.Code, clientDashboardResponse.Body.String())
	}
	retainedClientToken := manualClient.ProxyToken
	rotateRequest := httptest.NewRequest(http.MethodPut, "/api/admin/access-key", bytes.NewBufferString(`{"access_key":"new-unified-access-key-123"}`))
	rotateRequest.Header.Set("Content-Type", "application/json")
	rotateRequest.AddCookie(cookies[0])
	rotatedResponse := httptest.NewRecorder()
	router.ServeHTTP(rotatedResponse, rotateRequest)
	if rotatedResponse.Code != http.StatusOK {
		t.Fatalf("rotate=%d %s", rotatedResponse.Code, rotatedResponse.Body.String())
	}
	var rotated struct {
		AccessKey string `json:"access_key"`
	}
	_ = json.Unmarshal(rotatedResponse.Body.Bytes(), &rotated)
	if rotated.AccessKey == "" || rotated.AccessKey == payload.Secrets.AccessKey {
		t.Fatal("access key was not rotated")
	}

	oldTokenRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	oldTokenRequest.Header.Set("Authorization", "Bearer "+payload.Secrets.AccessKey)
	oldTokenResponse := httptest.NewRecorder()
	router.ServeHTTP(oldTokenResponse, oldTokenRequest)
	if oldTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old token status=%d", oldTokenResponse.Code)
	}
	newTokenRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	newTokenRequest.Header.Set("Authorization", "Bearer "+rotated.AccessKey)
	newTokenResponse := httptest.NewRecorder()
	router.ServeHTTP(newTokenResponse, newTokenRequest)
	if newTokenResponse.Code == http.StatusUnauthorized {
		t.Fatal("new access key was rejected by proxy auth")
	}
	if !identityManager.VerifyAdmin(rotated.AccessKey) || !identityManager.VerifyProxy(retainedClientToken) {
		t.Fatal("access key was not unified or an independent client token was invalidated")
	}

	reloadedIdentity, err := identity.Open(cfg.InstancePath, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(cfg, db, reloadedIdentity, proxy.NewService(cfg, db, reloadedIdentity)).Router()
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBufferString(`{"password":"`+rotated.AccessKey+`"}`))
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
