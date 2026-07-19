package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInitializePersistsUnifiedAccessKeyOnlyAsHashesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.json")
	manager, err := Open(path, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := manager.Initialize()
	if err != nil {
		t.Fatal(err)
	}
	if secrets.AccessKey == "" || secrets.RecoveryKey == "" {
		t.Fatalf("missing secrets: %#v", secrets)
	}
	if !manager.VerifyAdmin(secrets.AccessKey) || !manager.VerifyProxy(secrets.AccessKey) || !manager.UnifiedAccessEnabled() {
		t.Fatal("generated credentials do not verify")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secrets.AccessKey) {
		t.Fatal("plaintext login credentials were persisted")
	}
	reloaded, err := Open(path, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.VerifyAdmin(secrets.AccessKey) || !reloaded.VerifyProxy(secrets.AccessKey) {
		t.Fatal("credentials did not survive reload")
	}
	ciphertext, err := reloaded.Encrypt("upstream-key")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := reloaded.Decrypt(ciphertext)
	if err != nil || plaintext != "upstream-key" {
		t.Fatalf("decrypt=%q err=%v", plaintext, err)
	}
}

func TestRotateAccessKeyInvalidatesPreviousMasterButKeepsClientTokens(t *testing.T) {
	manager, _ := Open(filepath.Join(t.TempDir(), "instance.json"), nil, "", "")
	secrets, _ := manager.Initialize()
	_, clientToken, _ := manager.IssueClientToken("client")
	rotated, err := manager.RotateAccessKey("new-unified-access-key")
	if err != nil {
		t.Fatal(err)
	}
	if manager.VerifyProxy(secrets.AccessKey) || manager.VerifyAdmin(secrets.AccessKey) || !manager.VerifyProxy(rotated) || !manager.VerifyAdmin(rotated) {
		t.Fatal("access key rotation did not take effect")
	}
	if !manager.VerifyProxy(clientToken) {
		t.Fatal("access key rotation invalidated an independent client token")
	}
}

func TestLegacySeparateCredentialsRemainValidUntilUnified(t *testing.T) {
	manager, err := Open(filepath.Join(t.TempDir(), "instance.json"), make([]byte, 32), "legacy-admin-password", "legacy-proxy-token")
	if err != nil {
		t.Fatal(err)
	}
	if manager.UnifiedAccessEnabled() || !manager.VerifyAdmin("legacy-admin-password") || !manager.VerifyProxy("legacy-proxy-token") {
		t.Fatal("legacy credentials were not preserved")
	}
	accessKey, err := manager.RotateAccessKey("new-unified-access-key")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.UnifiedAccessEnabled() || !manager.VerifyAdmin(accessKey) || !manager.VerifyProxy(accessKey) {
		t.Fatal("legacy credentials were not unified")
	}
	if manager.VerifyAdmin("legacy-admin-password") || manager.VerifyProxy("legacy-proxy-token") {
		t.Fatal("legacy credentials remained valid after unification")
	}
}

func TestClientTokensPersistAndCanBeRevoked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.json")
	manager, _ := Open(path, nil, "", "")
	_, _ = manager.Initialize()
	client, token, err := manager.IssueClientToken("Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if client.ID == "" || client.Name != "Laptop" || token == "" || !manager.VerifyProxy(token) {
		t.Fatalf("invalid client token: %#v", client)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), token) {
		t.Fatal("plaintext client token was persisted")
	}
	reloaded, err := Open(path, nil, "", "")
	if err != nil || !reloaded.VerifyProxy(token) {
		t.Fatalf("client token did not survive reload: %v", err)
	}
	listed := reloaded.ListClientTokens()
	if len(listed) != 1 || listed[0].ID != client.ID {
		t.Fatalf("unexpected client token list: %#v", listed)
	}
	if err := reloaded.RevokeClientToken(client.ID); err != nil {
		t.Fatal(err)
	}
	if reloaded.VerifyProxy(token) || len(reloaded.ListClientTokens()) != 0 {
		t.Fatal("revoked client token is still active")
	}
}

func TestInitializeAllowsExactlyOneConcurrentCaller(t *testing.T) {
	manager, err := Open(filepath.Join(t.TempDir(), "instance.json"), nil, "", "")
	if err != nil {
		t.Fatal(err)
	}

	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := manager.Initialize()
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	succeeded, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrAlreadyInitialized):
			rejected++
		default:
			t.Fatalf("unexpected initialization error: %v", err)
		}
	}
	if succeeded != 1 || rejected != callers-1 {
		t.Fatalf("succeeded=%d rejected=%d", succeeded, rejected)
	}
}
