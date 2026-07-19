package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInitializePersistsOnlyHashesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.json")
	manager, err := Open(path, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := manager.Initialize()
	if err != nil {
		t.Fatal(err)
	}
	if secrets.AdminPassword == "" || secrets.ProxyToken == "" || secrets.RecoveryKey == "" {
		t.Fatalf("missing secrets: %#v", secrets)
	}
	if !manager.VerifyAdmin(secrets.AdminPassword) || !manager.VerifyProxy(secrets.ProxyToken) {
		t.Fatal("generated credentials do not verify")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secrets.AdminPassword) || strings.Contains(string(raw), secrets.ProxyToken) {
		t.Fatal("plaintext login credentials were persisted")
	}
	reloaded, err := Open(path, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.VerifyAdmin(secrets.AdminPassword) || !reloaded.VerifyProxy(secrets.ProxyToken) {
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

func TestRotateProxyTokenInvalidatesPreviousToken(t *testing.T) {
	manager, _ := Open(filepath.Join(t.TempDir(), "instance.json"), nil, "", "")
	secrets, _ := manager.Initialize()
	rotated, err := manager.RotateProxyToken()
	if err != nil {
		t.Fatal(err)
	}
	if manager.VerifyProxy(secrets.ProxyToken) || !manager.VerifyProxy(rotated) {
		t.Fatal("proxy token rotation did not take effect")
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
