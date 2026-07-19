package config

import (
	"encoding/base64"
	"testing"
)

func TestAccessKeyConfigUsesOneCredentialForAdminAndProxy(t *testing.T) {
	t.Setenv("MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("ACCESS_KEY", "one-unified-access-key")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("PROXY_TOKEN", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminPassword != "one-unified-access-key" || cfg.BootstrapToken != "one-unified-access-key" {
		t.Fatalf("access key was not unified: %#v", cfg)
	}
}

func TestAccessKeyRejectsLegacyCredentialMix(t *testing.T) {
	t.Setenv("MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("ACCESS_KEY", "one-unified-access-key")
	t.Setenv("ADMIN_PASSWORD", "legacy-admin")
	if _, err := Load(); err == nil {
		t.Fatal("mixed unified and legacy credentials were accepted")
	}
}
