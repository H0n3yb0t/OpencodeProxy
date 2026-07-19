package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr      string
	DatabasePath    string
	InstancePath    string
	MasterKey       []byte
	AdminPassword   string
	BootstrapToken  string
	UpstreamBaseURL string
	RequestTimeout  time.Duration
	IdleTimeout     time.Duration
	MaxRequestBytes int64
	EventRetention  time.Duration
	WebDir          string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:      env("LISTEN_ADDR", "0.0.0.0:8080"),
		DatabasePath:    env("DATABASE_PATH", "data/openpool.db"),
		AdminPassword:   os.Getenv("ADMIN_PASSWORD"),
		BootstrapToken:  os.Getenv("PROXY_TOKEN"),
		UpstreamBaseURL: env("UPSTREAM_BASE_URL", "https://opencode.ai/zen/go/v1"),
		RequestTimeout:  envDuration("REQUEST_TIMEOUT", 10*time.Minute),
		IdleTimeout:     envDuration("IDLE_TIMEOUT", 2*time.Minute),
		MaxRequestBytes: envInt64("MAX_REQUEST_BYTES", 64<<20),
		EventRetention:  envDuration("EVENT_RETENTION", 30*24*time.Hour),
		WebDir:          env("WEB_DIR", "web/dist"),
	}
	cfg.InstancePath = env("INSTANCE_PATH", filepath.Join(filepath.Dir(cfg.DatabasePath), "instance.json"))
	encoded := os.Getenv("MASTER_KEY")
	legacyCount := 0
	if encoded != "" {
		legacyCount++
	}
	if cfg.AdminPassword != "" {
		legacyCount++
	}
	if cfg.BootstrapToken != "" {
		legacyCount++
	}
	if legacyCount != 0 && legacyCount != 3 {
		return Config{}, errors.New("MASTER_KEY, ADMIN_PASSWORD and PROXY_TOKEN must be supplied together, or all omitted for Web setup")
	}
	if encoded != "" {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return Config{}, fmt.Errorf("MASTER_KEY must be base64-encoded 32 bytes")
		}
		cfg.MasterKey = key
	}
	if !strings.HasPrefix(cfg.UpstreamBaseURL, "https://opencode.ai/") && os.Getenv("ALLOW_CUSTOM_UPSTREAM") != "true" {
		return Config{}, errors.New("UPSTREAM_BASE_URL must use https://opencode.ai unless ALLOW_CUSTOM_UPSTREAM=true")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(name string, fallback int64) int64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
