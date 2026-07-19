package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/local/opencode-keypool/internal/config"
	"github.com/local/opencode-keypool/internal/httpapi"
	"github.com/local/opencode-keypool/internal/identity"
	"github.com/local/opencode-keypool/internal/proxy"
	"github.com/local/opencode-keypool/internal/scheduler"
	"github.com/local/opencode-keypool/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	db, err := store.Open(cfg.DatabasePath)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	identityManager, err := identity.Open(cfg.InstancePath, cfg.MasterKey, cfg.AdminPassword, cfg.BootstrapToken)
	if err != nil {
		logger.Error("initialize instance identity", "error", err)
		os.Exit(1)
	}
	proxyService := proxy.NewService(cfg, db, identityManager)
	api := httpapi.New(cfg, db, identityManager, proxyService)
	server := &http.Server{Addr: cfg.ListenAddr, Handler: api.Router(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: cfg.IdleTimeout}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go scheduler.New(cfg, db, proxyService).Run(ctx)
	go func() {
		logger.Info("openpool listening", "address", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server stopped", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown", "error", err)
	}
}
