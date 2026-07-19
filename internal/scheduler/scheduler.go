package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/H0n3yb0t/OpencodeProxy/internal/config"
	"github.com/H0n3yb0t/OpencodeProxy/internal/proxy"
	"github.com/H0n3yb0t/OpencodeProxy/internal/store"
)

type Scheduler struct {
	cfg   config.Config
	store *store.Store
	proxy *proxy.Service
}

func New(cfg config.Config, db *store.Store, p *proxy.Service) *Scheduler {
	return &Scheduler{cfg: cfg, store: db, proxy: p}
}
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.run(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.run(ctx)
		}
	}
}
func (s *Scheduler) run(ctx context.Context) {
	_ = s.store.MarkHalfOpenDue(ctx)
	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		return
	}
	keys, err := s.store.ListKeys(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, key := range keys {
		if key.QuotaState != "half_open" || !key.AdminEnabled {
			continue
		}
		enabled := settings.AutoProbeEnabled
		if key.AutoProbeOverride != nil {
			enabled = *key.AutoProbeOverride
		}
		if !enabled {
			continue
		}
		if key.LastCheckedAt != nil && now.Sub(*key.LastCheckedAt) < time.Duration(settings.ProbeIntervalSec)*time.Second {
			continue
		}
		if _, err := s.proxy.TestKey(ctx, key, true); err != nil {
			slog.Warn("automatic key probe failed", "key_id", key.ID, "error", err)
		}
	}
	if err := s.store.PurgeBefore(ctx, time.Now().Add(-s.cfg.EventRetention)); err != nil {
		slog.Warn("purge telemetry", "error", err)
	}
}
