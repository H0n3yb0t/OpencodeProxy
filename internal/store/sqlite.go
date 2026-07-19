package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure sqlite: %w", err)
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  encrypted_key BLOB NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  priority INTEGER NOT NULL DEFAULT 100,
  admin_enabled INTEGER NOT NULL DEFAULT 1,
  auth_state TEXT NOT NULL DEFAULT 'unknown',
  quota_state TEXT NOT NULL DEFAULT 'unknown',
  control_state TEXT NOT NULL DEFAULT 'unknown',
  pool_role TEXT NOT NULL DEFAULT 'standby',
  quota_window TEXT NOT NULL DEFAULT '',
  cooling_until TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  last_used_at TEXT,
  last_checked_at TEXT,
  auto_probe_override INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_keys_routing ON keys(admin_enabled, quota_state, priority, id);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  auto_probe_enabled INTEGER NOT NULL DEFAULT 1,
  force_stream_usage INTEGER NOT NULL DEFAULT 1,
  probe_model TEXT NOT NULL DEFAULT 'mimo-v2.5',
  probe_interval_sec INTEGER NOT NULL DEFAULT 900,
  models_cache_sec INTEGER NOT NULL DEFAULT 600
);
INSERT OR IGNORE INTO settings(id) VALUES(1);

CREATE TABLE IF NOT EXISTS proxy_requests (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  protocol TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  stream INTEGER NOT NULL DEFAULT 0,
  request_bytes INTEGER NOT NULL DEFAULT 0,
  message_count INTEGER NOT NULL DEFAULT 0,
  tool_count INTEGER NOT NULL DEFAULT 0,
  final_key_id INTEGER REFERENCES keys(id) ON DELETE SET NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  http_status INTEGER NOT NULL DEFAULT 0,
  outcome TEXT NOT NULL DEFAULT '',
  error_class TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER NOT NULL DEFAULT 0,
  ttft_ms INTEGER,
  input_uncached INTEGER,
  cache_read INTEGER,
  cache_write INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  total_input INTEGER,
  total_tokens INTEGER,
  usage_state TEXT NOT NULL DEFAULT 'unavailable',
  raw_usage_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_requests_started ON proxy_requests(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_key_started ON proxy_requests(final_key_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_model_started ON proxy_requests(model, started_at DESC);

CREATE TABLE IF NOT EXISTS proxy_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL REFERENCES proxy_requests(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
  attempt_no INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  http_status INTEGER NOT NULL DEFAULT 0,
  outcome TEXT NOT NULL DEFAULT '',
  error_class TEXT NOT NULL DEFAULT '',
  upstream_request TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_attempts_request ON proxy_attempts(request_id, attempt_no);

CREATE TABLE IF NOT EXISTS quota_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
  window TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  reset_at TEXT,
  message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_quota_key_time ON quota_events(key_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS model_cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  body BLOB NOT NULL,
  fetched_at TEXT NOT NULL,
  source_key_id INTEGER REFERENCES keys(id) ON DELETE SET NULL
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

func nowText() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) CreateKey(ctx context.Context, key Key) (Key, error) {
	now := nowText()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO keys(name, encrypted_key, fingerprint, priority, admin_enabled, auth_state, quota_state, control_state, pool_role, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'standby', ?, ?)`, key.Name, key.EncryptedKey, key.Fingerprint, key.Priority, boolInt(key.AdminEnabled), key.AuthState, key.QuotaState, key.ControlState, now, now)
	if err != nil {
		return Key{}, err
	}
	id, _ := result.LastInsertId()
	return s.KeyByID(ctx, id)
}

func (s *Store) ListKeys(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, keySelect+` ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Key, 0)
	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	return result, rows.Err()
}

func (s *Store) KeyByID(ctx context.Context, id int64) (Key, error) {
	return scanKey(s.db.QueryRowContext(ctx, keySelect+` WHERE id=?`, id))
}

func (s *Store) KeyByFingerprint(ctx context.Context, fingerprint string) (Key, error) {
	return scanKey(s.db.QueryRowContext(ctx, keySelect+` WHERE fingerprint=?`, fingerprint))
}

const keySelect = `SELECT id,name,encrypted_key,fingerprint,priority,admin_enabled,auth_state,quota_state,control_state,pool_role,quota_window,cooling_until,last_error,last_used_at,last_checked_at,auto_probe_override,created_at,updated_at FROM keys`

type scanner interface{ Scan(...any) error }

func scanKey(row scanner) (Key, error) {
	var k Key
	var enabled int
	var cooling, used, checked, created, updated sql.NullString
	var override sql.NullInt64
	err := row.Scan(&k.ID, &k.Name, &k.EncryptedKey, &k.Fingerprint, &k.Priority, &enabled, &k.AuthState, &k.QuotaState, &k.ControlState, &k.PoolRole, &k.QuotaWindow, &cooling, &k.LastError, &used, &checked, &override, &created, &updated)
	if err != nil {
		return Key{}, err
	}
	k.AdminEnabled = enabled != 0
	k.CoolingUntil = parseNullTime(cooling)
	k.LastUsedAt = parseNullTime(used)
	k.LastCheckedAt = parseNullTime(checked)
	k.CreatedAt = parseTime(created.String)
	k.UpdatedAt = parseTime(updated.String)
	if override.Valid {
		v := override.Int64 != 0
		k.AutoProbeOverride = &v
	}
	return k, nil
}

func parseNullTime(value sql.NullString) *time.Time {
	if !value.Valid || value.String == "" {
		return nil
	}
	t := parseTime(value.String)
	return &t
}

func parseTime(value string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, value)
	return t
}

func (s *Store) UpdateKey(ctx context.Context, id int64, name string, priority int, enabled bool, override *bool) (Key, error) {
	var ov any
	if override != nil {
		ov = boolInt(*override)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET name=?,priority=?,admin_enabled=?,auto_probe_override=?,pool_role=CASE WHEN ?=0 THEN 'standby' ELSE pool_role END,updated_at=? WHERE id=?`, name, priority, boolInt(enabled), ov, boolInt(enabled), nowText(), id)
	if err != nil {
		return Key{}, err
	}
	return s.KeyByID(ctx, id)
}

func (s *Store) DeleteKey(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM keys WHERE id=?`, id)
	return err
}

func (s *Store) SetActive(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE keys SET pool_role='standby',updated_at=? WHERE pool_role='active'`, nowText()); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE keys SET pool_role='active',updated_at=? WHERE id=? AND admin_enabled=1`, nowText(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (s *Store) MarkChecked(ctx context.Context, id int64, auth, control, quota, lastError string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET auth_state=?,control_state=?,quota_state=CASE WHEN ?='' THEN quota_state ELSE ? END,last_error=?,last_checked_at=?,updated_at=? WHERE id=?`, auth, control, quota, quota, truncate(lastError, 1000), nowText(), nowText(), id)
	return err
}

func (s *Store) MarkUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET auth_state='valid',control_state='reachable',quota_state='available',quota_window='',cooling_until=NULL,last_error='',last_used_at=?,updated_at=? WHERE id=?`, nowText(), nowText(), id)
	return err
}

func (s *Store) MarkInvalid(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET auth_state='invalid',pool_role='standby',last_error=?,last_checked_at=?,updated_at=? WHERE id=?`, truncate(message, 1000), nowText(), nowText(), id)
	return err
}

func (s *Store) MarkQuota(ctx context.Context, id int64, window string, resetAt *time.Time, message string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var reset any
	if resetAt != nil {
		reset = resetAt.UTC().Format(time.RFC3339Nano)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE keys SET quota_state='cooling',pool_role='standby',quota_window=?,cooling_until=?,last_error=?,last_checked_at=?,updated_at=? WHERE id=?`, window, reset, truncate(message, 1000), nowText(), nowText(), id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO quota_events(key_id,window,detected_at,reset_at,message) VALUES(?,?,?,?,?)`, id, window, nowText(), reset, truncate(message, 1000)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkHalfOpenDue(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET quota_state='half_open',updated_at=? WHERE quota_state='cooling' AND cooling_until IS NOT NULL AND cooling_until<=?`, nowText(), nowText())
	return err
}

func (s *Store) EligibleKeys(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, keySelect+` WHERE admin_enabled=1 AND auth_state!='invalid' AND quota_state!='cooling' ORDER BY CASE pool_role WHEN 'active' THEN 0 ELSE 1 END, priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, k)
	}
	return result, rows.Err()
}

func (s *Store) AuthValidKeys(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, keySelect+` WHERE admin_enabled=1 AND auth_state!='invalid' ORDER BY CASE control_state WHEN 'reachable' THEN 0 ELSE 1 END, priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Key
	for rows.Next() {
		k, e := scanKey(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, k)
	}
	return result, rows.Err()
}

func (s *Store) GetSettings(ctx context.Context) (Settings, error) {
	var v Settings
	var auto, usage int
	err := s.db.QueryRowContext(ctx, `SELECT auto_probe_enabled,force_stream_usage,probe_model,probe_interval_sec,models_cache_sec FROM settings WHERE id=1`).Scan(&auto, &usage, &v.ProbeModel, &v.ProbeIntervalSec, &v.ModelsCacheSec)
	v.AutoProbeEnabled, v.ForceStreamUsage = auto != 0, usage != 0
	return v, err
}

func (s *Store) UpdateSettings(ctx context.Context, v Settings) error {
	_, err := s.db.ExecContext(ctx, `UPDATE settings SET auto_probe_enabled=?,force_stream_usage=?,probe_model=?,probe_interval_sec=?,models_cache_sec=? WHERE id=1`, boolInt(v.AutoProbeEnabled), boolInt(v.ForceStreamUsage), v.ProbeModel, v.ProbeIntervalSec, v.ModelsCacheSec)
	return err
}

func (s *Store) BeginRequest(ctx context.Context, r RequestRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO proxy_requests(id,started_at,protocol,model,stream,request_bytes,message_count,tool_count,usage_state) VALUES(?,?,?,?,?,?,?,?,?)`, r.ID, r.StartedAt.UTC().Format(time.RFC3339Nano), r.Protocol, r.Model, boolInt(r.Stream), r.RequestBytes, r.MessageCount, r.ToolCount, "unavailable")
	return err
}

func (s *Store) AddAttempt(ctx context.Context, a AttemptRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO proxy_attempts(request_id,key_id,attempt_no,started_at,finished_at,http_status,outcome,error_class,upstream_request,latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`, a.RequestID, a.KeyID, a.AttemptNo, a.StartedAt.UTC().Format(time.RFC3339Nano), a.FinishedAt.UTC().Format(time.RFC3339Nano), a.HTTPStatus, a.Outcome, a.ErrorClass, a.UpstreamRequest, a.LatencyMS)
	return err
}

func (s *Store) FinishRequest(ctx context.Context, r RequestRecord, usage Usage) error {
	_, err := s.db.ExecContext(ctx, `UPDATE proxy_requests SET finished_at=?,final_key_id=?,attempt_count=?,http_status=?,outcome=?,error_class=?,latency_ms=?,ttft_ms=?,input_uncached=?,cache_read=?,cache_write=?,output_tokens=?,reasoning_tokens=?,total_input=?,total_tokens=?,usage_state=?,raw_usage_json=? WHERE id=?`,
		timePtrText(r.FinishedAt), r.FinalKeyID, r.AttemptCount, r.HTTPStatus, r.Outcome, r.ErrorClass, r.LatencyMS, r.TTFTMS, usage.InputUncached, usage.CacheRead, usage.CacheWrite, usage.OutputTokens, usage.ReasoningTokens, usage.TotalInput, usage.TotalTokens, usage.State, usage.RawJSON, r.ID)
	return err
}

func timePtrText(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (s *Store) RecentRequests(ctx context.Context, limit int, keyID int64, model string) ([]RequestRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT r.id,r.started_at,r.finished_at,r.protocol,r.model,r.stream,r.request_bytes,r.message_count,r.tool_count,r.final_key_id,COALESCE(k.name,''),r.attempt_count,r.http_status,r.outcome,r.error_class,r.latency_ms,r.ttft_ms,r.input_uncached,r.cache_read,r.cache_write,r.output_tokens,r.reasoning_tokens,r.total_input,r.usage_state FROM proxy_requests r LEFT JOIN keys k ON k.id=r.final_key_id WHERE 1=1`
	var args []any
	if keyID > 0 {
		query += ` AND r.final_key_id=?`
		args = append(args, keyID)
	}
	if model != "" {
		query += ` AND r.model=?`
		args = append(args, model)
	}
	query += ` ORDER BY r.started_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RequestRecord, 0)
	for rows.Next() {
		var r RequestRecord
		var started string
		var finished sql.NullString
		var stream int
		if err := rows.Scan(&r.ID, &started, &finished, &r.Protocol, &r.Model, &stream, &r.RequestBytes, &r.MessageCount, &r.ToolCount, &r.FinalKeyID, &r.FinalKeyName, &r.AttemptCount, &r.HTTPStatus, &r.Outcome, &r.ErrorClass, &r.LatencyMS, &r.TTFTMS, &r.InputUncached, &r.CacheRead, &r.CacheWrite, &r.OutputTokens, &r.ReasoningTokens, &r.TotalInput, &r.UsageState); err != nil {
			return nil, err
		}
		r.StartedAt = parseTime(started)
		r.FinishedAt = parseNullTime(finished)
		r.Stream = stream != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Dashboard(ctx context.Context, since time.Time) (Dashboard, error) {
	d := Dashboard{
		KeyCounts: map[string]int{},
		Timeline:  make([]TimelinePoint, 0),
		ByKey:     make([]KeyAggregate, 0),
	}
	keys, err := s.ListKeys(ctx)
	if err != nil {
		return d, err
	}
	for i := range keys {
		k := keys[i]
		label := k.QuotaState
		if !k.AdminEnabled {
			label = "disabled"
		} else if k.AuthState == "invalid" {
			label = "invalid"
		}
		d.KeyCounts[label]++
		if k.PoolRole == "active" {
			copy := k
			d.ActiveKey = &copy
		}
	}
	sinceText := since.UTC().Format(time.RFC3339Nano)
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN outcome!='success' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN attempt_count>1 THEN 1 ELSE 0 END),0),COALESCE(SUM(input_uncached),0),COALESCE(SUM(cache_read),0),COALESCE(SUM(cache_write),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(CASE WHEN usage_state='complete' THEN 1 ELSE 0 END),0) FROM proxy_requests WHERE started_at>=?`, sinceText).Scan(&d.Requests, &d.Successes, &d.Failures, &d.Failovers, &d.InputUncached, &d.CacheRead, &d.CacheWrite, &d.OutputTokens, &d.UsageComplete)
	if err != nil {
		return d, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT strftime('%Y-%m-%dT%H:00:00Z',started_at),COALESCE(SUM(input_uncached),0),COALESCE(SUM(cache_read),0),COALESCE(SUM(cache_write),0),COALESCE(SUM(output_tokens),0),COUNT(*) FROM proxy_requests WHERE started_at>=? GROUP BY 1 ORDER BY 1`, sinceText)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var p TimelinePoint
		var bucket string
		if err := rows.Scan(&bucket, &p.InputUncached, &p.CacheRead, &p.CacheWrite, &p.OutputTokens, &p.Requests); err != nil {
			rows.Close()
			return d, err
		}
		p.Bucket = parseTime(bucket)
		d.Timeline = append(d.Timeline, p)
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT k.id,k.name,COUNT(r.id),SUM(CASE WHEN r.outcome='success' THEN 1 ELSE 0 END),COALESCE(SUM(r.input_uncached),0),COALESCE(SUM(r.cache_read),0),COALESCE(SUM(r.cache_write),0),COALESCE(SUM(r.output_tokens),0),COALESCE(AVG(r.latency_ms),0) FROM keys k LEFT JOIN proxy_requests r ON r.final_key_id=k.id AND r.started_at>=? GROUP BY k.id,k.name ORDER BY k.priority,k.id`, sinceText)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var v KeyAggregate
		if err := rows.Scan(&v.KeyID, &v.KeyName, &v.Requests, &v.Successes, &v.InputUncached, &v.CacheRead, &v.CacheWrite, &v.OutputTokens, &v.AvgLatencyMS); err != nil {
			return d, err
		}
		d.ByKey = append(d.ByKey, v)
	}
	return d, rows.Err()
}

func (s *Store) SaveModelCache(ctx context.Context, body []byte, keyID int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO model_cache(id,body,fetched_at,source_key_id) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body,fetched_at=excluded.fetched_at,source_key_id=excluded.source_key_id`, body, nowText(), keyID)
	return err
}

func (s *Store) ModelCache(ctx context.Context) ([]byte, time.Time, error) {
	var body []byte
	var fetched string
	err := s.db.QueryRowContext(ctx, `SELECT body,fetched_at FROM model_cache WHERE id=1`).Scan(&body, &fetched)
	return body, parseTime(fetched), err
}

func (s *Store) PurgeBefore(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM proxy_requests WHERE started_at<?`, before.UTC().Format(time.RFC3339Nano))
	return err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func truncate(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		return v[:n]
	}
	return v
}

func IsNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
