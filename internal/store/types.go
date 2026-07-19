package store

import "time"

type Key struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	EncryptedKey      []byte     `json:"-"`
	Fingerprint       string     `json:"fingerprint"`
	Priority          int        `json:"priority"`
	AdminEnabled      bool       `json:"admin_enabled"`
	AuthState         string     `json:"auth_state"`
	QuotaState        string     `json:"quota_state"`
	ControlState      string     `json:"control_state"`
	PoolRole          string     `json:"pool_role"`
	QuotaWindow       string     `json:"quota_window,omitempty"`
	CoolingUntil      *time.Time `json:"cooling_until,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	LastCheckedAt     *time.Time `json:"last_checked_at,omitempty"`
	AutoProbeOverride *bool      `json:"auto_probe_override,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Settings struct {
	AutoProbeEnabled bool   `json:"auto_probe_enabled"`
	ForceStreamUsage bool   `json:"force_stream_usage"`
	ProbeModel       string `json:"probe_model"`
	ProbeIntervalSec int    `json:"probe_interval_sec"`
	ModelsCacheSec   int    `json:"models_cache_sec"`
}

type RequestRecord struct {
	ID              string     `json:"id"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ClientID        string     `json:"client_id"`
	ClientName      string     `json:"client_name"`
	Protocol        string     `json:"protocol"`
	Model           string     `json:"model"`
	Stream          bool       `json:"stream"`
	RequestBytes    int64      `json:"request_bytes"`
	MessageCount    int        `json:"message_count"`
	ToolCount       int        `json:"tool_count"`
	FinalKeyID      *int64     `json:"final_key_id,omitempty"`
	FinalKeyName    string     `json:"final_key_name,omitempty"`
	AttemptCount    int        `json:"attempt_count"`
	HTTPStatus      int        `json:"http_status"`
	Outcome         string     `json:"outcome"`
	ErrorClass      string     `json:"error_class,omitempty"`
	LatencyMS       int64      `json:"latency_ms"`
	TTFTMS          *int64     `json:"ttft_ms,omitempty"`
	InputUncached   *int64     `json:"input_uncached,omitempty"`
	CacheRead       *int64     `json:"cache_read,omitempty"`
	CacheWrite      *int64     `json:"cache_write,omitempty"`
	OutputTokens    *int64     `json:"output_tokens,omitempty"`
	ReasoningTokens *int64     `json:"reasoning_tokens,omitempty"`
	TotalInput      *int64     `json:"total_input,omitempty"`
	UsageState      string     `json:"usage_state"`
}

type AttemptRecord struct {
	RequestID       string
	KeyID           int64
	AttemptNo       int
	StartedAt       time.Time
	FinishedAt      time.Time
	HTTPStatus      int
	Outcome         string
	ErrorClass      string
	UpstreamRequest string
	LatencyMS       int64
}

type Usage struct {
	InputUncached   *int64 `json:"input_uncached,omitempty"`
	CacheRead       *int64 `json:"cache_read,omitempty"`
	CacheWrite      *int64 `json:"cache_write,omitempty"`
	OutputTokens    *int64 `json:"output_tokens,omitempty"`
	ReasoningTokens *int64 `json:"reasoning_tokens,omitempty"`
	TotalInput      *int64 `json:"total_input,omitempty"`
	TotalTokens     *int64 `json:"total_tokens,omitempty"`
	State           string `json:"state"`
	RawJSON         string `json:"-"`
}

type Dashboard struct {
	ActiveKey     *Key            `json:"active_key,omitempty"`
	KeyCounts     map[string]int  `json:"key_counts"`
	Requests      int64           `json:"requests"`
	Successes     int64           `json:"successes"`
	Failures      int64           `json:"failures"`
	Failovers     int64           `json:"failovers"`
	InputUncached int64           `json:"input_uncached"`
	CacheRead     int64           `json:"cache_read"`
	CacheWrite    int64           `json:"cache_write"`
	OutputTokens  int64           `json:"output_tokens"`
	UsageComplete int64           `json:"usage_complete"`
	Timeline      []TimelinePoint `json:"timeline"`
	ByKey         []KeyAggregate  `json:"by_key"`
}

type TimelinePoint struct {
	Bucket        time.Time `json:"bucket"`
	InputUncached int64     `json:"input_uncached"`
	CacheRead     int64     `json:"cache_read"`
	CacheWrite    int64     `json:"cache_write"`
	OutputTokens  int64     `json:"output_tokens"`
	Requests      int64     `json:"requests"`
}

type KeyAggregate struct {
	KeyID         int64  `json:"key_id"`
	KeyName       string `json:"key_name"`
	Requests      int64  `json:"requests"`
	Successes     int64  `json:"successes"`
	InputUncached int64  `json:"input_uncached"`
	CacheRead     int64  `json:"cache_read"`
	CacheWrite    int64  `json:"cache_write"`
	OutputTokens  int64  `json:"output_tokens"`
	AvgLatencyMS  int64  `json:"avg_latency_ms"`
}

type ClientAggregate struct {
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
	Requests      int64  `json:"requests"`
	Successes     int64  `json:"successes"`
	Failures      int64  `json:"failures"`
	Failovers     int64  `json:"failovers"`
	InputUncached int64  `json:"input_uncached"`
	CacheRead     int64  `json:"cache_read"`
	CacheWrite    int64  `json:"cache_write"`
	OutputTokens  int64  `json:"output_tokens"`
	UsageComplete int64  `json:"usage_complete"`
	AvgLatencyMS  int64  `json:"avg_latency_ms"`
}
