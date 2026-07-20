import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type KeyItem = {
  id: number;
  name: string;
  fingerprint: string;
  priority: number;
  admin_enabled: boolean;
  auth_state: string;
  quota_state: string;
  control_state: string;
  pool_role: string;
  quota_window?: string;
  cooling_until?: string;
  last_error?: string;
  last_used_at?: string;
  auto_probe_override?: boolean;
};
type RequestItem = {
  id: string;
  started_at: string;
  client_id: string;
  client_name: string;
  protocol: string;
  model: string;
  stream: boolean;
  final_key_name?: string;
  attempt_count: number;
  http_status: number;
  outcome: string;
  error_class?: string;
  latency_ms: number;
  ttft_ms?: number;
  input_uncached?: number;
  cache_read?: number;
  cache_write?: number;
  output_tokens?: number;
  total_input?: number;
  usage_state: string;
};
type DashboardData = {
  active_key?: KeyItem;
  key_counts: Record<string, number>;
  requests: number;
  successes: number;
  failures: number;
  failovers: number;
  input_uncached: number;
  cache_read: number;
  cache_write: number;
  output_tokens: number;
  usage_complete: number;
  timeline: Array<{
    bucket: string;
    input_uncached: number;
    cache_read: number;
    cache_write: number;
    output_tokens: number;
    requests: number;
  }>;
  by_key: Array<{
    key_id: number;
    key_name: string;
    requests: number;
    successes: number;
    input_uncached: number;
    cache_read: number;
    cache_write: number;
    output_tokens: number;
    avg_latency_ms: number;
  }>;
};
type Settings = {
  auto_probe_enabled: boolean;
  force_stream_usage: boolean;
  probe_model: string;
  probe_interval_sec: number;
  models_cache_sec: number;
};
type SetupSecrets = {
  access_key: string;
  recovery_key: string;
};
type KeyImportResult = {
  line: number;
  name?: string;
  fingerprint?: string;
  status: "imported" | "duplicate" | "failed";
  error?: string;
  test?: { ok?: boolean; stage?: string; message?: string };
};
type KeyImportResponse = {
  total: number;
  imported: number;
  duplicates: number;
  failed: number;
  results: KeyImportResult[];
};
type ClientToken = {
  id: string;
  name: string;
  created_at: string;
};
type ClientEnrollment = {
  ticket: string;
  expires_at: string;
};
type ClientDashboardItem = {
  id: string;
  name: string;
  kind: "master" | "client";
  active: boolean;
  created_at?: string;
  requests: number;
  successes: number;
  failures: number;
  failovers: number;
  input_uncached: number;
  cache_read: number;
  cache_write: number;
  output_tokens: number;
  usage_complete: number;
  avg_latency_ms: number;
};

const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (response.status === 204) return undefined as T;
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new Error(
      data.error?.message || data.error || `HTTP ${response.status}`,
    );
  return data;
};
const copyText = async (value: string) => {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // HTTP deployments on a LAN may not expose the Clipboard API.
    }
  }
  const area = document.createElement("textarea");
  area.value = value;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
};
const formatTokens = (value?: number) =>
  value == null
    ? "—"
    : value >= 1_000_000
      ? `${(value / 1_000_000).toFixed(2)}M`
      : value >= 1000
        ? `${(value / 1000).toFixed(1)}K`
        : String(value);
const formatDate = (value?: string) =>
  value
    ? new Intl.DateTimeFormat("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date(value))
    : "—";
const countdown = (value?: string) => {
  if (!value) return "";
  const seconds = Math.max(
    0,
    Math.floor((new Date(value).getTime() - Date.now()) / 1000),
  );
  const d = Math.floor(seconds / 86400),
    h = Math.floor((seconds % 86400) / 3600),
    m = Math.floor((seconds % 3600) / 60),
    s = seconds % 60;
  return [d && `${d}天`, h && `${h}时`, m && `${m}分`, `${s}秒`]
    .filter(Boolean)
    .join(" ");
};
const quotaWindowLabel = (value?: string) => {
  switch (value) {
    case "balance":
      return "余额不足";
    case "5h":
      return "5 小时额度";
    case "weekly":
      return "周额度";
    case "monthly":
      return "月额度";
    case "weekly_or_monthly":
      return "周/月额度";
    default:
      return value ? `${value}额度` : "额度";
  }
};

function Setup({ onComplete }: { onComplete: () => void }) {
  const [secrets, setSecrets] = useState<SetupSecrets | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const initialize = async () => {
    setBusy(true);
    setError("");
    try {
      const result = await api<{ secrets: SetupSecrets }>(
        "/api/setup/initialize",
        { method: "POST" },
      );
      setSecrets(result.secrets);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const exportText = secrets
    ? [
        "OpencodeProxy initialization credentials",
        `URL: ${location.origin}`,
        `Master access key: ${secrets.access_key}`,
        `Recovery key: ${secrets.recovery_key}`,
        "",
        "Keep this file private. These values will not be shown again.",
      ].join("\n")
    : "";

  const download = () => {
    const url = URL.createObjectURL(
      new Blob([exportText], { type: "text/plain;charset=utf-8" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "opencodeproxy-credentials.txt";
    link.click();
    URL.revokeObjectURL(url);
  };

  if (!secrets) {
    return (
      <main className="login-shell">
        <section className="login-card setup-card">
          <div className="brand-mark">O</div>
          <p className="eyebrow">FIRST RUN SETUP</p>
          <h1>初始化 OpencodeProxy</h1>
          <p className="muted setup-copy">
            系统将生成主访问密钥和数据恢复密钥。主访问密钥同时用于登录面板和调用代理 API。
          </p>
          <div className="setup-notice">
            尚未初始化的服务由第一个访问者取得管理权。请只在可信网络完成此步骤。
          </div>
          {error && <p className="form-error">{error}</p>}
          <button className="primary" disabled={busy} onClick={initialize}>
            {busy ? "正在安全初始化…" : "一键初始化"}
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="login-shell">
      <section className="login-card setup-card secrets-card">
        <div className="brand-mark">✓</div>
        <p className="eyebrow">INITIALIZATION COMPLETE</p>
        <h1>请保存一次性凭据</h1>
        <p className="muted setup-copy">
          主访问密钥只在此页面显示一次。恢复密钥用于数据卷备份恢复。
        </p>
        <div className="secret-list">
          {[
            ["主访问密钥", secrets.access_key],
            ["恢复密钥", secrets.recovery_key],
          ].map(([label, value]) => (
            <div className="secret-row" key={label}>
              <span>{label}</span>
              <code>{value}</code>
              <button onClick={() => copyText(value)}>复制</button>
            </div>
          ))}
        </div>
        <div className="setup-actions">
          <button onClick={() => copyText(exportText)}>复制全部</button>
          <button onClick={download}>下载凭据文件</button>
        </div>
        <label className="check setup-check">
          <input
            type="checkbox"
            checked={saved}
            onChange={(event) => setSaved(event.target.checked)}
          />
          我已安全保存以上凭据
        </label>
        <button className="primary" disabled={!saved} onClick={onComplete}>
          进入控制台
        </button>
      </section>
    </main>
  );
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      onLogin();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="login-shell">
      <section className="login-card">
        <div className="brand-mark">O</div>
        <p className="eyebrow">OPENCODE GO CONTROL PLANE</p>
        <h1>OpencodeProxy</h1>
        <p className="muted">故障转移、额度恢复与缓存效率，一处掌握。</p>
        <form onSubmit={submit}>
          <label>
            主访问密钥
            <input
              autoFocus
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="输入初始化时生成的主访问密钥"
            />
          </label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary" disabled={busy}>
            {busy ? "正在验证…" : "进入控制台"}
          </button>
        </form>
      </section>
    </main>
  );
}

function App() {
  const [mode, setMode] = useState<"loading" | "setup" | "login" | "app">(
    "loading",
  );
  const [page, setPage] = useState(location.hash.slice(1) || "dashboard");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    api<{ initialized: boolean }>("/api/setup/status")
      .then((status) => {
        if (!status.initialized) {
          setMode("setup");
          return;
        }
        api("/api/admin/me")
          .then(() => setMode("app"))
          .catch(() => setMode("login"));
      })
      .catch(() => setMode("login"));
  }, []);
  useEffect(() => {
    const handler = () => setPage(location.hash.slice(1) || "dashboard");
    addEventListener("hashchange", handler);
    return () => removeEventListener("hashchange", handler);
  }, []);
  useEffect(() => {
    if (mode !== "app") return;
    const source = new EventSource("/api/admin/stream");
    source.addEventListener("tick", () => setRefresh((v) => v + 1));
    return () => source.close();
  }, [mode]);
  if (mode === "loading") return <div className="boot">正在启动控制台…</div>;
  if (mode === "setup") return <Setup onComplete={() => setMode("app")} />;
  if (mode === "login") return <Login onLogin={() => setMode("app")} />;
  const logout = async () => {
    await api("/api/admin/logout", { method: "POST" });
    setMode("login");
  };
  return (
    <div className="app-shell">
      <aside>
        <div className="brand">
          <div className="brand-mark small">O</div>
          <div>
            <strong>OpencodeProxy</strong>
            <span>OpenCode Go</span>
          </div>
        </div>
        <nav>
          {[
            ["dashboard", "总览", "01"],
            ["keys", "密钥池", "02"],
            ["requests", "请求流水", "03"],
            ["clients", "客户端", "04"],
            ["settings", "设置", "05"],
          ].map(([id, label, num]) => (
            <a key={id} className={page === id ? "active" : ""} href={`#${id}`}>
              <span>{num}</span>
              {label}
            </a>
          ))}
        </nav>
        <div className="aside-foot">
          <span className="live-dot" /> 服务运行中
          <button onClick={logout}>退出</button>
        </div>
      </aside>
      <section className="workspace">
        {page === "dashboard" && <Dashboard refresh={refresh} />}{" "}
        {page === "keys" && <Keys refresh={refresh} />}{" "}
        {page === "requests" && <Requests refresh={refresh} />}{" "}
        {page === "clients" && <ClientsPage />}{" "}
        {page === "settings" && <SettingsPage />}
      </section>
    </div>
  );
}

function PageHead({
  kicker,
  title,
  children,
}: {
  kicker: string;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <header className="page-head">
      <div>
        <p className="eyebrow">{kicker}</p>
        <h1>{title}</h1>
      </div>
      {children}
    </header>
  );
}
function Stat({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: string;
}) {
  return (
    <article className={`stat ${tone || ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function Dashboard({ refresh }: { refresh: number }) {
  const [windowName, setWindowName] = useState("5h");
  const [data, setData] = useState<DashboardData | null>(null);
  const [now, setNow] = useState(Date.now());
  const load = useCallback(
    () =>
      api<DashboardData>(`/api/admin/dashboard?window=${windowName}`).then(
        (value) =>
          setData({
            ...value,
            key_counts: value.key_counts || {},
            timeline: value.timeline || [],
            by_key: value.by_key || [],
          }),
      ),
    [windowName],
  );
  useEffect(() => {
    load();
  }, [load, refresh]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  void now;
  if (!data) return <div className="loading">载入运行数据…</div>;
  const totalInput = data.input_uncached + data.cache_read + data.cache_write;
  const hit = totalInput ? (data.cache_read / totalInput) * 100 : 0;
  const coverage = data.requests
    ? (data.usage_complete / data.requests) * 100
    : 0;
  return (
    <>
      <PageHead kicker="LIVE OPERATIONS" title="运行总览">
        <div className="segmented">
          {["5h", "24h", "7d", "30d"].map((v) => (
            <button
              className={windowName === v ? "selected" : ""}
              onClick={() => setWindowName(v)}
              key={v}
            >
              {v}
            </button>
          ))}
        </div>
      </PageHead>
      <section className="hero-status">
        <div>
          <span className="signal">ACTIVE KEY</span>
          <h2>{data.active_key?.name || "等待首个可用 key"}</h2>
          <p>
            {data.active_key
              ? `•••• ${data.active_key.fingerprint} · 上次使用 ${formatDate(data.active_key.last_used_at)}`
              : "添加并验证 key 后自动激活"}
          </p>
        </div>
        <div className="pool-counts">
          <div>
            <strong>{data.key_counts.available || 0}</strong>
            <span>可用</span>
          </div>
          <div>
            <strong>{data.key_counts.cooling || 0}</strong>
            <span>冷却</span>
          </div>
          <div>
            <strong>{data.key_counts.invalid || 0}</strong>
            <span>失效</span>
          </div>
        </div>
      </section>
      <section className="stats-grid">
        <Stat
          label="请求"
          value={data.requests}
          detail={`${data.successes} 成功 · ${data.failures} 失败`}
        />
        <Stat
          label="输入 TOKEN"
          value={formatTokens(totalInput)}
          detail={`${formatTokens(data.input_uncached)} 未缓存`}
        />
        <Stat
          label="缓存命中"
          value={`${hit.toFixed(1)}%`}
          detail={`${formatTokens(data.cache_read)} cache read`}
          tone="mint"
        />
        <Stat
          label="输出 TOKEN"
          value={formatTokens(data.output_tokens)}
          detail={`${coverage.toFixed(0)}% usage 覆盖率`}
        />
        <Stat
          label="故障转移"
          value={data.failovers}
          detail="同一逻辑请求多次尝试"
          tone={data.failovers ? "amber" : ""}
        />
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">TOKEN FLOW</p>
            <h3>消耗结构</h3>
          </div>
          <div className="legend">
            <i className="uncached" />
            未缓存
            <i className="read" />
            Cache read
            <i className="write" />
            Cache write
            <i className="output" />
            输出
          </div>
        </div>
        <TokenChart points={data.timeline || []} />
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">KEY PERFORMANCE</p>
            <h3>每 key 视角</h3>
          </div>
          <span className="muted">当前窗口</span>
        </div>
        <div className="key-performance">
          {(data.by_key || []).map((k) => {
            const input = k.input_uncached + k.cache_read + k.cache_write;
            const ratio = input ? (k.cache_read / input) * 100 : 0;
            return (
              <div className="performance-row" key={k.key_id}>
                <div>
                  <strong>{k.key_name}</strong>
                  <span>
                    {k.requests} 请求 · {k.successes} 成功
                  </span>
                </div>
                <div>
                  <small>5H INPUT</small>
                  <strong>{formatTokens(input)}</strong>
                </div>
                <div>
                  <small>CACHE HIT</small>
                  <strong>{ratio.toFixed(1)}%</strong>
                </div>
                <div>
                  <small>OUTPUT</small>
                  <strong>{formatTokens(k.output_tokens)}</strong>
                </div>
                <div>
                  <small>AVG LATENCY</small>
                  <strong>{k.avg_latency_ms} ms</strong>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </>
  );
}

function TokenChart({ points }: { points: DashboardData["timeline"] }) {
  const max = Math.max(
    1,
    ...points.map(
      (p) => p.input_uncached + p.cache_read + p.cache_write + p.output_tokens,
    ),
  );
  if (!points.length)
    return (
      <div className="empty-chart">产生请求后，这里会显示 token 时间线。</div>
    );
  return (
    <div className="chart">
      {points.map((p) => {
        const values = [
          [p.input_uncached, "uncached"],
          [p.cache_read, "read"],
          [p.cache_write, "write"],
          [p.output_tokens, "output"],
        ] as const;
        return (
          <div
            className="bar-slot"
            key={p.bucket}
            title={`${formatDate(p.bucket)} · ${p.requests} 请求`}
          >
            <div className="bar">
              {values.map(([v, c]) => (
                <i
                  key={c}
                  className={c}
                  style={{
                    height: `${Math.max(v ? 2 : 0, (v / max) * 150)}px`,
                  }}
                />
              ))}
            </div>
            <span>{new Date(p.bucket).getHours()}:00</span>
          </div>
        );
      })}
    </div>
  );
}

function Keys({ refresh }: { refresh: number }) {
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [error, setError] = useState("");
  const [now, setNow] = useState(Date.now());
  const load = useCallback(
    () =>
      api<{ keys: KeyItem[] }>("/api/admin/keys").then((v) =>
        setKeys(v.keys || []),
      ),
    [],
  );
  useEffect(() => {
    load();
  }, [load, refresh]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  void now;
  const action = async (path: string, method = "POST", body?: unknown) => {
    setError("");
    try {
      await api(path, {
        method,
        body: body ? JSON.stringify(body) : undefined,
      });
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  return (
    <>
      <PageHead kicker="CREDENTIAL ROUTING" title="密钥池">
        <button
          className="primary compact"
          onClick={() => setShowAdd(!showAdd)}
        >
          {showAdd ? "取消" : "添加 key"}
        </button>
      </PageHead>
      {showAdd && <AddKey onImported={load} />}
      {error && <p className="banner-error">{error}</p>}
      <section className="keys-list">
        {keys.length === 0 && (
          <div className="empty-state">
            <strong>池里还没有 key</strong>
            <span>添加第一个独立的 OpenCode Go API key。</span>
          </div>
        )}
        {keys.map((key) => (
          <article
            className={`key-card ${key.pool_role === "active" ? "is-active" : ""}`}
            key={key.id}
          >
            <div className="key-main">
              <div className="key-title">
                <span className={`status-dot ${statusTone(key)}`} />
                <div>
                  <h3>
                    {key.name}
                    {key.pool_role === "active" && <b>ACTIVE</b>}
                  </h3>
                  <p>
                    •••• {key.fingerprint} · 优先级 {key.priority}
                  </p>
                </div>
              </div>
              <div className="state-pills">
                <span>{key.auth_state}</span>
                <span>{key.control_state}</span>
                <span className={key.quota_state}>{key.quota_state}</span>
                {!key.admin_enabled && (
                  <span className="disabled">disabled</span>
                )}
              </div>
            </div>
            {key.quota_state === "cooling" && (
              <div className="cooldown">
                <span>{quotaWindowLabel(key.quota_window)}冷却中</span>
                <strong>{countdown(key.cooling_until)}</strong>
                <small>
                  {key.quota_window === "balance" ? "最早重试" : "预计恢复"}{" "}
                  {formatDate(key.cooling_until)}
                </small>
              </div>
            )}
            {key.last_error && <p className="key-error">{key.last_error}</p>}
            <div className="key-actions">
              <button
                onClick={() =>
                  action(`/api/admin/keys/${key.id}/test`, "POST", {
                    inference: false,
                  })
                }
              >
                验证鉴权
              </button>
              <button
                onClick={() =>
                  action(`/api/admin/keys/${key.id}/test`, "POST", {
                    inference: true,
                  })
                }
              >
                推理探测
              </button>
              <button
                disabled={
                  key.pool_role === "active" || key.quota_state === "cooling"
                }
                onClick={() => action(`/api/admin/keys/${key.id}/activate`)}
              >
                设为活动
              </button>
              <button
                onClick={() =>
                  action(`/api/admin/keys/${key.id}`, "PATCH", {
                    admin_enabled: !key.admin_enabled,
                  })
                }
              >
                {key.admin_enabled ? "禁用" : "启用"}
              </button>
              <select
                value={
                  key.auto_probe_override == null
                    ? "inherit"
                    : key.auto_probe_override
                      ? "enabled"
                      : "disabled"
                }
                onChange={(e) =>
                  action(`/api/admin/keys/${key.id}`, "PATCH", {
                    auto_probe_mode: e.target.value,
                  })
                }
              >
                <option value="inherit">探测：继承</option>
                <option value="enabled">探测：开启</option>
                <option value="disabled">探测：关闭</option>
              </select>
              <button
                className="danger"
                onClick={() =>
                  confirm(`删除 ${key.name}？`) &&
                  action(`/api/admin/keys/${key.id}`, "DELETE")
                }
              >
                删除
              </button>
            </div>
          </article>
        ))}
      </section>
    </>
  );
}
function statusTone(k: KeyItem) {
  if (!k.admin_enabled || k.auth_state === "invalid") return "bad";
  if (k.quota_state === "cooling") return "warn";
  if (k.pool_role === "active") return "good";
  return "idle";
}
function AddKey({ onImported }: { onImported: () => void | Promise<void> }) {
  const [name, setName] = useState("");
  const [keyText, setKeyText] = useState("");
  const [priority, setPriority] = useState(100);
  const [validate, setValidate] = useState(true);
  const [probe, setProbe] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<KeyImportResponse | null>(null);
  const lines = keyText
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
  const uniqueCount = new Set(lines).size;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await api<KeyImportResponse>("/api/admin/keys/import", {
        method: "POST",
        body: JSON.stringify({
          keys: lines,
          name_prefix: name,
          priority,
          validate,
          test_inference: validate && probe,
        }),
      });
      setResult(response);
      if (response.failed === 0) setKeyText("");
      await onImported();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="add-key" onSubmit={submit}>
      <div>
        <label>
          名称前缀（可选）
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="例如 HK Go；批量导入时自动追加序号"
          />
        </label>
        <label>
          起始优先级
          <input
            type="number"
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
          />
        </label>
      </div>
      <label>
        OpenCode Go API key（每行一个，最多 100 个）
        <textarea
          required
          rows={7}
          spellCheck={false}
          autoComplete="off"
          value={keyText}
          onChange={(e) => setKeyText(e.target.value)}
          placeholder={"opencode-key-1\nopencode-key-2\nopencode-key-3"}
        />
        <small className="import-count">
          已识别 {lines.length} 行 · {uniqueCount} 个不同 key
        </small>
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={validate}
          onChange={(e) => {
            setValidate(e.target.checked);
            if (!e.target.checked) setProbe(false);
          }}
        />
        导入后逐个验证鉴权
      </label>
      <label className="check">
        <input
          type="checkbox"
          disabled={!validate}
          checked={probe}
          onChange={(e) => setProbe(e.target.checked)}
        />
        验证时执行一次最小推理探测
      </label>
      {error && <p className="form-error">{error}</p>}
      {result && (
        <section className="import-result">
          <strong>
            已导入 {result.imported} / {result.total}
          </strong>
          <span>
            {result.duplicates} 个重复 · {result.failed} 个失败
          </span>
          <div>
            {result.results.map((item) => (
              <p className={item.status} key={`${item.line}-${item.status}`}>
                <b>第 {item.line} 行</b>
                <code>{item.fingerprint || "—"}</code>
                <span>
                  {item.status === "imported"
                    ? item.test?.ok === false
                      ? `已保存，验证失败：${item.test.message || item.test.stage || "未知错误"}`
                      : item.test
                        ? "已保存并通过验证"
                        : "已保存"
                    : item.status === "duplicate"
                      ? item.error === "key already exists"
                        ? "已存在于密钥池"
                        : "本次导入中重复"
                      : item.error || "导入失败"}
                </span>
              </p>
            ))}
          </div>
        </section>
      )}
      <button className="primary" disabled={busy || lines.length === 0}>
        {busy
          ? `正在导入 ${lines.length} 个 key…`
          : lines.length
            ? `导入 ${lines.length} 个 key`
            : "导入 key"}
      </button>
    </form>
  );
}

function Requests({ refresh }: { refresh: number }) {
  const [items, setItems] = useState<RequestItem[]>([]);
  const [keyFilter, setKeyFilter] = useState("");
  const [modelFilter, setModelFilter] = useState("");
  const load = useCallback(
    () =>
      api<{ requests: RequestItem[] }>(
        `/api/admin/requests?limit=100${keyFilter ? `&key_id=${keyFilter}` : ""}${modelFilter ? `&model=${encodeURIComponent(modelFilter)}` : ""}`,
      ).then((v) => setItems(v.requests || [])),
    [keyFilter, modelFilter],
  );
  useEffect(() => {
    load();
  }, [load, refresh]);
  const models = useMemo(
    () => Array.from(new Set(items.map((i) => i.model).filter(Boolean))),
    [items],
  );
  return (
    <>
      <PageHead kicker="REQUEST LEDGER" title="请求流水">
        <div className="filters">
          <input
            placeholder="Key ID"
            value={keyFilter}
            onChange={(e) => setKeyFilter(e.target.value)}
          />
          <select
            value={modelFilter}
            onChange={(e) => setModelFilter(e.target.value)}
          >
            <option value="">全部模型</option>
            {models.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
        </div>
      </PageHead>
      <section className="table-panel">
        <table>
          <thead>
            <tr>
              <th>时间 / REQUEST ID</th>
              <th>模型</th>
              <th>KEY / 尝试</th>
              <th>未缓存输入</th>
              <th>CACHE READ</th>
              <th>CACHE WRITE</th>
              <th>输出</th>
              <th>命中率</th>
              <th>TTFT / 总耗时</th>
              <th>结果</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => {
              const total =
                item.total_input ??
                (item.input_uncached || 0) +
                  (item.cache_read || 0) +
                  (item.cache_write || 0);
              const hit = total ? ((item.cache_read || 0) / total) * 100 : 0;
              return (
                <tr key={item.id}>
                  <td>
                    <strong>{formatDate(item.started_at)}</strong>
                    <small>
                      {item.id.slice(0, 12)} · {item.client_name || "主访问密钥"}
                    </small>
                  </td>
                  <td>
                    <strong>{item.model || "—"}</strong>
                    <small>
                      {item.protocol}
                      {item.stream ? " · stream" : ""}
                    </small>
                  </td>
                  <td>
                    <strong>{item.final_key_name || "—"}</strong>
                    <small>{item.attempt_count} attempt</small>
                  </td>
                  <td>{formatTokens(item.input_uncached)}</td>
                  <td className="mint-text">{formatTokens(item.cache_read)}</td>
                  <td>{formatTokens(item.cache_write)}</td>
                  <td>{formatTokens(item.output_tokens)}</td>
                  <td>
                    {item.usage_state === "unavailable"
                      ? "—"
                      : `${hit.toFixed(1)}%`}
                  </td>
                  <td>
                    <strong>
                      {item.ttft_ms == null ? "—" : `${item.ttft_ms}ms`}
                    </strong>
                    <small>{item.latency_ms}ms</small>
                  </td>
                  <td>
                    <span className={`result ${item.outcome}`}>
                      {item.http_status || "—"} {item.outcome}
                    </span>
                    {item.error_class && <small>{item.error_class}</small>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!items.length && (
          <div className="empty-table">
            暂无请求流水。通过代理发送第一个模型请求后会出现在这里。
          </div>
        )}
      </section>
    </>
  );
}

function ClientsPage() {
  const [name, setName] = useState("我的 OpenCode 客户端");
  const [manualName, setManualName] = useState("");
  const [platform, setPlatform] = useState<"powershell" | "shell">(
    /Windows/i.test(navigator.userAgent) ? "powershell" : "shell",
  );
  const [windowName, setWindowName] = useState("5h");
  const [enrollment, setEnrollment] = useState<ClientEnrollment | null>(null);
  const [clients, setClients] = useState<ClientDashboardItem[]>([]);
  const [issuedToken, setIssuedToken] = useState<{ name: string; token: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const loadClients = useCallback(() => {
    api<{ clients: ClientDashboardItem[] }>(
      `/api/admin/client-dashboard?window=${windowName}`,
    )
      .then((result) => setClients(result.clients || []))
      .catch((error) => setMessage((error as Error).message));
  }, [windowName]);

  useEffect(() => loadClients(), [loadClients]);
  useEffect(() => {
    const timer = setInterval(loadClients, 5000);
    return () => clearInterval(timer);
  }, [loadClients]);

  const generate = async () => {
    setBusy(true);
    setMessage("");
    try {
      setEnrollment(
        await api<ClientEnrollment>("/api/admin/client-enrollments", {
          method: "POST",
          body: JSON.stringify({ name }),
        }),
      );
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const createManual = async () => {
    setBusy(true);
    setMessage("");
    try {
      const result = await api<{ client: ClientToken; proxy_token: string }>(
        "/api/admin/client-tokens",
        { method: "POST", body: JSON.stringify({ name: manualName }) },
      );
      setIssuedToken({ name: result.client.name, token: result.proxy_token });
      setManualName("");
      loadClients();
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const rename = async (client: ClientDashboardItem) => {
    const next = prompt("新的客户端名称", client.name)?.trim();
    if (!next || next === client.name) return;
    try {
      await api(`/api/admin/client-tokens/${client.id}`, {
        method: "PATCH",
        body: JSON.stringify({ name: next }),
      });
      loadClients();
    } catch (error) {
      setMessage((error as Error).message);
    }
  };

  const revoke = async (client: ClientDashboardItem) => {
    if (!confirm(`删除“${client.name}”？该客户端密钥会立即失效，历史统计会保留。`)) return;
    try {
      await api(`/api/admin/client-tokens/${client.id}`, { method: "DELETE" });
      loadClients();
    } catch (error) {
      setMessage((error as Error).message);
    }
  };

  const origin = location.origin;
  const psQuote = (value: string) => value.replaceAll("'", "''");
  const shQuote = (value: string) => value.replaceAll("'", "'\"'\"'");
  const command = enrollment
    ? platform === "powershell"
      ? `& ([scriptblock]::Create((Invoke-RestMethod '${psQuote(origin)}/api/client/install.ps1'))) -Server '${psQuote(origin)}' -Ticket '${psQuote(enrollment.ticket)}'`
      : `curl -fsSL '${shQuote(origin)}/api/client/install.sh' | sh -s -- '${shQuote(origin)}' '${shQuote(enrollment.ticket)}'`
    : "";
  const totals = clients.reduce(
    (sum, client) => ({
      requests: sum.requests + client.requests,
      input: sum.input + client.input_uncached + client.cache_read + client.cache_write,
      output: sum.output + client.output_tokens,
      cacheRead: sum.cacheRead + client.cache_read,
    }),
    { requests: 0, input: 0, output: 0, cacheRead: 0 },
  );

  return (
    <>
      <PageHead kicker="CLIENT OPERATIONS" title="客户端面板">
        <div className="segmented">
          {["5h", "24h", "7d", "30d"].map((value) => (
            <button
              className={windowName === value ? "selected" : ""}
              onClick={() => setWindowName(value)}
              key={value}
            >
              {value}
            </button>
          ))}
        </div>
      </PageHead>
      <section className="stats-grid client-stats">
        <Stat label="客户端" value={clients.filter((v) => v.kind === "client" && v.active).length} detail="当前有效凭证" />
        <Stat label="请求" value={totals.requests} detail={`统计窗口 ${windowName}`} />
        <Stat label="输入 TOKEN" value={formatTokens(totals.input)} detail={`${formatTokens(totals.cacheRead)} cache read`} tone="mint" />
        <Stat label="输出 TOKEN" value={formatTokens(totals.output)} detail="所有客户端合计" />
      </section>
      <section className="client-grid">
        <article className="panel client-installer">
          <div className="panel-head">
            <div>
              <h3>一键配置 OpenCode</h3>
              <p className="muted">自动备份并合并全局配置，同时安装两组模型。</p>
            </div>
          </div>
          <label>
            客户端名称
            <input value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />
          </label>
          <div className="platform-tabs">
            <button className={platform === "powershell" ? "active" : ""} onClick={() => setPlatform("powershell")}>Windows PowerShell</button>
            <button className={platform === "shell" ? "active" : ""} onClick={() => setPlatform("shell")}>macOS / Linux</button>
          </div>
          {!enrollment ? (
            <button className="primary" disabled={busy || !name.trim()} onClick={generate}>
              {busy ? "正在生成…" : "生成一次性安装命令"}
            </button>
          ) : (
            <div className="install-command">
              <div className="command-meta">
                <strong>复制到{platform === "powershell" ? " PowerShell" : "终端"}执行</strong>
                <span>{countdown(enrollment.expires_at)}后失效</span>
              </div>
              <code>{command}</code>
              <div className="command-actions">
                <button className="primary compact" onClick={() => copyText(command)}>复制命令</button>
                <button className="secondary compact" onClick={generate} disabled={busy}>重新生成</button>
              </div>
            </div>
          )}
        </article>

        <article className="panel manual-client">
          <h3>手动添加客户端</h3>
          <p className="muted">为其他程序签发独立 API key，不修改任何本机配置。</p>
          <label>
            客户端名称
            <input value={manualName} maxLength={80} onChange={(event) => setManualName(event.target.value)} placeholder="例如：CI Runner" />
          </label>
          <button className="primary" disabled={busy || !manualName.trim()} onClick={createManual}>生成客户端密钥</button>
          {issuedToken && (
            <div className="rotated-token manual-token">
              <div>
                <strong>{issuedToken.name}（仅显示一次）</strong>
                <code>{issuedToken.token}</code>
              </div>
              <button onClick={() => copyText(issuedToken.token)}>复制</button>
            </div>
          )}
        </article>
      </section>

      <section className="panel client-performance-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">CLIENT USAGE</p>
            <h3>每客户端视角</h3>
          </div>
          <span className="muted">修改名称只影响显示；删除会立即撤销密钥</span>
        </div>
        <div className="client-performance">
          {clients.map((client) => {
            const input = client.input_uncached + client.cache_read + client.cache_write;
            const hit = input ? (client.cache_read / input) * 100 : 0;
            return (
              <div className={`client-performance-row ${client.active ? "" : "inactive"}`} key={client.id}>
                <div className="client-identity">
                  <strong>{client.name}</strong>
                  <span>{client.kind === "master" ? "主密钥" : client.active ? "有效" : "已删除"}</span>
                </div>
                <div>
                  <small>REQUESTS</small>
                  <strong>{client.requests}</strong>
                  <span>{client.failures} failed</span>
                </div>
                <div><small>INPUT</small><strong>{formatTokens(input)}</strong></div>
                <div><small>CACHE HIT</small><strong>{hit.toFixed(1)}%</strong></div>
                <div><small>OUTPUT</small><strong>{formatTokens(client.output_tokens)}</strong></div>
                <div><small>FAILOVER</small><strong>{client.failovers}</strong></div>
                <div><small>AVG LATENCY</small><strong>{client.avg_latency_ms} ms</strong></div>
                <div className="client-row-actions">
                  {client.kind === "client" && client.active && (
                    <>
                      <button onClick={() => rename(client)}>改名</button>
                      <button className="danger" onClick={() => revoke(client)}>删除</button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>
      {message && <div className="toast">{message}</div>}
    </>
  );
}

function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState("");
  const [newAccessKey, setNewAccessKey] = useState("");
  const [shownAccessKey, setShownAccessKey] = useState("");
  const [unifiedAccess, setUnifiedAccess] = useState<boolean | null>(null);
  useEffect(() => {
    api<Settings>("/api/admin/settings").then(setSettings);
    api<{ unified: boolean }>("/api/admin/access-key").then((value) =>
      setUnifiedAccess(value.unified),
    );
  }, []);
  if (!settings) return <div className="loading">载入设置…</div>;
  const save = async () => {
    try {
      const v = await api<Settings>("/api/admin/settings", {
        method: "PUT",
        body: JSON.stringify(settings),
      });
      setSettings(v);
      setSaved("已保存");
      setTimeout(() => setSaved(""), 2000);
    } catch (e) {
      setSaved((e as Error).message);
    }
  };
  const changeAccessKey = async () => {
    if (
      !confirm(
        "修改后，旧管理员密码和旧主代理 token 会立即失效；独立客户端密钥保持不变。继续吗？",
      )
    )
      return;
    try {
      const result = await api<{ access_key: string; unified: boolean }>(
        "/api/admin/access-key",
        { method: "PUT", body: JSON.stringify({ access_key: newAccessKey }) },
      );
      setShownAccessKey(result.access_key);
      setNewAccessKey("");
      setUnifiedAccess(result.unified);
    } catch (e) {
      setSaved((e as Error).message);
    }
  };
  return (
    <>
      <PageHead kicker="SYSTEM POLICY" title="设置">
        <button className="primary compact" onClick={save}>
          保存设置
        </button>
      </PageHead>
      <section className="settings-grid">
        <article className="panel">
          <h3>恢复与探测</h3>
          <Toggle
            label="自动探测额度恢复"
            detail="关闭后，到期 key 等待真实业务请求或手动探测。"
            value={settings.auto_probe_enabled}
            onChange={(v) =>
              setSettings({ ...settings, auto_probe_enabled: v })
            }
          />
          <label>
            探测模型
            <input
              value={settings.probe_model}
              onChange={(e) =>
                setSettings({ ...settings, probe_model: e.target.value })
              }
            />
            <small>
              使用 OpenAI-compatible 接口发送 2 个输出 token 的最小请求。
            </small>
          </label>
          <label>
            未知恢复时间的探测间隔（秒）
            <input
              type="number"
              min="60"
              value={settings.probe_interval_sec}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  probe_interval_sec: Number(e.target.value),
                })
              }
            />
          </label>
        </article>
        <article className="panel">
          <h3>统计与模型目录</h3>
          <Toggle
            label="请求流式 usage"
            detail="为兼容的 OpenAI 流请求补充 include_usage；若某模型拒绝该参数，可在此关闭。"
            value={settings.force_stream_usage}
            onChange={(v) =>
              setSettings({ ...settings, force_stream_usage: v })
            }
          />
          <label>
            模型列表缓存（秒）
            <input
              type="number"
              min="30"
              value={settings.models_cache_sec}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  models_cache_sec: Number(e.target.value),
                })
              }
            />
            <small>
              模型列表不受推理 quota
              状态影响，并在上游故障时返回最后一次成功缓存。
            </small>
          </label>
        </article>
        <article className="panel deployment">
          <div className="panel-head">
            <h3>主访问密钥与接入信息</h3>
            <span className={`access-state ${unifiedAccess ? "unified" : "legacy"}`}>
              {unifiedAccess ? "已统一" : "待统一"}
            </span>
          </div>
          {unifiedAccess === false && (
            <p className="setup-notice access-notice">
              这是旧版本升级实例。当前管理员密码和主代理 token 仍分别有效；在下方修改一次后会统一为同一条主访问密钥。
            </p>
          )}
          <div className="access-key-editor">
            <label>
              新主访问密钥
              <input
                type="password"
                value={newAccessKey}
                onChange={(event) => setNewAccessKey(event.target.value)}
                placeholder="留空则由服务端随机生成"
              />
              <small>长度 16–256 个字符，同时用于面板登录和主 API 鉴权。</small>
            </label>
            <button className="secondary" onClick={changeAccessKey}>
              {newAccessKey ? "保存新主密钥" : "随机生成并更换"}
            </button>
          </div>
          <dl>
            <div>
              <dt>OpenAI-compatible Base URL</dt>
              <dd>{location.origin}/v1</dd>
            </div>
            <div>
              <dt>Anthropic Base URL</dt>
              <dd>{location.origin}/v1</dd>
            </div>
            <div>
              <dt>鉴权</dt>
              <dd>Authorization: Bearer &lt;主访问密钥或客户端密钥&gt;</dd>
            </div>
            <div>
              <dt>监听</dt>
              <dd>0.0.0.0:8080</dd>
            </div>
          </dl>
          {shownAccessKey && (
            <div className="rotated-token">
              <div>
                <strong>新主访问密钥（请立即保存）</strong>
                <code>{shownAccessKey}</code>
              </div>
              <button onClick={() => copyText(shownAccessKey)}>复制</button>
            </div>
          )}
        </article>
      </section>
      {saved && <div className="toast">{saved}</div>}
    </>
  );
}
function Toggle({
  label,
  detail,
  value,
  onChange,
}: {
  label: string;
  detail: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button className="toggle-row" onClick={() => onChange(!value)}>
      <div>
        <strong>{label}</strong>
        <span>{detail}</span>
      </div>
      <i className={value ? "on" : ""}>
        <b />
      </i>
    </button>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
