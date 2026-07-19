# OpenCode Keypool

面向个人部署的 OpenCode Go 主备故障转移代理。它会坚持使用当前活动 key；只有确认额度耗尽或凭证失效时，才在同一请求尚未向客户端输出内容的情况下切换到下一枚独立 key。

## 功能

- 同时代理 OpenAI-compatible `POST /v1/chat/completions` 与 Anthropic-compatible `POST /v1/messages`
- `GET /v1/models` 使用独立控制面状态和缓存，不受推理 quota 冷却影响
- 识别 5 小时、周、月额度错误并显示恢复倒计时
- 可全局或逐 key 关闭自动恢复探测
- AES-GCM 加密保存上游 key，UI 只显示指纹
- 统计输入、输出、cache read、cache write、TTFT、延迟和故障转移
- 最近 100 条请求流水，不保存 prompt 和模型输出
- 单管理员 Web UI、SQLite 持久化、单容器部署

## Docker Compose 部署

复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

生成主加密密钥和代理 token：

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)

$tokenBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
[Convert]::ToHexString($tokenBytes).ToLowerInvariant()
```

把生成值写入 `.env` 的 `MASTER_KEY` 和 `PROXY_TOKEN`，同时修改管理员密码，然后启动：

```powershell
docker compose up -d --build
```

管理页面：`http://服务器地址:8080`

应用监听 `0.0.0.0:8080`。管理 UI 和推理接口都有鉴权，但如果跨公网访问，仍应在前面配置 HTTPS 反向代理和防火墙。

> `MASTER_KEY` 丢失后无法解密数据库中的 OpenCode key。备份数据卷时也要安全备份这个值。

## 客户端接入

OpenAI-compatible：

```text
Base URL: http://服务器地址:8080/v1
API Key:  .env 中的 PROXY_TOKEN
```

Anthropic-compatible：

```text
Base URL: http://服务器地址:8080/v1
API Key:  .env 中的 PROXY_TOKEN
```

示例：

```powershell
$headers = @{ Authorization = "Bearer $env:KEYPOOL_PROXY_TOKEN" }
$body = @{
  model = "mimo-v2.5"
  messages = @(@{ role = "user"; content = "Reply with OK" })
  max_tokens = 2
} | ConvertTo-Json -Depth 10
Invoke-RestMethod http://127.0.0.1:8080/v1/chat/completions -Method Post -Headers $headers -ContentType application/json -Body $body
```

## 状态语义

模型列表成功只会证明 key 鉴权有效、OpenCode 控制面可访问，不会把推理额度标记为可用。额度冷却结束后，只有最小推理探测或真实业务请求成功，key 才会恢复为 `available`。

流式请求一旦向客户端发送了正常事件，就不会自动从另一枚 key 重放，以避免重复生成和重复消耗。网络超时和普通 5xx 默认也不会触发 key 切换。

统计只反映经过本代理且上游返回 usage 的请求。Dashboard 中的 usage 覆盖率用于提示数据完整程度；其他地方直接使用同一账户产生的用量不会出现在本地统计中。

## 本地开发

后端需要 Go 1.24 或更高版本，前端需要 Node.js 22 或更高版本。

```powershell
cd web
npm install
npm run build
cd ..

$env:ADMIN_PASSWORD = "dev-password"
$env:PROXY_TOKEN = "dev-proxy-token"
$env:MASTER_KEY = "一个 Base64 编码的 32 字节随机值"
$env:DATABASE_PATH = ".tmp/keypool.db"
go run ./cmd/keypool
```

测试：

```powershell
go test ./...
```

## 运行边界

- 当前只支持单实例。不要在同一个 SQLite 数据卷上运行多个副本。
- 不抓取 OpenCode Dashboard Cookie，也不伪造精确剩余额度百分比。
- 模型和价格会变化；当前版本记录上游 token usage，但不把 token 总数伪装成官方美元额度。

