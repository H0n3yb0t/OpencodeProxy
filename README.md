# OpenPool

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

不需要创建 `.env` 或手动生成任何密钥：

```powershell
docker compose up -d --build
```

打开 `http://服务器地址:8080`，在首次运行页面点击“一键初始化”。OpenPool 会自动生成：

- 管理员密码
- 客户端代理 token
- 数据恢复密钥

三项凭据只在初始化结果页显示一次，可以一键复制或下载为文本文件。确认保存后直接进入控制台。

应用监听 `0.0.0.0:8080`。管理 UI 和推理接口都有鉴权，但如果跨公网访问，仍应在前面配置 HTTPS 反向代理和防火墙。

> 尚未初始化时，第一个访问初始化页面的人可以取得管理权。不要把全新实例直接暴露在不可信公网。初始化完成后，管理 UI 和推理 API 都需要鉴权。

所有配置、加密主密钥和数据库都保存在 Docker 数据卷 `openpool-data`。备份和迁移时应备份整个数据卷；恢复密钥也应单独安全保存。

## 客户端接入

OpenAI-compatible：

```text
Base URL: http://服务器地址:8080/v1
API Key:  初始化页面生成的代理 token
```

Anthropic-compatible：

```text
Base URL: http://服务器地址:8080/v1
API Key:  初始化页面生成的代理 token
```

示例：

```powershell
$proxyToken = "粘贴初始化页面生成的代理 token"
$headers = @{ Authorization = "Bearer $proxyToken" }
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

后端需要 Go 1.25 或更高版本，前端需要 Node.js 22 或更高版本。

```powershell
cd web
npm install
npm run build
cd ..

$env:DATABASE_PATH = ".tmp/openpool.db"
go run ./cmd/keypool
```

随后打开 `http://127.0.0.1:8080` 完成 Web 初始化。原有的 `ADMIN_PASSWORD`、`PROXY_TOKEN`、`MASTER_KEY` 环境变量仍作为向后兼容的高级部署方式保留，但普通部署不需要使用。

默认部署不会读取或写入宿主机的 `.env`。初始化资格由持久卷中的 `/data/instance.json` 决定：仅当实例身份不存在且未通过旧式环境变量提供身份时，Web UI 才显示初始化页。初始化成功后，后端立即关闭初始化接口；刷新页面或并发重复请求都不能重新生成、轮换或再次读取凭据。此时再次请求初始化接口只会得到 `404 Not Found`。代理 Token 后续只能由已登录管理员在设置页主动轮换。

测试：

```powershell
go test ./...
```

## 运行边界

- 当前只支持单实例。不要在同一个 SQLite 数据卷上运行多个副本。
- 不抓取 OpenCode Dashboard Cookie，也不伪造精确剩余额度百分比。
- 模型和价格会变化；当前版本记录上游 token usage，但不把 token 总数伪装成官方美元额度。
