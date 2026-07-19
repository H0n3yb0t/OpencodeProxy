# OpencodeProxy

面向个人部署的 OpenCode Go 主备故障转移代理。OpencodeProxy 固定使用当前活动 key；仅在确认额度耗尽或凭证失效，且请求尚未向客户端输出内容时切换到下一枚独立 key。

## 功能

- 同时代理 OpenAI-compatible `POST /v1/chat/completions` 与 Anthropic-compatible `POST /v1/messages`
- `GET /v1/models` 使用独立控制面状态和缓存，不受推理 quota 冷却影响
- 识别 5 小时、周、月额度错误并显示恢复倒计时
- 可全局或逐 key 关闭自动恢复探测
- 支持每行一个 key 的批量导入、去重和导入结果汇总
- AES-GCM 加密保存上游 key，UI 只显示指纹
- 统计输入、输出、cache read、cache write、TTFT、延迟和故障转移
- 最近 100 条请求流水，不保存 prompt 和模型输出
- 单管理员 Web UI、SQLite 持久化、单容器部署

## Docker Compose 部署

```powershell
docker compose up -d --build
```

打开 `http://服务器地址:8080`，在首次运行页面点击“一键初始化”。OpencodeProxy 会自动生成：

- 管理员密码
- 客户端代理 token
- 数据恢复密钥

三项凭据只在初始化结果页显示一次，可以一键复制或下载为文本文件。确认保存后直接进入控制台。

应用监听 `0.0.0.0:8080`。公网部署必须配置 HTTPS 反向代理和防火墙。

> 尚未初始化时，第一个访问初始化页面的人可以取得管理权。不要把全新实例直接暴露在不可信公网。初始化完成后，管理 UI 和推理 API 都需要鉴权。

初始化是原子单次操作。完成后初始化接口关闭并返回 `404 Not Found`，已生成的凭据无法通过该接口再次读取或重置。代理 token 只能由已登录管理员在设置页轮换。

配置、加密主密钥和数据库保存在 Docker 数据卷 `opencodeproxy-data`。备份和迁移时应备份整个数据卷，并单独安全保存恢复密钥。

也可以将宿主机目录绑定到 `/data`：

```yaml
volumes:
  - ./data:/data
```

容器启动时会校正该目录的所有权，然后以非 root 用户运行服务。默认 UID/GID 均为 `10001`。NAS 目录使用特定所有者时，可以通过 `PUID` 和 `PGID` 指定运行身份：

```yaml
environment:
  PUID: "1000"
  PGID: "1000"
```

绑定目录所在的文件系统必须允许对应 UID/GID 写入。NFS root-squash 等不允许容器执行 `chown` 的存储，应先将目录递归设置为 `PUID:PGID`，或使用默认 Docker 命名卷。

### 无人值守初始化

自动化部署可以同时提供 `MASTER_KEY`、`ADMIN_PASSWORD` 和 `PROXY_TOKEN` 环境变量。`MASTER_KEY` 必须是 Base64 编码的 32 字节密钥；缺少其中任意一项都会导致服务拒绝启动。通过环境变量建立实例身份后，Web 初始化入口保持关闭。

### Docker 镜像发布

GitHub Actions 工作流会将 `master` 分支的每次推送构建为 `h0n3yb0t/opencodeproxy:latest`，并同时发布对应的 `sha-*` 标签。推送 `v1.2.3` 格式的 Git tag 时，还会发布 `v1.2.3`、`1.2.3` 和 `1.2` 标签。镜像包含 `linux/amd64` 与 `linux/arm64` 两个平台。

仓库需要配置 Actions secret `DOCKERHUB_TOKEN`，其值为具备 Docker Hub 仓库读写权限的 Personal Access Token。发布任务也可以从 GitHub Actions 页面手动触发。

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

$env:DATABASE_PATH = ".tmp/opencodeproxy.db"
go run ./cmd/opencodeproxy
```

打开 `http://127.0.0.1:8080` 完成 Web 初始化。

测试：

```powershell
go test ./...
```

## 运行边界

- 部署拓扑为单实例，不能让多个副本同时读写同一个 SQLite 数据卷。
- 额度状态来自上游推理错误和本地请求统计，不接入 OpenCode Dashboard Cookie，因此不提供官方剩余额度百分比。
- token usage 按上游响应记录，不换算为官方美元额度。
