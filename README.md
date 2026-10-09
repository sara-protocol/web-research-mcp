# Web Research MCP Server — 可部署 MVP

一个只读 Web 研究 MCP 服务，使用 MCP 官方 TypeScript SDK 的 **Streamable HTTP** 传输。设计目标是让多个 AI 客户端连接同一个服务端，而不是给每个客户端重复配置一套爬取逻辑。

## 当前功能

- `web_search`：通过 Brave Search API 搜索公开网页，返回标题、URL、摘要。
- `fetch_page`：抓取公开 HTTP(S) 网页并提取可读正文。
- `web_research_bundle`：先搜索，再抓取最多 3 个结果页，返回带 URL 的材料。
- `/mcp`：远程 MCP 端点，必须使用 Bearer token。
- `/public/mcp`：可选的无认证、只读端点，供 ChatGPT 网页端在只提供 OAuth/无认证选项时测试接入；默认关闭，并启用每 IP 频率限制和进程内每日搜索上限。
- `/healthz`：健康检查。

## 架构

```text
ChatGPT web ─────────── HTTPS ── /public/mcp (optional, no auth, rate-limited)
Claude Code ─────────── HTTPS ── /mcp (Bearer token)
Cursor ──────────────── HTTPS ── /mcp (Bearer token)
Your Agent / Responses API ───── /mcp (Bearer token)
                                  │
                         Web Research MCP
                         ├── Brave Search API
                         └── Public webpage fetch/extraction
```

远程客户端需要访问服务器的 HTTPS URL。Compose 默认只把服务绑定到服务器本机的 `127.0.0.1:8787`，建议在前面放 Caddy/Nginx/Cloudflare Tunnel 等 HTTPS 反向代理，不要直接把应用端口开放到公网。

## 1. 前置条件

- Docker Engine + Docker Compose plugin。
- 一个域名（生产部署建议）和 HTTPS 反向代理/隧道。
- Brave Search API key（`web_search` 和 `web_research_bundle` 必需）。
- 至少 32 字符的随机 `MCP_BEARER_TOKEN`。

示例生成 token：

```bash
openssl rand -hex 32
```

## 2. 配置和启动

### Windows + Docker Desktop（PowerShell）

在解压目录打开 PowerShell，先运行：

```powershell
.\scripts\windows-quickstart.ps1
notepad .env
```

脚本会复制 `.env.example` 并随机生成 `MCP_BEARER_TOKEN`；请在 `.env` 中填写 `BRAVE_SEARCH_API_KEY` 后保存。然后运行：

```powershell
docker compose up -d --build
docker compose logs -f web-mcp
Invoke-RestMethod http://127.0.0.1:8787/healthz
```

### Linux / macOS

```bash
cp .env.example .env
# Edit .env, add a random token and your Brave Search API key
```

编辑 `.env`：填写 `MCP_BEARER_TOKEN` 和 `BRAVE_SEARCH_API_KEY`。默认 `PUBLIC_MCP_ENABLED=false`，先启动受保护的端点：

```bash
docker compose up -d --build
docker compose logs -f web-mcp
curl http://127.0.0.1:8787/healthz
```

运行冒烟测试：

```bash
# Linux/macOS
export MCP_BEARER_TOKEN='你的 token'
npm install
npm run smoke
```

若只用 Docker 运行且宿主机没有 Node，可用 `docker compose exec web-mcp node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>r.text()).then(console.log)"` 检查健康状态。

## 3. 配置 HTTPS 入口

让反向代理把 `https://YOUR_DOMAIN/mcp` 转发到 `http://127.0.0.1:8787/mcp`，并保留 POST 请求、`Authorization` 头和 MCP 的 `application/json` / `text/event-stream` 响应。若代理缓冲 SSE/流式响应，请关闭该路径的响应缓冲。仓库附有 `Caddyfile.example`，适用于 Caddy 安装在宿主机、应用端口仅绑定到 `127.0.0.1:8787` 的部署方式。域名 DNS 应指向服务器，且公网 80/443 端口按 Caddy 自动 HTTPS 的要求开放。

注意：`compose.yaml` 只发布到回环接口，这是有意的。请不要把 `8787` 直接暴露在公网。

## 4. 连接 Cursor

将 `configs/cursor-mcp.json` 的内容合并到 Cursor 全局 `~/.cursor/mcp.json`，或者当前项目的 `.cursor/mcp.json`。把 `YOUR_DOMAIN.example` 替换为真实域名，并在启动 Cursor 的环境中设置 `WEB_MCP_TOKEN`。

Windows PowerShell 示例：

```powershell
[Environment]::SetEnvironmentVariable('WEB_MCP_TOKEN', '你的token', 'User')
```

重新启动 Cursor，在 MCP 设置页检查连接状态。Cursor 的配置变量支持 `${env:WEB_MCP_TOKEN}`；如果你的 Cursor 版本不展开它，请按该版本文档将 token 放在环境变量或本机私密配置中，不要提交进 Git。

## 5. 连接 Claude Code

按 `configs/claude-code.md` 的命令注册远程 HTTP MCP：

```bash
export WEB_MCP_TOKEN='与服务端 MCP_BEARER_TOKEN 相同的值'
claude mcp add --transport http --scope user \
  --header "Authorization: Bearer ${WEB_MCP_TOKEN}" \
  web-research https://YOUR_DOMAIN.example/mcp
claude mcp list
```

在 Claude Code 执行 `/mcp` 查看连接状态。若你指的是 Claude Desktop GUI 而不是 Claude Code，请先确认该版本是否支持远程 HTTP MCP；也可通过官方支持的本地/远程桥接方式接入。

## 6. 连接 ChatGPT 网页端

ChatGPT 官方当前文档列出的自定义 MCP 认证方式是 OAuth、No authentication 或 OAuth/No authentication 组合；它不像本项目的 Cursor/Claude Code 配置那样直接填普通 Bearer Token。为此，本项目将 ChatGPT 的测试端点单独设为可选的 **无认证只读入口**：`/public/mcp`。它默认关闭。

仅在了解该端点会被互联网上任何知道 URL 的人访问、且只想测试公开网页搜索/抓取时才启用：

1. 在 `.env` 中设置 `PUBLIC_MCP_ENABLED=true`。
2. 设置较低的 `PUBLIC_PER_MINUTE_LIMIT`（默认 12）和 `PUBLIC_DAILY_SEARCH_LIMIT`（默认 100）。
3. 重建：`docker compose up -d --build`。
4. 在 ChatGPT 网页端，若账户/工作区提供“Add custom MCP server”或相应自定义应用入口，填入 `https://YOUR_DOMAIN/public/mcp`，选择 **No authentication**，安装后在对话中明确调用该连接。

**生产风险说明：** 无认证端点是公开端点；速率/每日限制只保存在进程内，重启会重置，多实例部署也不会共享计数。正式对外服务应增加 OAuth 2.1、持久化限额、日志监控与滥用检测。不要在此端点加入私有数据、写入类工具或昂贵的其他 API。若账户没有自定义 MCP 入口，该服务仍可正常供 Cursor、Claude Code 和 API Agent 使用；无需为了 ChatGPT UI 而牺牲安全性。

## 7. 接入你自己的 Agent

任何支持 MCP Streamable HTTP 的客户端都可以连接 `https://YOUR_DOMAIN/mcp` 并发送 `Authorization: Bearer <token>`。`examples/openai-responses-agent.mjs` 展示了 OpenAI Responses API 的接入方式：

```bash
npm install openai
export OPENAI_API_KEY='...'
export MCP_SERVER_URL='https://YOUR_DOMAIN/mcp'
export MCP_BEARER_TOKEN='你的 token'
node examples/openai-responses-agent.mjs
```

请按你账户可用的模型更新 `OPENAI_MODEL`。示例将工具调用审批设为 `always`，便于测试和审查。

## 8. 用 MCP Inspector 做端到端检查

在能访问该服务的机器运行：

```bash
npx @modelcontextprotocol/inspector@latest
```

选择 Streamable HTTP，URL 填 `https://YOUR_DOMAIN/mcp`，并在请求头中配置 `Authorization: Bearer <token>`。连接后检查 Tools 列表，再测试 `web_search` 和 `fetch_page`。

## 安全设计与边界

- 只读工具，不提供发帖、购买、登录、表单提交或网站修改能力。
- 页面抓取只允许 HTTP(S)、默认端口 80/443；阻止 localhost、私网/保留 IP、含凭据 URL、非标准端口、非 HTML/纯文本响应、过大页面和过多重定向。
- 对 DNS 解析结果做公共地址校验，并将校验后的地址固定到本次连接，降低 SSRF/DNS rebinding 风险。
- 仍建议在生产环境加出站防火墙、请求/响应日志、可观测性、持久化限额和依赖更新扫描。
- 网页正文是不可信的外部输入，可能包含提示注入内容；AI 应将其作为资料而不是指令。
- Brave API 的费用、配额与条款由你的 Brave 账号决定；本项目不会提供 API key。

## 排错

- **`web_search` 提示未配置 key**：检查 `.env` 的 `BRAVE_SEARCH_API_KEY`，然后 `docker compose up -d --build`。
- **401**：检查客户端的 token 是否与 `.env` 中 `MCP_BEARER_TOKEN` 完全一致。
- **ChatGPT 无法连接 `/mcp`**：该端点要求 Bearer token；ChatGPT UI 当前认证方式不同，请用 `/public/mcp` 做只读验证，或为正式使用实现 OAuth 2.1。
- **远程客户端超时/初始化失败**：确认 URL 为 HTTPS 且以 `/mcp` 或 `/public/mcp` 结尾，反向代理没有删掉 `Authorization` 请求头，也没有缓冲/中断流式响应。
- **抓取某些网站失败**：网站可能需要 JavaScript、登录、反机器人验证，或返回了不支持的内容类型。本 MVP 不运行浏览器、不绕过登录或反机器人措施。

## 下一阶段建议

将 MVP 升级为生产版时，优先做：OAuth 2.1（统一客户端身份）、可持久化配额与审计日志、站点许可/robots 约束、搜索缓存、测试矩阵与 CI、部署到固定域名的自动更新流水线。
