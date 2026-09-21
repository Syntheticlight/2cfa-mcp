# 2cfa-mcp - Conversational 2FA Remote MCP Server in Go

[中文文档](#中文文档) | [English Documentation](#english-documentation)

---

<a name="中文文档"></a>
# 中文文档

`2cfa-mcp` 是一个专为 **Android Termux（手机后台保活）**、**轻量 Linux VPS（如 512MB 廉价机）**、**树莓派** 等边缘设备打造的**极轻量、高安全、开箱即用**的远程 **Model Context Protocol (MCP)** 服务端。

专用于将 **ChatGPT Web** 及各类远程 AI Agent 通过 **Cloudflare Tunnel** 或 **FRP** 安全桥接到你的私有边缘设备，并首创**对话内原生 2FA 解锁 + 隐式租约通行证**机制。

---

## 目录
- [为什么选择 2cfa-mcp？](#为什么选择-2cfa-mcp)
- [核心设计：三种使用模式（一分钟看懂权限逻辑）](#核心设计三种使用模式一分钟看懂权限逻辑)
- [核心 MCP 工具集](#核心-mcp-工具集)
- [第一部分：服务端极速部署与公网穿透](#第一部分服务端极速部署与公网穿透)
- [第二部分：在 ChatGPT 网页版中添加 MCP 服务（核心教程）](#第二部分在-chatgpt-网页版中添加-mcp-服务核心教程)
- [第三部分：日常对话与 2FA 实战演练](#第三部分日常对话与-2fa-实战演练)
- [可视化安全控制台与健康审计](#可视化安全控制台与健康审计)
- [English Documentation](#english-documentation)
- [License](#license)

---

## 为什么选择 2cfa-mcp？

1. **告别 Node.js 内存笨重**：传统基于 Node.js 的 MCP 服务动辄消耗 100MB~150MB V8 内存，手机后台频繁被杀。本项目采用 Go 1.26.8+ 编写，运行时常驻内存仅 **10MB ~ 15MB RAM**，单文件静态二进制仅 **~8MB**。
2. **彻底解决未鉴权泄密隐患**：重构了社区项目中未鉴权 `/health` 导致 Token 泄露的致命隐患，实现全链路零泄露设计（Zero-Leakage）与基于 `filepath.Clean` 的强制路径防穿越保护。
3. **首创对话内隐式租约机制**：在对话中直接报一次 6 位 TOTP 动态码完成解锁，签发隐式凭证（`lease_token`）。AI 在后台数据流中静默携带，聊天界面干干净净，无惧底层网络重连与掉线！

---

## 核心设计：三种使用模式（一分钟看懂权限逻辑）

整个项目的权限模型极其直观，**本质上只有以下 3 种使用情况**：

| 模式 | 配置与状态 | 权限与体验 | 适用人群/场景 |
| :--- | :--- | :--- | :--- |
| **1. Token 直连模式（默认）** | 不配置/不开启 2FA，仅设 `AUTH_TOKEN` | **只要 Token 对，就拥有全部权限！** 所有命令和读写工具秒级直通运行，零拦截、零弹窗、零打扰。 | **本地用户 / 局域网用户 / 个人极简自用** |
| **2. 对话 2FA 会话模式** | 对话中开启 2FA，报一次 6 位动态码 | **报一次码即可获得隐式通行证！** 默认无时间过期，网络重连不掉线；直到显式锁门/撤销、2FA 更换或服务重启才失效。它是 bearer lease，并非与某个聊天线程密码学绑定。 | **公网暴露（如 CF 穿透）但自己长期使用** |
| **3. 对话 2FA 限时模式** | 对话中指定开闸时间（如“*帮我开门 30 分钟*”） | **时效内带隐式通行证有全部权限，超时自动锁死！** 超过设定时间后自动撤销凭证，需重新报验证码解锁。 | **临时借给他人使用 / 在不可信公共设备上操作** |

---

## 核心 MCP 工具集

> 💡 **重要说明**：**默认情况下所有核心工具均为 100% 直通可用，不需要任何 2FA 验证码！**  
> 本地或日常使用只要填了 `AUTH_TOKEN`，即可直接调用所有命令和读写工具。2FA 只是一个完全可选的公网防护盾牌，平时根本不需要碰它。

### 1. 日常核心生产力工具（默认直接可用，无门槛）

| 工具名称 | 主要功能 | 常用参数 |
| :--- | :--- | :--- |
| `execute_command` | 执行 Shell 命令（支持自定义长耗时任务与运行时有界输出捕获） | `command` (命令), `work_dir` (可选目录), `timeout_seconds` (正数最多 7 天，`-1` 为无限) |
| `read_file` | 读取工作区内指定文件（强制防路径穿越保护） | `path` (文件相对路径) |
| `write_file` | 写入或覆盖工作区文件（自动递归创建父级目录） | `path` (文件相对路径), `content` (写入内容) |
| `list_dir` | 结构化列出指定目录下的文件与文件夹（单次最多返回 2000 项） | `path` (可选目录路径，留空为根目录) |
| `system_status` | 查看 OS/架构、逻辑 CPU 数、Go 进程内存、运行时间及版本更新状态 | 无需任何参数 |
| `check_update` | 检查 GitHub 是否有新版本发布与更新日志 | `force` (可选是否强制跳过缓存) |

> ⚠️ **Shell 权限边界**：`work_dir` 只限制命令的**起始工作目录**。由于 `execute_command` 提供的是完整 Shell，它会继承 2cfa-mcp 进程本身的系统权限，并不是 chroot/bwrap 级文件系统沙箱。真正需要只读/只写 workspace 时，请优先使用 `read_file` / `write_file` / `list_dir`，这些工具会执行路径穿越与符号链接逃逸检查。

> 🧩 **结构化返回**：v1.0.10 起，全部工具都会向支持 MCP structured content 的客户端公开 `outputSchema`。成功结果同时包含机器可读 `structuredContent` 和人类可读文本，因此旧客户端仍兼容；例如 `execute_command` 会直接提供 `stdout`、`stderr`、`exit_code`、`duration_ms`、截断状态等字段。

> **文件路径与超时行为**：文件工具通过 `os.Root` 在实际读写时限制工作区边界，防止符号链接在检查后被替换造成越界。支持指向工作区内部的相对符号链接；绝对符号链接会被拒绝，即使目标位于工作区内部。命令超时也会返回结构化的部分输出，并标记 `timed_out=true` 和 MCP 工具错误。

### 2. 可选 2FA 安全门禁工具（仅当你主动开启 2FA 时才需要）

*如果你只是本地使用或局域网使用，以下 3 个工具完全可以忽略，平时不需要使用它们：*

> 🔐 一旦 2FA 已启用，**仅凭 AUTH_TOKEN 不能关闭或重置 2FA**。关闭/重新配置必须额外提供有效 `lease_token` 或当前 TOTP 验证码。同一 TOTP 时间步只能成功使用一次，并对连续失败尝试进行限速。

| 工具名称 | 主要功能 | 触发时机 |
| :--- | :--- | :--- |
| `setup_2fa` | 在对话中开启/关闭 2FA，或配置 TOTP 密钥 | 仅在你想给服务加一道动态锁时调用 |
| `unlock_gate` | 校验 6 位验证码并临时开闸 | 仅在开启了 2FA 且锁死时调用一次 |
| `lock_gate` | 物理锁死安全门，注销所有凭证 | 临时离开电脑或需要紧急锁门时调用 |

---

## 第一部分：服务端极速部署与公网穿透

### 1. 克隆与环境准备
```bash
git clone https://github.com/Syntheticlight/2cfa-mcp.git
cd 2cfa-mcp

cp .env.example .env
vim .env  # 或使用 nano/文本编辑器
```
在 `.env` 中填入你的专有安全密钥：
```ini
PORT=2232
AUTH_TOKEN=your-high-entropy-url-safe-token-here
WORKSPACE_PATH=./workspace
EXEC_TIMEOUT=120
ENABLE_2FA_GATE=false
TOTP_SECRET=
```
*(注：`ENABLE_2FA_GATE` 建议保持 `false`，后续在与 ChatGPT 对话中可随时动态开启)*

> 🔐 **密钥配置**：`AUTH_TOKEN` 与 `TOTP_SECRET` 只从环境变量或 `.env` 读取，不接受命令行参数，避免出现在 `ps` / `/proc/.../cmdline`。如果使用默认 URL Path Token 模式，建议用 `openssl rand -hex 32` 生成 URL-safe Token。手工设置 `ENABLE_2FA_GATE=true` 时必须同时提供有效 `TOTP_SECRET`，否则服务会拒绝启动。

### 2. 编译服务端
- **本机编译**：
  ```bash
  make build
  ```
- **交叉编译（Android Termux 原生静态版）**：
  ```bash
  make build-android-arm64
  ```
- **交叉编译（Linux ARM64 / 树莓派）**：
  ```bash
  make build-linux-arm64
  ```
- **交叉编译（Linux VPS AMD64）**：
  ```bash
  make build-linux-amd64
  ```

### 3. 启动守护进程与 Cloudflare 隧道
> ⚠️ **升级说明**：如果你是从 `v1.0.4` 或更早版本升级，建议先执行 `git pull`（或重新克隆仓库）再运行 `./scripts/daemon.sh update`。旧版 `daemon.sh` 只会替换二进制，不会自动更新自身，因此拿不到 v1.0.5+ 新增的 argv 脱敏、日志轮转和 SHA-256 校验逻辑。

> 🛡️ **v1.0.7 安全加固**：SSE 长连接不再受全局写超时影响；显式系统环境变量优先于 `.env`；CI/Release 会执行 `govulncheck ./...`；最低 Go 工具链提升到包含标准库安全修复的 1.26.8，并将 `golang.org/x/text` 升级到已修复 GO-2026-5970 的版本。

> 🛡️ **v1.0.8 开源加固**：Release 构建与发布写权限隔离；CI 增加 Go race detector；`.env` 启动时收紧到 `0600`；命令审计不再保存命令参数；活动 lease 数量有界；目录列表和正数执行超时增加上限；Dashboard 增加 no-referrer/no-store/CSP 等浏览器安全头。

> 🛡️ **v1.0.9 深度加固**：URL Token 日志改为结构化脱敏；敏感密钥不再允许出现在 CLI argv；文件读取在流式读取阶段强制 10MB 上限；Supervisor 使用精确 PID 停止进程；GitHub Actions 锁定 immutable commit SHA，并由 Dependabot 自动跟踪 Go/Actions 更新。

> 🧩 **v1.0.10 结构化输出升级**：全部 10 个 MCP 工具声明标准 `outputSchema`，成功调用同时返回 `structuredContent` 与原有文本 fallback。ChatGPT/Agent 可直接读取稳定 JSON 字段，不再依赖解析自然语言文本；服务端同时启用 output schema 运行时校验。

> 🛡️ **v1.0.11 运行时与安全加固**：工作区文件操作引入 `os.Root` 目录隔离，防止外部软链接逃逸与检查-使用竞态；2FA 管理操作同一锁内原子校验并支持配置变更后立即注销待确认密钥；严格校验租约有效时长；优化 HTTP 传输层路由与版本更新并发检查。

项目自带高可用 Supervisor 脚本，支持进程自愈重启与 Termux 唤醒锁防休眠：
```bash
chmod +x scripts/daemon.sh

# 启动后台常驻服务
./scripts/daemon.sh start

# 查看状态
./scripts/daemon.sh status

# 一键平滑安全升级至最新版（v1.0.5+ 会校验 Release 的 SHA256SUMS，校验失败拒绝替换二进制）
./scripts/daemon.sh update

# 一键启动 Cloudflare 免费公网隧道
./scripts/daemon.sh cloudflared
```
终端会输出一个免费公网临时域名，形如：
```text
https://xxx-xxx-xxx.trycloudflare.com
```

---

## 第二部分：在 ChatGPT 网页版中添加 MCP 服务（核心教程）

`2cfa-mcp` 同时支持标准 SSE（Server-Sent Events）与 Streamable HTTP 协议，并针对 Web 客户端特意设计了 **URL Path Token 双模鉴权**。

### 方式一：ChatGPT 网页版 原生 MCP / Developer Connectors（推荐）

1. 打开并登录 [ChatGPT 网页版](https://chatgpt.com)。
2. 点击左下角个人头像或进入 **Settings（设置）**。
3. 进入 **Connect an app（连接应用）** 或 **Developer（开发者）/ Connected Accounts** 页面。
4. 点击 **Add MCP Server（添加 MCP 服务）** 或 **New Remote Connection**。
5. 填写连接配置：
   - **Name（名称）**：`2cfa-mcp`
   - **Type（传输类型）**：选择 `SSE`
   - **Server URL（服务地址）**：
     > **【推荐免 Header 模式（URL 鉴权）】**  
     > 由于部分浏览器及 WebHook 场景无法向 SSE 请求中附加自定义 HTTP Header，`2cfa-mcp` 原生支持直接将 Token 编入路径：  
     > `https://<你的穿透域名>/mcp/<你的AUTH_TOKEN>/sse`  
     > *示例：`https://xxx.trycloudflare.com/mcp/your-high-entropy-url-safe-token-here/sse`*
     >
     > **【标准 Header 模式】**  
     > URL 填写：`https://<你的穿透域名>/sse`  
     > 鉴权方式选择 **Bearer Token**，填入你的 `AUTH_TOKEN`。
6. 点击 **Save & Connect（保存并连接）**。
   - 连接成功后，ChatGPT 将自动加载并显示 10 个工具（`setup_2fa`, `unlock_gate`, `execute_command` 等）。

---

### 方式二：在 Custom GPTs（自定义智能体 / Agent）中接入

如果你希望创建一个具备私有设备控制能力的“专属运维小助手”：

1. 打开 ChatGPT，进入 **Explore GPTs** -> 点击右上角 **+ Create**。
2. 切换到 **Configure（配置）** 标签页。
3. 滚动到底部找到 **Actions（操作）** -> 点击 **Create new action**。
4. 如果通过 MCP 桥接插件或 OpenAPI 规格，将目标服务指向：
   ```text
   https://<你的穿透域名>/mcp/<你的AUTH_TOKEN>/
   ```
5. 在 **Instructions（系统指令提示词）** 中加入以下关键上下文引导：
   ```markdown
   你连接了远程 2cfa-mcp 服务器。read_file/write_file/list_dir 受工作区路径保护；execute_command 是继承服务进程系统权限的完整 Shell，不是文件系统沙箱。
   如果执行命令或读写文件时提示 2FA 锁定：
   1. 主动提示用户提供 Google Authenticator 上的 6 位 TOTP 动态码；
   2. 收到验证码后调用 unlock_gate(code="...") 解锁并获取 lease_token；
   3. 在本会话的后续工具调用中隐式带上该 lease_token，无需再次打扰用户。
   ```

---

### 方式三：ChatGPT 桌面端（macOS / Windows）接入

在 ChatGPT 桌面客户端的开发者配置文件中添加如下条目即可：

```json
{
  "mcpServers": {
    "2cfa-mcp": {
      "url": "https://<你的穿透域名>/mcp/<你的AUTH_TOKEN>/sse"
    }
  }
}
```

---

## 第三部分：日常对话与 2FA 实战演练

连接完成后，无需死记硬背任何 API，在 ChatGPT 聊天框中使用纯自然语言即可完成所有交互：

### 1. 默认状态（开箱直接使用）
> **用户**：“帮我查看当前设备的系统负载和内存状态。”  
> **ChatGPT**：*（调用 `system_status`）* 当前系统为 Linux/arm64，逻辑 CPU 8 核，Go 进程已分配内存 12.8MB，服务运行正常。

> **用户**：“在 workspace 下创建一个 notes.md 文件，写入今天的备忘内容。”  
> **ChatGPT**：*（调用 `write_file`）* 文件已安全写入 `workspace/notes.md`。

---

### 2. 对话中动态开启 2FA 门禁（标准两步验证防锁死流程）
当服务暴露在公网，或打算借给他人使用时，随时在聊天中安全开启，无需预先生成密钥：
> **用户**：“帮我开启 2FA 门禁。”  
> **ChatGPT**：*（调用 `setup_2fa(enable=true)` 毫秒级自生成密钥）*  
> 🔑 **2FA 密钥已生成（待验证确认）！**  
> - **Base32 密钥**：`WM3H23RKVLQOOZ2GQO52VTEL7Y5H3DCB`  
> - **绑定链接**：`otpauth://totp/2cfa-mcp?secret=WM3H23...&issuer=2cfa-mcp`  
> 请将密钥添加到 Google Authenticator 或其他验证器，并将显示的 6 位验证码发给我以完成最终激活。  
>  
> **用户**：“验证码是 482910”  
> **ChatGPT**：*（调用 `setup_2fa(enable=true, code="482910")` 校验通过，自动持久化写回 `.env`）*  
> 🎉 **2FA 验证成功，门禁已正式激活并永久保存！** 当前会话已自动完成首次开闸，您可以直接执行后续任务。

---

### 3. 秒级解锁与隐式租约流转
开启 2FA 后，尝试执行受限操作时：
> **用户**：“执行 `df -h` 看看磁盘空间。”  
> **ChatGPT**：“安全门已锁死。检测到已启用 2FA，请告诉我您 Google Authenticator 上的 6 位动态验证码。”  
> **用户**：“619283”  
> **ChatGPT**：*（后台调用 `unlock_gate(code="619283")` 获得凭证，并自动附带凭证执行 `execute_command(command="df -h")`）*  
> 🔓 **验证成功！** 磁盘空间详情如下：Filesystem Size Used Avail Use% Mounted on...  
> *（后续所有请求均自动隐式携带通行证，无需频繁二次输入）*

---

### 4. 自定义限时开闸与应急锁门
- **限时开放**：“*帮我开门 15 分钟*”  
  -> ChatGPT 自动调用 `unlock_gate(code="...", duration_minutes=15)`，到期后门禁自动锁死。
- **物理断电关门**：“*把门锁上*”  
  -> ChatGPT 自动调用 `lock_gate()`，即刻撤销所有租约，断电物理上锁。
- **关闭/重置 2FA**：启用 2FA 后属于安全管理操作，必须携带当前有效 `lease_token`，或额外验证当前 TOTP；单独持有 `AUTH_TOKEN` 无法关闭或替换第二因素。

`duration_minutes` 必须是 `0` 到 `525600` 的整数；`0` 表示无时间过期。负数、小数或超出范围的值会报错，避免意外转换成永久租约。全局 `lock_gate()` 还会取消待确认的密钥配置；2FA 未启用时，锁门不会自动开启 2FA。

---

## 可视化安全控制台与健康审计

### 1. 零泄露健康检查（Zero-Leakage Health Check）
访问 `https://<你的域名>/health` 或 `/healthz`：
- 严格遵循零泄露设计，永远仅返回 `{"status":"ok"}`。
- 杜绝在公开健康检查接口中回显版本、环境变量或 Token。

### 2. 暗色大屏安全控制台（Web Dashboard）
在浏览器中访问：
```text
https://<你的穿透域名>/gate?token=<你的AUTH_TOKEN>
```
提供现代暗色高科技仪表盘，实时显示：
- 当前 2FA 门禁开关状态
- 活跃租约数量与门禁状态
- 最近请求审计流水与可信代理解析后的客户端 IP / 国家信息
- 网页端一键应急物理锁闸

---

<a name="english-documentation"></a>
# English Documentation

`2cfa-mcp` is an ultra-lightweight, high-security remote **Model Context Protocol (MCP)** server implemented in **Go 1.26.8+**. Designed specifically for **Android Termux (24/7 background alive)**, **low-spec Linux VPS (512MB RAM)**, and **Raspberry Pi**, it connects ChatGPT Web and remote AI agents to edge devices with minimal footprint (~12MB RAM) and zero-friction security.

## Core Architecture: 3 Simple Modes (Zero-Friction Mental Model)

| Mode | Configuration | Access & Experience | Best For |
| :--- | :--- | :--- | :--- |
| **1. Direct Token Mode (Default)** | No 2FA configured; only `AUTH_TOKEN` is set. | **Valid Token = 100% Full Access!** All shell commands and file tools run directly with zero popups or hurdles. | **Local users / Home LAN / Personal use** |
| **2. Conversational 2FA Mode** | Enable 2FA in chat and provide a 6-digit TOTP code once. | **Unlock once to receive an implicit bearer lease.** By default it has no time expiry and survives reconnects, but it is invalidated by explicit lock/revocation, 2FA rotation/disable, or server restart; it is not cryptographically bound to one chat thread. | **Exposed to public via Cloudflare Tunnel** |
| **3. Timed 2FA Mode** | Specify duration during unlock (e.g., *"Open gate for 30 minutes"*). | **Full access within time window; auto-locks when expired.** Re-verification required after time runs out. | **Lending to others / Public untrusted devices** |

## Quick Start in 3 Minutes

### 1. Setup & Compile
```bash
git clone https://github.com/Syntheticlight/2cfa-mcp.git
cd 2cfa-mcp

cp .env.example .env
# Edit .env and set your AUTH_TOKEN.
# Recommended: openssl rand -hex 32
# AUTH_TOKEN/TOTP_SECRET are read only from environment/.env, not CLI argv.

make build
chmod +x scripts/daemon.sh
./scripts/daemon.sh start
./scripts/daemon.sh cloudflared
```

### 2. Connect in ChatGPT Web
1. Go to [ChatGPT Web](https://chatgpt.com) -> **Settings** -> **Connect an app** / **Developer**.
2. Click **Add MCP Server**:
   - **Type**: `SSE`
   - **URL**: `https://<YOUR-TUNNEL-DOMAIN>/mcp/<YOUR_AUTH_TOKEN>/sse`
3. Click **Save & Connect**. All 10 remote tools will be available immediately!

All tools publish MCP `outputSchema` and return `structuredContent` plus a backward-compatible text fallback, so clients can consume stable JSON fields without scraping human-readable output.

File tools perform operations through `os.Root` to prevent symlink traversal and replacement races. Relative symlinks within the workspace are supported; absolute symlinks are rejected. Command timeouts return structured partial output with `timed_out=true` and an MCP tool error. Lease durations must be whole minutes from 0 to 525600 (0 means no time expiry). A global lock also cancels pending 2FA setup; it does not enable a disabled gate.

---

## License
[MIT License](LICENSE) © 2026 Syntheticlight
