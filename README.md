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
- [核心设计：4 大极简原则（KISS 哲学）](#核心设计4-大极简原则kiss-哲学)
- [核心 MCP 工具集](#核心-mcp-工具集)
- [第一部分：服务端极速部署与公网穿透](#第一部分服务端极速部署与公网穿透)
- [第二部分：在 ChatGPT 网页版中添加 MCP 服务（核心教程）](#第二部分在-chatgpt-网页版中添加-mcp-服务核心教程)
- [第三部分：日常对话与 2FA 实战演练](#第三部分日常对话与-2fa-实战演练)
- [可视化安全控制台与健康审计](#可视化安全控制台与健康审计)
- [English Documentation](#english-documentation)
- [License](#license)

---

## 为什么选择 2cfa-mcp？

1. **告别 Node.js 内存笨重**：传统基于 Node.js 的 MCP 服务动辄消耗 100MB~150MB V8 内存，手机后台频繁被杀。本项目采用 Go 1.22+ 编写，运行时常驻内存仅 **10MB ~ 15MB RAM**，单文件静态二进制仅 **~8MB**。
2. **彻底解决未鉴权泄密隐患**：重构了社区项目中未鉴权 `/health` 导致 Token 泄露的致命隐患，实现全链路零泄露设计（Zero-Leakage）与基于 `filepath.Clean` 的强制路径防穿越保护。
3. **首创对话内隐式租约机制**：在对话中直接报一次 6 位 TOTP 动态码完成解锁，签发隐式凭证（`lease_token`）。AI 在后台数据流中静默携带，聊天界面干干净净，无惧底层网络重连与掉线！

---

## 核心设计：4 大极简原则（KISS 哲学）

1. **默认仅凭 Token 直连（零门槛，开箱即用）**：
   - 新手或日常自用，只需在 `.env` 设置一个 `AUTH_TOKEN`，手机或 VPS 启动后直接连接，**不需要任何复杂的初始配置，零拦截、零弹窗**。
2. **支持在对话里设置/启用 2FA（按需动态安全升级）**：
   - 处于公共网络或需要临时借出？直接在 ChatGPT 聊天框对 AI 说：“*帮我开启 2FA，密钥是 JBSWY3DPEHPK3PXP*”。
   - AI 自动调用 `setup_2fa(enable=true, secret="...")` 动态启用物理门禁，**无需重启服务端，零配置文件负担**！
3. **默认隐式码（lease_token）不过期（不打扰用户）**：
   - 启用 2FA 后，在对话中报一次 6 位动态码，AI 调用 `unlock_gate(code="...")` 解锁。
   - 服务端签发的动态租约令牌（`lease_token`）**默认在本场对话中永久有效（不会隔 60 分钟强制踢你下线）**。
   - AI 在后台隐式带码，**聊天界面无乱码**，底层 SSE 网络抖动重连无感保持。
4. **支持在对话里随意控制有效期与随时锁门**：
   - **指定限时开闸**：在公网或临时授权时对 AI 说：“*帮我开门 30 分钟*”，AI 传入 `duration_minutes=30`，到期自动物理关闸。
   - **随时一键关闸**：对 AI 说：“*把门锁上*”，AI 调用 `lock_gate()` 立即断电上锁。

---

## 核心 MCP 工具集

| 工具名称 | 功能描述 | 隐式参数 |
| :--- | :--- | :--- |
| `setup_2fa` | 在对话中开启/关闭 2FA 或配置 Google Authenticator 密钥 | 无需凭证 |
| `unlock_gate` | 校验 6 位 TOTP 动态码，签发隐式 `lease_token`（支持自定义有效期） | 无需凭证 |
| `lock_gate` | 一键物理锁死安全门，注销当前租约 | 支持指定凭证或全局锁 |
| `execute_command` | 在工作区子目录下执行受限 Shell 命令（带 120s 超时与 1MB 截断） | `lease_token` (若开启 2FA) |
| `read_file` | 安全读取工作区内指定文件（强制防路径穿越） | `lease_token` (若开启 2FA) |
| `write_file` | 安全写入/覆盖工作区文件（自动递归创建父级目录） | `lease_token` (若开启 2FA) |
| `list_dir` | 结构化列出指定工作区目录的文件列表 | `lease_token` (若开启 2FA) |
| `system_status` | 查看系统硬件负载（CPU/内存）与当前 2FA 门禁状态 | `lease_token` (若开启 2FA) |

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
PORT=8080
AUTH_TOKEN=your-high-entropy-secret-token-here
WORKSPACE_PATH=./workspace
EXEC_TIMEOUT=120
ENABLE_2FA_GATE=false
TOTP_SECRET=
```
*(注：`ENABLE_2FA_GATE` 建议保持 `false`，后续在与 ChatGPT 对话中可随时动态开启)*

### 2. 编译服务端
- **本机编译**：
  ```bash
  make build
  ```
- **交叉编译（Android Termux / 树莓派 ARM64）**：
  ```bash
  make build-linux-arm64
  ```
- **交叉编译（Linux VPS AMD64）**：
  ```bash
  make build-linux-amd64
  ```

### 3. 启动守护进程与 Cloudflare 隧道
项目自带高可用 Supervisor 脚本，支持进程自愈重启与 Termux 唤醒锁防休眠：
```bash
chmod +x scripts/daemon.sh

# 启动后台常驻服务
./scripts/daemon.sh start

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
     > *示例：`https://xxx.trycloudflare.com/mcp/your-high-entropy-secret-token-here/sse`*
     >
     > **【标准 Header 模式】**  
     > URL 填写：`https://<你的穿透域名>/sse`  
     > 鉴权方式选择 **Bearer Token**，填入你的 `AUTH_TOKEN`。
6. 点击 **Save & Connect（保存并连接）**。
   - 连接成功后，ChatGPT 将自动加载并显示 8 个安全工具（`setup_2fa`, `unlock_gate`, `execute_command` 等）。

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
   你连接了远程 2cfa-mcp 服务器。你的工作区位于受限安全目录内。
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
> **ChatGPT**：*（调用 `system_status`）* 当前 CPU 使用率 3%，常驻内存使用 12.8MB，系统运行正常。

> **用户**：“在 workspace 下创建一个 notes.md 文件，写入今天的备忘内容。”  
> **ChatGPT**：*（调用 `write_file`）* 文件已安全写入 `workspace/notes.md`。

---

### 2. 对话中动态开启 2FA 门禁
当服务暴露在公网，或打算借给同事朋友使用时，随时在聊天中升级防护：
> **用户**：“帮我开启 2FA 门禁，密钥是 `JBSWY3DPEHPK3PXP`。”  
> **ChatGPT**：*（调用 `setup_2fa(enable=true, secret="JBSWY3DPEHPK3PXP")`）*  
> 🔒 **2FA 物理门禁已成功激活！** 后续所有命令执行和文件读写操作均需动态验证码解锁。

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
- 活跃租约通行证清单与倒计时
- 最近请求审计流水与 Cloudflare 真实穿透 IP（含 `CF-IPCountry` 地理归属与客户端 User-Agent）
- 网页端一键应急物理锁闸

---

<a name="english-documentation"></a>
# English Documentation

`2cfa-mcp` is an ultra-lightweight, high-security remote **Model Context Protocol (MCP)** server implemented in **Go 1.22+**. Designed specifically for **Android Termux (24/7 background alive)**, **low-spec Linux VPS (512MB RAM)**, and **Raspberry Pi**, it connects ChatGPT Web and remote AI agents to edge devices with minimal footprint (~12MB RAM) and zero-friction security.

## The 4 Minimal Principles
1. **Direct Token Connect by Default**: Connect right out of the box with `AUTH_TOKEN`. Zero initial popups or barriers.
2. **Conversational 2FA Configuration**: Enable or disable Google Authenticator protection directly inside chat via `setup_2fa`.
3. **Implicit Lease Tokens**: Unlock with a 6-digit TOTP code once; the dynamic lease token stays active for your chat session without disrupting the UI.
4. **Custom Lease Duration & Emergency Lock**: Specify `duration_minutes` anytime or instruct AI to `lock_gate()` immediately.

## Quick Start in 3 Minutes

### 1. Setup & Compile
```bash
git clone https://github.com/Syntheticlight/2cfa-mcp.git
cd 2cfa-mcp

cp .env.example .env
# Edit .env and set your AUTH_TOKEN

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
3. Click **Save & Connect**. All 8 remote tools will be available immediately!

---

## License
[MIT License](LICENSE) © 2026 Syntheticlight