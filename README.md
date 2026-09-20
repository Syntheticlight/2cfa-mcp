# 2cfa-mcp - Minimal, Fast & Secure Remote MCP Server in Go

[中文文档](#中文文档) | [English Documentation](#english-documentation)

---

<a name="中文文档"></a>
# 中文文档

`2cfa-mcp` 是一个专为 Linux VPS、Android Termux、树莓派等边缘设备打造的**高安全、极低资源占用、开箱即用**的远程 **Model Context Protocol (MCP)** 服务端。专用于将 ChatGPT Web 及远程 AI Agent 通过 Cloudflare Tunnel 或 FRP 安全桥接到边缘设备。

---

## 核心设计与 4 大极简原则

### 1. 默认仅凭 Token 直连（零门槛，开箱即用）
- 新手或日常自用，只需在 `.env` 设置一个 `AUTH_TOKEN`，手机或 VPS 启动后直接连接，**不需要任何复杂的初始配置，零拦截、零弹窗**。
- 常驻内存仅 **10MB ~ 15MB RAM**，纯单文件静态二进制（~8MB），彻底解决 Node.js 内存占用过大（100MB+）被手机系统杀后台的痛点。

### 2. 支持在对话里设置/启用 2FA（按需动态安全升级）
- 想临时离开电脑或处于公共网络？直接在 ChatGPT 聊天框对 AI 说：“*帮我开启 2FA，密钥是 JBSWY3DPEHPK3PXP*”。
- AI 自动调用 `setup_2fa(enable=true, secret="...")` 动态启用物理门禁，**无需重启服务端，零配置文件负担**！

### 3. 默认隐式码（lease_token）不过期（不打扰用户）
- 当启用了 2FA，用户只需在对话中报一次 6 位动态码，AI 调用 `unlock_gate(code="...")` 解锁。
- 服务端签发的动态租约令牌（`lease_token`）**默认在本场对话中永久有效（不会隔 60 分钟把你踢出去）**。
- AI 在后台 JSON 数据中隐式带码，**聊天界面干干净净无乱码**，无惧底层网络掉线抖动！

### 4. 支持在对话里随意控制有效期与随时锁门
- **指定限时开闸**：借给他人使用时，对 AI 说：“*帮我开门 30 分钟*”，AI 传入 `unlock_gate(code="...", duration_minutes=30)`，到期自动物理关闸。
- **随时一键关闸**：对 AI 说：“*把门锁上*”，AI 调用 `lock_gate()` 立即断电上锁。

---

## 核心 MCP 工具集（Tools）

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

## 1 分钟极速开箱步骤

### 1. 配置初始连接密钥
```bash
cp .env.example .env
vim .env
# 只需填入一个高熵 AUTH_TOKEN 即可！
```

### 2. 编译或下载单二进制
- **本地编译**:
  ```bash
  make build
  ```
- **Android Termux / 树莓派 (ARM64) 交叉编译**:
  ```bash
  make build-linux-arm64
  ```
- **Linux VPS (AMD64) 交叉编译**:
  ```bash
  make build-linux-amd64
  ```

### 3. 启动服务与 Cloudflare 隧道
```bash
chmod +x scripts/daemon.sh
./scripts/daemon.sh start

# 一键启动公网临时隧道
./scripts/daemon.sh cloudflared
```
获取控制台输出的临时域名 (例如 `https://xxxx.trycloudflare.com`)。

### 4. ChatGPT Web 端连接
在 ChatGPT Custom GPT / AI Agent 中配置 MCP 服务：
- **SSE URL 地址**: `https://<YOUR-TUNNEL-DOMAIN>/mcp/<YOUR_AUTH_TOKEN>/sse`
- **或标准 Header 鉴权**: `Authorization: Bearer <YOUR_AUTH_TOKEN>` 访问 `https://<YOUR-TUNNEL-DOMAIN>/sse`

---

## 常见使用对话示例

### 示例 1：默认直接使用
> **你**：帮我看一下当前服务器的 CPU 和内存占用。  
> **ChatGPT**：（调用 `system_status`）当前 CPU 占用 12%，内存使用 1.4GB / 4GB...

### 示例 2：对话中开启 2FA 物理防线
> **你**：帮我开启 2FA 门禁，我的密钥是 JBSWY3DPEHPK3PXP。  
> **ChatGPT**：（调用 `setup_2fa(enable=true, secret="...")`）已为您成功开启 2FA 物理门禁！后续敏感指令将需要验证码解锁。

### 示例 3：对话中秒级解锁
> **你**：帮我在 workspace 下建一个 test.txt 文件。  
> **ChatGPT**：检测到 2FA 门禁处于锁定状态，请告诉我您 Google Authenticator 上的 6 位动态验证码。  
> **你**：582910  
> **ChatGPT**：（调用 `unlock_gate(code="582910")` 拿到隐式码，并在后台自动执行 `write_file`）已成功为您创建 test.txt 文件！

---

<a name="english-documentation"></a>
# English Documentation

`2cfa-mcp` is an ultra-lightweight, zero-friction remote **Model Context Protocol (MCP)** server in **Go 1.22+**. Designed for Linux VPS, Android Termux, and Raspberry Pi, it bridges ChatGPT Web and remote AI agents with maximum simplicity and modular security.

## The 4 Minimal Principles
1. **Direct Token Connect by Default**: Connect right away with `AUTH_TOKEN`. Zero initial setup barriers.
2. **Conversational 2FA Setup**: Enable or disable Google Authenticator protection directly inside chat via `setup_2fa`.
3. **No Annoying Expiration**: Verified `lease_token` stays valid for your chat session by default (`duration_minutes=0`).
4. **Conversational Duration & Emergency Lock**: Specify `duration_minutes` anytime or call `lock_gate()` to lock immediately.

## Quick Start
```bash
cp .env.example .env
make build-linux-arm64
./scripts/daemon.sh start
./scripts/daemon.sh cloudflared
```

---

## License
MIT License
