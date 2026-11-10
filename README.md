# SRC Guarded Workflow

一个可迁移的 Codex 插件：把“给定 SRC 资产 → 自动建立范围 → 被动侦察 → 基线采集 → 候选分析 → 人工批准后的低影响验证 → 证据门禁 → 报告草稿”打包成聊天驱动的 MCP 工作流。

## 你现在怎么用

在聊天里给出：

```text
SRC 项目：<项目名或规则链接>
授权资产：https://target.example.com/path
确认：该资产在授权范围内
```

Codex 会优先调用 `srcGuardedWorkflow` MCP 工具的 `src_start`：

1. 创建本次运行目录。
2. 只允许该资产的主机、端口、路径和只读方法。
3. 做 DNS/证书透明度的被动侦察。
4. 发送一次低影响 `GET` 基线请求。
5. 生成 `attack-surface.md`、证据和运行状态。
6. 后续高风险操作通过聊天里的 `APPROVE <code>` 人工门禁。

不需要记忆命令行。命令行工具仍然保留，供调试和跨平台迁移使用。

## 插件结构

```text
src-workflow/
├── plugin.json                 # 可迁移 Agent Plugin 清单
├── mcp.json                    # 本地 stdio MCP 服务
├── skills/src-bug-bounty/      # 聊天入口 Skill
├── server/src_guarded_mcp.py   # MCP 工具服务
├── scripts/                    # 范围、HTTP、证据、报告脚本
├── schemas/                    # Scope / Finding schema
├── knowledge/expert-routes.json # 场景到专家 Playbook 的路由
├── config/scope.example.yaml
├── templates/clueboard.md      # 跨轮线索板
├── templates/report.md
├── THIRD_PARTY_NOTICES.md      # 第三方来源与许可证
├── tests/
└── install.ps1 / install.sh
```

## 安装到个人环境

Windows：

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

安装器会：

- 安装个人 Skill 到 `~/.agents/skills/src-bug-bounty`。
- 安装插件到 `~/.agents/plugins/src-guarded-workflow`。
- 写入个人 marketplace 条目。
- 安装 `PyYAML` 和 `jsonschema`。

重启 Codex 桌面应用后，在本地 Plugins 源启用 `src-guarded-workflow`。

## MCP 工具

- `src_start`：一次调用完成授权范围创建、被动侦察、基线请求和 `CLUEBOARD.md` / `CLUEBOARD.json` 初始化。
- `src_clueboard`：读取或更新跨轮线索板，并维护 Facts / Intents / Hints 状态图（`CLUEBOARD.json`）。
- `src_hunt_route`：把 JS、认证、越权、注入、业务逻辑、文件、SSRF、Agent/MCP 等场景路由到专家流程和漏洞 Playbook。
- `src_skill_audit`：安装第三方 Skill/插件前做静态供应链安全检查，覆盖危险执行、审批绕过、提示词注入、密钥、外传和混淆信号。
- `src_prepare_run`：只创建范围与运行目录，不发目标流量。
- `src_passive_recon`：DNS、证书透明度等被动信息收集。
- `src_asset_intel`：查询 FOFA、Shodan、Quake、Hunter、ZoomEye、urlscan 等空间搜索引擎，结果标记 in_scope/out-of-scope。
- `src_intel_status`：查看空间搜索引擎 API Key 配置状态。
- `src_check_scope`：检查 URL 和方法是否在范围内。
- `src_js_inventory`：抓取基线页面和同源 JS，提取接口、参数和 source map；需要批量批准。
- `src_import_har`：导入浏览器/Burp HAR，建立范围内的请求和参数清单。
- `src_path_probe`：最多 25 条明确路径的低速探测；不接受 wordlist 暴力扫描，需要批量批准。
- `src_port_probe`：只检查 scope 明确允许的端口，最多 20 个；需要批量批准。
- `src_http`：受控 HTTP 请求，默认 dry-run；写操作和高风险操作必须带聊天批准码。
- `src_request_approval`：生成聊天审批码。
- `src_confirm_approval`：只有用户回复 `APPROVE <code>` 后才确认。
- `src_save_finding`：保存候选/已确认发现。
- `src_validate_finding`：证据、哈希、人工复核门禁。
- `src_render_report`：只从已验证发现生成报告草稿。
- `src_status`：查看运行状态、请求数、发现和审批。
- `src_vuln_playbook`：按 IDOR、SSRF、XSS、SQLi、业务逻辑等类别返回检测方法、确认条件和误报项。
- `src_tool_status`：检测本机侦察工具。
- `src_install_tool`：安装白名单内的官方工具，必须显式 `confirm: true`。

## 信息搜集链路

1. `src_start`：被动 DNS/CT + 一次基线 GET + 初始化 `CLUEBOARD.md` / `CLUEBOARD.json`。
2. `src_clueboard`：读取线索板、Fact-Intent-Hint 图和当前焦点。
3. `src_asset_intel`：用精确域名/证书/资产查询 FOFA、Shodan、Quake、Hunter、ZoomEye、urlscan。
4. `src_js_inventory`：同源 JS、接口、参数和 source map。
5. 浏览器或 Burp/Caido 登录测试账号，走真实功能，导出 HAR。
6. `src_import_har`：把 HAR 转成范围内的端点/参数清单。
7. `src_path_probe`：只探测从 JS/HTML/HAR 得到的明确路径。
8. `src_port_probe`：只检查 scope 允许的端口。
9. `src_hunt_route`：按功能点/技术栈/异常信号选择专家路线。
10. `src_vuln_playbook`：按漏洞类型进入检测。
11. `src_http`：单请求最小验证。
12. `src_clueboard`：写回事实、意图、人工提示、否定证据和覆盖度。
13. `src_save_finding` / `src_validate_finding` / `src_render_report`：证据和报告。

“可疑站点搜索”仅指授权项目内的公开资产发现，不扫描范围外主机。

## 漏洞分类与检测

执行任何候选验证前，先调用 `src_vuln_playbook`。例如：

```text
src_vuln_playbook(class_id="idor_bola")
src_vuln_playbook(query="JWT")
src_vuln_playbook(priority="high")
```

返回内容包括：

- 攻击面
- 可观察信号
- 最小安全验证
- 确认条件
- 常见误报
- 是否必须人工批准
- 潜在影响

目前内置 27 类 Playbook 和 20 条专家路由：认证绕过、会话/JWT、IDOR/BOLA、租户隔离、SQL/NoSQL 注入、SSTI、命令注入、反序列化、SSRF、开放重定向、XSS、CSRF、CORS、文件上传、路径穿越、业务逻辑、竞态、GraphQL、OAuth/JWT、信息泄露、云存储、缓存/Host Header、WebSocket、LLM 提示注入、Agentic/MCP 工作流安全、HTTP 请求走私等。

## CK-Skills 方法整合

本版本吸收 CK-Skills 的 JS-first、专家路由、跨轮线索板、证伪优先和覆盖度自检，但不导入其“任意目标直接执行”、凭据猜测、自动 WAF 绕过或完全自主利用等假设。移动端逆向、Windows 逆向和源码审计只返回 `manual_only` 手交路线。来源与 MIT 许可证见 `THIRD_PARTY_NOTICES.md`。

## SecSkills 方法整合

SecSkills 是一个 102 项目的能力索引，不是单一技能。本版本只吸收其中当前工程缺少的精华：第三方 Skill 供应链审计、Facts/Intents/Hints 状态空间图、Agentic/MCP 工作流安全、独立 Oracle 验证，以及“脚本保证覆盖、LLM 保证判断”的双层架构。未安装其列出的自主渗透平台，也未引入移动逆向、二进制利用、CTF 或域渗透自动化。详见 `skills/src-bug-bounty/references/secskills-integration.md`。

## 自动安装工具

Skill 先调用 `src_tool_status`。若缺少工具，只对白名单工具调用 `src_install_tool`，例如：

- `httpx`
- `subfinder`
- `dnsx`
- `katana`
- `nuclei`
- `gau`
- `ffuf`

安装来源仅限 ProjectDiscovery、lc/gau、ffuf 等官方 Go 模块。不会自动安装来源不明的 GitHub 项目，不会自动运行 `nuclei`、`sqlmap`、`ffuf` 或暴力破解。

## 安全边界

- 只有明确授权的 SRC 资产可以测试。
- 默认只读，写操作、认证流程、SSRF、文件上传、跨租户、凭据使用和漏洞链必须人工批准。
- 真实用户数据、凭据、内网资产和业务影响必须立即停止扩大。
- 扫描器结果只能是线索，不能直接当漏洞。
- 报告必须人工复核，不能自动提交到 SRC。

## 本地测试

```powershell
python -m unittest discover -s tests -v
```

测试覆盖：MCP 初始化/工具列表、范围创建、线索板及 Facts/Intents/Hints 图、专家路由、Skill 供应链审计、dry-run、聊天审批门禁、候选发现校验、证据记录、重定向阻断和报告渲染。



