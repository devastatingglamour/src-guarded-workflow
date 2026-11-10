# SRC Guarded Workflow 迁移说明

这个迁移包包含插件、Skill、MCP 服务和安装脚本。换机器后不需要手工改代码路径。

## Windows

1. 把 `src-guarded-workflow-migration.zip` 复制到目标机器。
2. 解压。
3. 在解压目录打开 PowerShell。
4. 运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

5. 重启 Codex 桌面应用。
6. 在 Plugins 里确认 `src-guarded-workflow` 已启用，或运行：

```powershell
codex plugin list
```

## Linux / macOS

```bash
unzip src-guarded-workflow-migration.zip
cd src-guarded-workflow-migration
bash install.sh
```

重启 Codex 桌面应用。

## 前置条件

- Codex 已安装，`codex` 命令在 PATH 中。
- Python 3.10+。
- 安装依赖时需要网络；插件工具按需安装时需要网络。
- Burp/Caido 等客户端工具不是强依赖；需要时手动安装。

## 信息搜集链路

1. `src_start`：DNS/CT 被动侦察、基线请求和 `CLUEBOARD.md`/`CLUEBOARD.json` 初始化。
2. `src_asset_intel`：查询 FOFA、Shodan、Quake、Hunter、ZoomEye、urlscan。
3. `src_js_inventory`：同源 JS、接口、参数和 source map。
4. 浏览器或 Burp/Caido 登录测试账号，访问真实功能，导出 HAR。
5. `src_import_har`：导入 HAR，建立端点/参数清单。
6. `src_path_probe`：最多 25 条明确路径，需要批量批准。
7. `src_port_probe`：只检查 scope 允许的端口，最多 20 个，需要批量批准。
8. `src_hunt_route`：按功能点/信号选择专家路线。
9. `src_vuln_playbook`：按漏洞类型获取检测方法。
10. `src_http`：单请求最小验证。
11. `src_clueboard`：写回 Facts / Intents / Hints、否定证据和覆盖度。
12. `src_save_finding` / `src_validate_finding` / `src_render_report`：证据和报告。

“可疑站点搜索”只限授权项目内的公开资产发现，不扫描范围外主机。

## 漏洞分类

插件内置 27 类漏洞检测手册和 20 条专家路由，并提供 `src_skill_audit` 第三方 Skill 供应链静态审计。Codex 会先调用 `src_hunt_route`，再调用 `src_vuln_playbook` 获取：

- 攻击面
- 可观察信号
- 最小安全验证
- 确认条件
- 常见误报
- 审批级别

覆盖 IDOR/BOLA、租户隔离、认证/会话、SQL/NoSQL、SSTI、命令注入、反序列化、SSRF、XSS、CSRF、CORS、文件上传、路径穿越、业务逻辑、竞态、GraphQL、OAuth/JWT、云存储、缓存/Host Header、WebSocket、LLM 提示注入和 HTTP 请求走私等类别。

## 迁移后的使用方式

在聊天里提供：

```text
SRC 项目：<项目名或规则链接>
授权资产：https://target.example.com/path
确认：该资产已授权，且在 SRC 范围内
```

Codex 会调用 `src_start` 自动建立范围、做被动侦察和基线采集，并初始化 `CLUEBOARD.md` 与 `CLUEBOARD.json`。

## 工具安装

Skill 先调用 `src_tool_status`。缺少工具时，只有用户确认后才调用 `src_install_tool` 安装白名单工具：

- `httpx`
- `subfinder`
- `dnsx`
- `katana`
- `nuclei`
- `gau`
- `ffuf`

不会自动安装来源不明的 GitHub 项目，也不会自动运行扫描器或暴力破解。



