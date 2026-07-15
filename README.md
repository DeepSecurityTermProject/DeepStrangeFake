# DeepStrangeFake

DeepStrangeFake 是一个面向源码仓库的 Agent 主导安全审计原型。系统支持本地目录以及公开的 GitHub/GitLab 仓库，通过项目管理、代码分析、协作调查、证据验证和报告生成，形成可回放的审计过程与项目安全态势。

> 本项目用于课程、研究和已获授权的安全测试。请勿扫描未获得授权的系统或私有仓库。Web 服务仅面向本机使用，不应直接暴露到公网。

## 主要能力

- 管理多个本地或远程代码项目及其历次扫描任务；
- 自动分析仓库结构、语言、依赖和静态安全信号；
- 以 Agent 主导模式生成假设、调用工具、收集证据并复核结论；
- 通过 SSE 实时展示任务日志、Agent 调查摘要、工具调用和验证状态；
- 保存运行状态、证据链、JSON/Markdown 报告和跨次扫描趋势；
- 在可信证据基础上展示项目风险评分、安全态势和高风险漏洞。

## 环境要求

- Windows 10/11（下面的命令使用 PowerShell）；
- Python 3.12 或更高版本；
- Node.js 20.19+ 或 22.12+，以及 npm；
- Git（使用远程仓库扫描时需要）；
- Docker Desktop（仅使用 Docker sandbox 或受约束 PoC 修复时需要）。

## 快速启动

### 1. 安装后端依赖

在普通用户的 PowerShell 中进入仓库根目录：

```powershell
cd D:\DeepStrangeFake
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[js-ast]"
```

如果不需要可选的 Tree-sitter 语言分析能力，可以使用最小安装：

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
```

### 2. 配置模型服务

纯静态扫描或 `mock` 模型不需要 API Key。使用 OpenAI-compatible 模型服务时，在仓库根目录创建或编辑 `.env`：

```dotenv
LLM_API_KEY=替换为实际密钥
LLM_API_BASE_URL=https://your-provider.example/v1
LLM_MODEL=替换为供应商实际支持的模型名称

# 可选配置
AUDIT_AGENT_LLM_PROVIDER=openai-compatible
AUDIT_AGENT_LLM_RESPONSE_FORMAT=auto
AUDIT_AGENT_LLM_TOKEN_BUDGET=16000
```

`.env` 不应提交到 Git。模型密钥只由后端读取，不要在前端页面、仓库 URL 或扫描参数中填写密钥。

### 3. 配置本地仓库访问范围

默认允许扫描后端进程可见的全部本地盘符和已映射盘符。该设置适用于当前单用户课程实验环境；服务必须继续绑定 `127.0.0.1`，不要暴露到局域网或公网。

如果需要恢复最小权限边界，可以在启动后端前设置白名单。Windows 使用分号分隔多个根目录：

```powershell
$env:AUDIT_LOCAL_ALLOWED_ROOTS = "D:\DeepStrangeFake;D:\course-repositories;D:\fixtures"
```

该配置由后端启动进程直接读取，因此推荐在 PowerShell 中设置，而不是只写入 `.env`。路径授权不会取消独立的 25,000 文件和 128 MiB 本地预检预算。

### 4. 启动后端

在仓库根目录执行：

```powershell
cd D:\DeepStrangeFake
.\.venv\Scripts\python.exe -m uvicorn audit_agent.server.app:app --host 127.0.0.1 --port 8000
```

后端启动后可在另一个 PowerShell 中检查健康状态：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

正常响应包含：

```json
{"service":"agentic-security-audit-api","status":"ok","api_version":"v1"}
```

### 5. 启动前端

打开第二个 PowerShell：

```powershell
cd D:\DeepStrangeFake\frontend
npm install
npm run dev
```

浏览器访问：

```text
http://127.0.0.1:5173/
```

Vite 默认将 `/api` 请求代理到 `http://127.0.0.1:8000`。前后端终端都需要保持运行；停止服务时分别在两个终端按 `Ctrl+C`。

## 远程 GitHub/GitLab 仓库

远程仓库获取默认关闭。仅在获得授权且确认需要网络访问时，在 `.env` 中启用：

```dotenv
AUDIT_REMOTE_ACQUISITION_ENABLED=true
AUDIT_REMOTE_ACQUISITION_NETWORK=true
AUDIT_REMOTE_ALLOWED_HOSTS=github.com,gitlab.com
AUDIT_REMOTE_CACHE_ROOT=.audit-cache/repositories
AUDIT_REMOTE_WORK_ROOT=.audit-work/repositories
```

支持不含凭据的公开 HTTPS URL，例如：

```text
https://github.com/owner/repository
https://gitlab.com/group/subgroup/repository
```

不要在 URL 中嵌入用户名、Token 或密码。将 `AUDIT_REMOTE_ACQUISITION_NETWORK` 设为 `false` 时，系统只使用已经存在并通过校验的本地镜像缓存。

## 使用其他端口

例如后端使用 `18000`、前端使用 `18173`：

```powershell
# 终端一：后端
cd D:\DeepStrangeFake
.\.venv\Scripts\python.exe -m uvicorn audit_agent.server.app:app --host 127.0.0.1 --port 18000
```

```powershell
# 终端二：前端
cd D:\DeepStrangeFake\frontend
$env:VITE_API_PROXY_TARGET = "http://127.0.0.1:18000"
npm run dev -- --port 18173
```

随后访问 `http://127.0.0.1:18173/`。

## 命令行扫描

不启动 Web UI 也可以直接扫描本地目录：

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan `
  --target D:\path\to\project `
  --output runs `
  --graph-mode agent-led `
  --validation-level static-only
```

使用 mock 模型验证 Agent 工作流：

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan `
  --target fixtures\integration_smoke `
  --output runs `
  --graph-mode agent-led `
  --runtime `
  --llm-provider mock `
  --llm-decisions `
  --memory-mode lexical `
  --mcp-mode off
```

使用真实兼容模型时，将 `--llm-provider` 改为 `openai-compatible`，并通过 `--model` 指定供应商真实支持的模型，或省略 `--model` 以使用 `.env` 中的 `LLM_MODEL`。

## 数据目录

默认运行数据保存在：

```text
runs/                                  每次审计的证据、状态和报告
.audit-cache/web/workspace.sqlite3     项目、任务、事件索引和安全态势
.audit-cache/web/events/               可回放的公开审计事件
.audit-cache/repositories/             远程仓库镜像缓存
.audit-work/repositories/              远程仓库临时工作区
```

不要在后端运行期间手动删除这些目录。需要迁移、恢复或清理数据时，请先停止后端，并参考 [项目控制台运维文档](docs/project-console.md)。

## 常见问题

### 创建任务时报 `[WinError 5] 拒绝访问`

Web 扫描需要在仓库根目录的 `runs` 下创建运行目录。请从自己的普通 PowerShell 启动后端，并确认当前账号能在 `runs` 中创建子目录。通过 Codex 或其他受限沙箱启动的长期后端可能继承会话级限制权限，从而无法写入由旧会话创建的目录。

可以先在普通 PowerShell 中执行一次可逆的权限探测：

```powershell
cd D:\DeepStrangeFake
$probe = Join-Path (Resolve-Path .\runs) ".write-probe"
New-Item -ItemType Directory -Path $probe -ErrorAction Stop
Remove-Item -LiteralPath $probe
```

如果第一条写入命令失败，请在 Windows 文件属性的“安全 -> 高级”中检查 `runs` 是否继承仓库根目录权限，或由有权限的用户修复该目录后再启动服务。不要通过放宽整个磁盘权限解决问题。

### 本地目录预检返回 422

默认策略已覆盖所有本地和映射盘符。出现该错误通常表示路径不存在，或者启动前通过 `AUDIT_LOCAL_ALLOWED_ROOTS` 主动收窄了范围；修改白名单后必须重启后端。`local-source-byte-budget-exceeded` 和 `local-source-file-budget-exceeded` 属于独立的仓库规模限制，不是路径授权错误。

### 真实模型提示缺少 API Key

确认 `.env` 位于启动后端时的工作目录，并至少配置 `LLM_API_KEY`、`LLM_API_BASE_URL` 和 `LLM_MODEL`。修改 `.env` 后重启后端。

### 模型接口返回 HTTP 400/404

检查 Base URL 是否包含供应商要求的 API 前缀，以及页面或 `.env` 中的模型名称是否由该供应商实际提供。前端允许输入模型名称，但不会替供应商验证模型是否存在。

### 端口被占用

检查端口：

```powershell
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 8000,5173
```

停止占用进程，或按照“使用其他端口”一节同时修改后端端口和前端代理地址。

## 验证与测试

后端测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

前端测试、类型检查和生产构建：

```powershell
cd frontend
npm test
npm run typecheck
npm run build
```

## 更多文档

- [完整使用说明](docs/usage.md)
- [项目控制台、存储、SSE 与恢复说明](docs/project-console.md)
- [Agent 主导运行时设计](openspec/changes/add-agent-led-investigation-runtime/design.md)
