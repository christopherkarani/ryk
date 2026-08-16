<p align="center">
  <a href="https://rykanv.com/">网站</a> ·
  <a href="https://discord.gg/uZn9MDUYKx">Discord</a> ·
  <a href="CONTRIBUTING.md">参与贡献</a> ·
  <a href="SECURITY.md">安全</a>
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.ur-pk.md">اردو</a>
</p>

<p align="center">
  <a href="https://github.com/christopherkarani/ryk/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/christopherkarani/ryk/build.yml?label=build" alt="构建状态"></a>
  <a href="https://github.com/christopherkarani/ryk/blob/main/LICENSE"><img src="https://img.shields.io/github/license/christopherkarani/ryk" alt="Apache 2.0 许可证"></a>
  <a href="https://github.com/christopherkarani/ryk"><img src="https://img.shields.io/github/stars/christopherkarani/ryk?style=flat" alt="GitHub 星标"></a>
</p>

# ryk

**本地编码代理护栏。**

通过一个本地二进制运行 Claude Code、Codex、Pi、OpenCode、Hermes、OpenClaw 或 Grok。ryk 在命令、文件、密钥、网络和 MCP 操作触及你的机器之前进行检查 — allow / ask / deny / observe — 并将证据保存在磁盘上。

<p align="center">
  <img src="docs/assets/ryk-deny-demo.gif" alt="ryk 拒绝 OpenCode 的 rm -rf / 命令" width="720">
</p>

<p align="center"><em>代理尝试 <code>rm -rf</code>。ryk 拒绝执行。会话留在你的笔记本上。</em></p>

## 安装

```sh
curl -fsSL https://rykanv.com/install | sh
```

## 启动代理

```sh
ryk claude    # or: codex | pi | opencode | openclaw | hermes | grok
```

扫描过往代理会话中的风险命令和类似密钥的暴露：

```sh
ryk scan
```

如果 ryk 帮你避免了一次糟糕经历，请[给仓库加星](https://github.com/christopherkarani/ryk) — 这能帮助其他工程师找到它。

## 你能获得什么

| | |
| --- | --- |
| 主机集成 | 为 Pi、Hermes、OpenCode、Codex、Claude Code、OpenClaw 和 Grok 提供启动别名。Cursor 通过主机发现和其 shell hook 获得支持。 |
| 操作系统沙箱 | 在可用时，macOS 上使用 Seatbelt、Linux 上使用 Landlock 自动进行操作系统文件系统沙箱。Windows 没有操作系统沙箱（仅 wrapper/hook 级别）。 |
| 密钥脱敏 | 在写入审计和 replay 数据之前，类似密钥的值会被脱敏。 |
| MCP 保护 | MCP 工具调用在本地分类，受支持的 stdio 服务器通过 ryk 的受保护代理运行。 |
| 86 个安全 pack | 内置破坏性操作和敏感操作的命令模式，并提供项目级可选 pack。 |
| 策略决策 | 对本地动作做出 `allow`、`ask`、`deny` 和 `observe` 决策。 |
| 本地证据 | 本地主机仪表盘（包括被阻止命令的终端视图）以及用于会话、决策和审计记录的 replay 命令。 |
| 单一本地二进制 | Zig CLI 负责启动、评估、策略检查、主机适配器和诊断。 |



### 支持的主机

| 主机 | 入口 | 集成点 |
| --- | --- | --- |
| Pi | `ryk pi` | Bundled extension |
| Hermes | `ryk hermes` | `pre_tool_call` |
| OpenCode | `ryk opencode` | `tool.execute.before` |
| Codex | `ryk codex` | `PreToolUse` |
| Claude Code | `ryk claude` | `PreToolUse` |
| OpenClaw | `ryk openclaw` | `tool.before` |
| Grok | `ryk grok` | `PreToolUse` |
| Cursor | 主机发现和 `cursor-agent` 预设 | `beforeShellExecution` |



## 策略如何工作

ryk 在本地评估每个受保护的动作。主要策略面包括：

| 策略面 | 示例 |
| --- | --- |
| 命令 | Shell 命令、管道、重定向和解释器 |
| 文件 | 工作区文件、项目控制文件和敏感路径 |
| 环境 | 继承的变量和密钥访问 |
| 网络 | 主机允许列表和受控出站连接 |
| 工具 | 映射到效果的 MCP 和主机工具调用 |

策略模式控制响应方式：

| 模式 | 行为 |
| --- | --- |
| `observe` | 记录决策，但不阻止受支持的动作 |
| `ask` | 当主机可以恢复时，对风险动作进行提示 |
| `strict` | 除非有规则允许，否则拒绝未知或风险动作 |
| `ci` | 运行严格行为且不提示；`ask` 变为 deny |

显式拒绝规则优先级最高。安全 pack 用于分类命令和效果，但不会越过拒绝规则授予权限。

验证内置预设：

```sh
ryk policy check --preset ask
```

请参阅[策略参考](docs/policy.md)了解策略文件、优先级和示例。

## 安全 pack

安全 pack 为 shell 评估器扩展聚焦的命令覆盖范围。`core.*` 和 `system.disk` 等基线 pack 默认启用。

```sh
ryk packs
ryk packs show core.git
ryk packs enable containers.docker database.postgresql
ryk packs disable containers.docker
```

在 Git 工作区中，项目 pack 选择保存在 `.ryk.toml` 中。脚本和诊断使用 `ryk packs`。

在不实际运行的情况下测试或解释命令：

```sh
ryk test "git status"
ryk test "rm -rf /" --format json
ryk explain "rm -rf /"
```

## 架构

启动别名、主机适配器、shell 评估器和策略引擎共用一条本地决策路径。

<p align="center">
  <img src="docs/images/ryk-architecture.svg" alt="ryk 架构：从代理主机经本地策略到受保护的效果和证据" width="100%">
</p>

1. 启动别名以 ryk 的会话默认值启动代理。
2. 主机适配器将 shell 和工具事件发送到评估器。
3. 评估器组合策略规则、安全 pack 匹配和当前模式。
4. ryk 允许、询问、观察或拒绝该动作。
5. 会话记录本地证据，供仪表盘和 replay 命令使用。

## 仪表盘

启动本地主机仪表盘：

```sh
ryk dashboard
```

打开 [http://127.0.0.1:7742](http://127.0.0.1:7742)。服务器默认仅监听 localhost，并使用现有的 ryk 策略和 CLI 路径。

用于冒烟测试和自动化时，`--once` 处理一个请求后退出：

```sh
ryk dashboard --once
```

## 限制

ryk 是分级中介，而非通用的操作系统沙箱。它以 macOS/Linux 为先。Windows 会话以 wrapper/hook 级别运行，没有操作系统沙箱。绝对路径二进制、未 shim 的工具、非代理流量以及未触发的 host hook 可能落在特定执行面之外。`ryk doctor` 报告平台能力；它不能证明子会话已附加到操作系统沙箱，也无法将 Windows 提升为 `OS-enforced`。在做出更强声明之前，请阅读[兼容性矩阵](docs/compatibility.md)和[威胁模型](docs/threat-model.md)。

发布版本包含可选的产品遥测：除非你运行 `ryk telemetry enable`，否则不会收集或发送任何数据。请参阅 [docs/telemetry.md](docs/telemetry.md) 了解确切的 payload 约定。

## 文档

从[文档索引](docs/README.md)开始。最有用的指南包括：

- [安装和发布产物](docs/install.md)
- [快速入门](docs/quickstart.md)
- [命令](docs/commands.md)
- [策略](docs/policy.md)
- [凭据和密钥处理](docs/credentials.md)
- [MCP](docs/mcp.md)
- [平台说明](docs/platform-linux.md)
- [Windows 平台](docs/platform-windows.md)

## 参与贡献

ryk 使用 Zig 0.16.0 构建。从检出目录：

```sh
./scripts/zig version
./scripts/compile-fast.sh check
./scripts/zig build test-shell-engine
```

提交 pull request 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请使用 [SECURITY.md](SECURITY.md)。

## 社区

- [网站](https://rykanv.com/)
- [Discord](https://discord.gg/uZn9MDUYKx)
- [GitHub Issues](https://github.com/christopherkarani/ryk/issues)

## 许可证

Apache 2.0。见 [LICENSE](LICENSE)。
