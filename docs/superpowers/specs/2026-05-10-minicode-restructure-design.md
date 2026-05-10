# MiniCode 包结构重组 — 设计

**Date**: 2026-05-10
**Branch**: feat/swebench-eval
**Scope**: 仅移动文件并修正 import,不改变任何函数行为或公开 API。

## 目标

把当前扁平的 `minicode/` 包(20 个 .py 文件 + 根目录 `tui.py`)按概念分层,
仿照 `Project/claude-code/package/cli/src/` 的目录组织方式,
让职责一目了然、文件粒度更小。

## 非目标

- 不改任何函数 / 类的行为或签名。
- 不"顺手"清理无关代码、注释、格式。
- 不为外部消费者保留旧路径 shim(用户已确认)。
- 不改 `bench/`、`tests/`、`bin/`、`.minicode/`、根 `skills/`(SKILL.md 内容目录)。

## 目录布局

```
minicode/
├── __init__.py
├── config.py                         # 不动
├── prompts.py                        # 不动(import 路径要改)
│
├── agent/                            # 运行时核心(非工具)
│   ├── __init__.py
│   ├── loop.py                       # ← minicode/loop.py
│   ├── dispatch.py                   # ← minicode/dispatch.py
│   └── compression.py                # ← minicode/compression.py
│
├── tools/                            # 所有 agent 可调用工具的实现
│   ├── __init__.py                   # re-export 顶层符号
│   ├── _common.py                    # _clamp_timeout
│   ├── persisted_output.py           # ← minicode/persisted_output.py
│   ├── bash.py                       # run_bash
│   ├── read.py                       # run_read
│   ├── write.py                      # run_write
│   ├── edit.py                       # run_edit
│   ├── grep.py                       # run_grep
│   ├── glob.py                       # run_glob
│   ├── subagent.py                   # ← minicode/subagent.py(task 工具)
│   ├── todos.py                      # ← minicode/todos.py
│   ├── tasks.py                      # ← minicode/tasks.py
│   ├── memory.py                     # ← minicode/memory.py
│   ├── scheduling.py                 # ← minicode/scheduling.py
│   ├── worktree.py                   # ← minicode/worktree.py
│   ├── mcp.py                        # ← minicode/mcp.py
│   ├── team.py                       # ← minicode/team.py
│   └── skills.py                     # ← minicode/skills.py
│
├── services/                         # 中间件
│   ├── __init__.py
│   ├── hooks.py                      # ← minicode/hooks.py
│   └── security.py                   # ← minicode/security.py
│
├── commands/                         # 入口面
│   ├── __init__.py                   # agent_runner 注入
│   ├── repl.py                       # ← cli.py 的 repl()(含斜杠命令)
│   └── batch.py                      # ← cli.py 的 run_prompt() / _arg()
│
└── ui/                               # ← 根目录 tui.py 完整内容
    ├── __init__.py                   # 暴露 run_app
    ├── app.py                        # MiniCodeApp + run_app
    ├── stream_capture.py             # _StreamCapture
    ├── screens/
    │   ├── __init__.py
    │   └── permission.py             # _PermissionModal
    └── components/
        ├── __init__.py
        └── side_panel.py             # _SidePanel
```

根目录:
- `main.py` 保留,作 thin entrypoint;import 改为 `from minicode.commands.batch import run_prompt`、`from minicode.commands.repl import repl`。
- `tui.py` 删除。

## 文件级映射

### 直接移动(单文件 → 单文件)

| 旧路径 | 新路径 |
|---|---|
| `minicode/loop.py`             | `minicode/agent/loop.py` |
| `minicode/dispatch.py`         | `minicode/agent/dispatch.py` |
| `minicode/compression.py`      | `minicode/agent/compression.py` |
| `minicode/subagent.py`         | `minicode/tools/subagent.py` |
| `minicode/todos.py`            | `minicode/tools/todos.py` |
| `minicode/tasks.py`            | `minicode/tools/tasks.py` |
| `minicode/memory.py`           | `minicode/tools/memory.py` |
| `minicode/scheduling.py`       | `minicode/tools/scheduling.py` |
| `minicode/worktree.py`         | `minicode/tools/worktree.py` |
| `minicode/mcp.py`              | `minicode/tools/mcp.py` |
| `minicode/team.py`             | `minicode/tools/team.py` |
| `minicode/skills.py`           | `minicode/tools/skills.py` |
| `minicode/persisted_output.py` | `minicode/tools/persisted_output.py` |
| `minicode/hooks.py`            | `minicode/services/hooks.py` |
| `minicode/security.py`         | `minicode/services/security.py` |

### 拆分

**`minicode/tools.py` → 6 个文件 + `_common.py`**

- `_clamp_timeout` → `tools/_common.py`
- `run_bash`  → `tools/bash.py`
- `run_read`  → `tools/read.py`
- `run_write` → `tools/write.py`
- `run_edit`  → `tools/edit.py`
- `run_grep`  → `tools/grep.py`
- `run_glob`  → `tools/glob.py`

`tools/__init__.py` **只 re-export 这 6 个 `run_*` 符号**,服务于 `agent/dispatch.py` 中既有的 `from minicode.tools import run_bash, ...` 风格;其它工具单例(`SKILLS`、`TODO`、`TASK_MGR` 等)不再 re-export,详见下文 import 规则。

**`minicode/cli.py` → `commands/repl.py` + `commands/batch.py`**

- `repl()` 及其内部斜杠命令分支 → `commands/repl.py`
- `_arg()`、`run_prompt()` → `commands/batch.py`
- 启动时的 `agent_runner` 注入两行(scheduling + team)→ `commands/__init__.py`,
  在 `repl` / `batch` 模块顶部 `import minicode.commands` 即可触发。

**根 `tui.py` → `minicode/ui/`**

- `_resolve_workdir`、模块顶部初始化、`run_app` → `ui/app.py`
- `_StreamCapture` → `ui/stream_capture.py`
- `_PermissionModal` → `ui/screens/permission.py`
- `_SidePanel` → `ui/components/side_panel.py`
- `MiniCodeApp` → `ui/app.py`
- `ui/__init__.py` 暴露 `run_app`

## Import 改动模式

每条 `from minicode.X import Y` 会被改成 `from minicode.<bucket>.X import Y`,例如:

| 旧 | 新 |
|---|---|
| `from minicode.loop import agent_loop`        | `from minicode.agent.loop import agent_loop` |
| `from minicode.dispatch import all_tools`     | `from minicode.agent.dispatch import all_tools` |
| `from minicode.compression import auto_compact` | `from minicode.agent.compression import auto_compact` |
| `from minicode.security import PERMS`         | `from minicode.services.security import PERMS` |
| `from minicode.hooks import HOOKS`            | `from minicode.services.hooks import HOOKS` |
| `from minicode.tools import run_bash, ...`    | 不变(`tools/__init__.py` 集中 re-export 6 个 `run_*`) |
| `from minicode.skills import SKILLS`          | `from minicode.tools.skills import SKILLS` |
| `from minicode.tasks import TASK_MGR, BG`     | `from minicode.tools.tasks import TASK_MGR, BG` |
| `from minicode.team import BUS, TEAM, ...`    | `from minicode.tools.team import ...` |
| `from minicode.memory import MEMORY, MEMORY_TYPES` | `from minicode.tools.memory import ...` |
| `from minicode.scheduling import CRON`        | `from minicode.tools.scheduling import CRON` |
| `from minicode.worktree import WORKTREES`     | `from minicode.tools.worktree import WORKTREES` |
| `from minicode.mcp import MCP`                | `from minicode.tools.mcp import MCP` |
| `from minicode.todos import TODO`             | `from minicode.tools.todos import TODO` |
| `from minicode.subagent import run_subagent`  | `from minicode.tools.subagent import run_subagent` |
| `from minicode.persisted_output import maybe_persist_output` | `from minicode.tools.persisted_output import maybe_persist_output` |

**统一规则**:

1. **`run_bash/run_read/run_write/run_edit/run_grep/run_glob` 这 6 个工具函数** 走包级别 re-export,即 `from minicode.tools import run_bash, ...` —— 唯一原因是 `agent/dispatch.py` 已用此形式且本次不改其调用风格。
2. **其余所有符号(`SKILLS`、`TODO`、`TASK_MGR`、`BG`、`MEMORY`、`MEMORY_TYPES`、`CRON`、`WORKTREES`、`MCP`、`BUS`、`TEAM`、`run_subagent`、`handle_*`、`maybe_persist_output`)** 都走精确子模块路径 `from minicode.tools.<sub> import ...`,**不**在 `tools/__init__.py` 里 re-export,避免循环 import 风险(team→tasks→memory 等内部依赖触发 `__init__` 部分加载时取不到符号)。
3. `tools/` 内部模块互相 import 也走精确子模块路径,如 `from minicode.tools.persisted_output import maybe_persist_output`。
4. 一律用绝对路径,不引入相对 import。

## `agent_runner` 注入

旧 `minicode/cli.py` 中:

```python
import minicode.scheduling as _sched
import minicode.team as _team
_sched.agent_runner = agent_loop
_team.agent_runner = agent_loop
```

新位置 `minicode/commands/__init__.py`:

```python
from minicode.agent.loop import agent_loop
import minicode.tools.scheduling as _sched
import minicode.tools.team as _team
_sched.agent_runner = agent_loop
_team.agent_runner = agent_loop
```

`commands/repl.py` 和 `commands/batch.py` 顶部不必显式 import 这一段 —
Python 在 import `minicode.commands.repl` 时会先执行 `minicode/commands/__init__.py`,完成注入。

## 风险与缓解

| 风险 | 缓解 |
|---|---|
| 漏改某处 import,启动崩 | 每搬完一桶执行 `python -c "from minicode.commands.repl import repl; from minicode.ui.app import run_app"` 烟测 |
| `tools/__init__.py` re-export 引发循环 import | 严格只 re-export 6 个 `run_*` 叶子函数;其它单例一律走子模块路径 |
| 外部脚本(`.minicode/` 下的工具)引用旧路径 | 用户已确认不留 shim;迁移时同步检查 `.minicode/`、`bin/` 中的 `from minicode.*` 字符串 |
| `tui.py` 拆分后样式或事件绑定丢失 | 拆分时仅做剪贴和 import 修复,不改任何 textual 装饰器 / CSS / handler |

## 成功标准

1. `python main.py --help` 正常打印帮助文本。
2. `python main.py --prompt "echo"` 不抛 ImportError 即视为通路联通(模型调用本身不在本次范围验证)。
3. `python -c "from minicode.ui.app import run_app"` 不抛错。
4. `pytest -q tests/` 与重组前结果一致(tests 不引用 minicode,所以应保持原状态)。
5. `git grep -n "from minicode\." minicode/ main.py` 返回的所有路径都在新布局内。
6. 工作树里只剩下:`main.py`、`minicode/` 新结构,无残留旧 .py 文件,无新增 shim。

## 范围之外

- 不动 `tui.py` 之外的根目录脚本。
- 不重命名任何公开类、单例(`SKILLS`、`MEMORY`、`TASK_MGR` 等)。
- 不改 `config.py` 的常量或 `prompts.py` 的文本。
- `tools/team.py`(394 行)和 `tools/tasks.py`(192 行)虽偏大,本次不做内部再拆。
