# MiniCode 包结构重组 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把当前扁平的 `minicode/` 包按概念分层重组(`agent/`、`tools/`、`services/`、`commands/`、`ui/`),仿照 `Project/claude-code/package/cli/src/` 的目录组织方式,不改变任何函数行为或公开 API。

**Architecture:** 按 bucket 自底向上迁移 —— 先建包骨架,再依次搬 services/ → tools/ → agent/ → commands/ → ui/,每搬完一桶就在所有仍存在的旧文件里把 `from minicode.<old>` 改成 `from minicode.<bucket>.<old>`,然后跑一次 import 烟测确保未破坏其它桶的可加载性。最后改 `main.py` 入口、删根 `tui.py`,全量烟测后提交。

**Tech Stack:** Python 3、Textual(TUI 库)、anthropic SDK。仓库无 minicode 单元测试套件;验收靠 import 烟测 + `python main.py --help` / `--prompt` 通路。

**Spec:** `docs/superpowers/specs/2026-05-10-minicode-restructure-design.md`

---

## 通用约定

- 每个 Task 末尾的 commit message 都以 `refactor(minicode): ` 开头并附:
  ```
  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```
- 用 `git mv` 而不是 `mv`,保留历史。
- 文件内容**不修改任何函数体**,只改顶部 import 语句。
- `tools/__init__.py` 只 re-export 6 个 `run_*` 工具函数;其它单例(`SKILLS`、`TODO`、`TASK_MGR`、`BG`、`MEMORY`、`MEMORY_TYPES`、`CRON`、`WORKTREES`、`MCP`、`BUS`、`TEAM`、`run_subagent`、`handle_*`、`maybe_persist_output`)**不**在那里 re-export,以避免循环 import。
- 烟测命令统一:
  ```bash
  python -c "import minicode"
  python main.py --help
  ```
  全量验收在 Task 7。

---

## Task 1: 建立新包骨架(不冲突的部分)

**Files (Create):**
- `minicode/agent/__init__.py`
- `minicode/services/__init__.py`
- `minicode/commands/__init__.py`
- `minicode/ui/__init__.py`
- `minicode/ui/screens/__init__.py`
- `minicode/ui/components/__init__.py`

> `minicode/tools/__init__.py` **本 Task 不建**:它会与现存的 `minicode/tools.py`(模块同名)冲突 —— 若同时存在,Python 优先选包,旧 `tools.py` 的 6 个 `run_*` 即刻不可访问。该包在 Task 3 里和 `tools.py` 的拆分一起完成。

- [ ] **Step 1**: 创建 5 个新包目录及空 `__init__.py`

  ```bash
  cd /Users/fscnb/Project/MiniCode
  mkdir -p minicode/agent minicode/services minicode/commands \
           minicode/ui/screens minicode/ui/components
  touch minicode/agent/__init__.py \
        minicode/services/__init__.py \
        minicode/commands/__init__.py \
        minicode/ui/__init__.py \
        minicode/ui/screens/__init__.py \
        minicode/ui/components/__init__.py
  ```

- [ ] **Step 2**: 烟测

  ```bash
  python -c "import minicode; import minicode.agent; import minicode.services; import minicode.commands; import minicode.ui; import minicode.ui.screens; import minicode.ui.components; print('skeleton ok')"
  ```

  Expected: `skeleton ok`,退出码 0。

- [ ] **Step 3**: 不单独 commit;留到 Task 2 合并提交(空 `__init__.py` 自身没有意义,合入第一次有内容的搬迁更清晰)。

---

## Task 2: 迁移 services/(hooks、security)

**Files:**
- Move: `minicode/hooks.py` → `minicode/services/hooks.py`
- Move: `minicode/security.py` → `minicode/services/security.py`
- Modify(本 Task 内):所有引用旧路径的 .py 文件。

预扫:

```bash
git grep -nE "from minicode\.(hooks|security)\b|import minicode\.(hooks|security)\b" -- "*.py"
```

预期命中范围:`minicode/cli.py`、`minicode/dispatch.py`、`minicode/loop.py`、`minicode/tools.py`、`minicode/team.py`、根 `tui.py`。

- [ ] **Step 1**: 用 `git mv` 搬文件

  ```bash
  git mv minicode/hooks.py minicode/services/hooks.py
  git mv minicode/security.py minicode/services/security.py
  ```

- [ ] **Step 2**: 批量更新引用

  ```bash
  python - <<'PY'
  import pathlib, re
  patterns = [
      (r"from minicode\.hooks import",    "from minicode.services.hooks import"),
      (r"import minicode\.hooks\b",       "import minicode.services.hooks"),
      (r"from minicode\.security import", "from minicode.services.security import"),
      (r"import minicode\.security\b",    "import minicode.services.security"),
  ]
  files = list(pathlib.Path("minicode").rglob("*.py")) + [pathlib.Path("tui.py"), pathlib.Path("main.py")]
  for p in files:
      if not p.exists(): continue
      s = str(p)
      if "/.venv/" in s or "/__pycache__/" in s: continue
      t = p.read_text(); new = t
      for pat, rep in patterns: new = re.sub(pat, rep, new)
      if new != t: p.write_text(new); print("updated", p)
  PY
  ```

- [ ] **Step 3**: 验证旧路径无残留

  ```bash
  git grep -nE "from minicode\.(hooks|security)\b|import minicode\.(hooks|security)\b" -- "*.py"
  ```

  Expected: 无输出。

- [ ] **Step 4**: 烟测

  ```bash
  python -c "from minicode.services.hooks import HOOKS; from minicode.services.security import PERMS, PERM_MODES, safe_path; print('services ok')"
  ```

  Expected: `services ok`。

- [ ] **Step 5**: Commit

  ```bash
  git add -A
  git commit -m "$(cat <<'EOF'
  refactor(minicode): move hooks/security under services/

  Also seed empty agent/, commands/, ui/ packages.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Task 3: 把 tools.py 拆成 tools/ 包,并把所有"工具实现"模块搬进来

最大的一步。分三段:**(a)** 整文件搬迁 → **(b)** 拆 tools.py → **(c)** 重写引用并修内部依赖。

### (a) 整文件搬迁 10 个工具实现模块

**Files (Move):**
| 旧 | 新 |
|---|---|
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

- [ ] **Step 1**: 搬 10 个文件

  ```bash
  cd /Users/fscnb/Project/MiniCode
  for f in subagent todos tasks memory scheduling worktree mcp team skills persisted_output; do
    git mv minicode/$f.py minicode/tools/$f.py
  done
  ```

  > 这一步之后 Python 看到目录 `minicode/tools/` 和文件 `minicode/tools.py` 同名。Python 优先选包,旧 `tools.py` 的 6 个 `run_*` 暂不可访问。下面立刻替换它。

### (b) 拆 minicode/tools.py

执行者**必须**先 `Read minicode/tools.py` 拿到原始函数体,**逐字复制**到新文件;以下样板仅作骨架与 import 指南。

- [ ] **Step 2**: 写 `minicode/tools/_common.py`

  ```python
  """Shared helpers for tool implementations."""


  def _clamp_timeout(value, default: int, hi: int) -> int:
      """Coerce a possibly-None / negative / oversized timeout into a sane int.

      Models sometimes pass `null` or wild values for `timeout`. Without this,
      `subprocess.run(timeout=None)` would block forever and a huge value
      would let a runaway shell hang the agent indefinitely.
      """
      try:
          v = int(value) if value is not None else default
      except (TypeError, ValueError):
          return default
      if v <= 0:
          return default
      return min(v, hi)
  ```

- [ ] **Step 3**: 写 `minicode/tools/bash.py`

  顶部:
  ```python
  """Bash tool: run shell command in WORKDIR."""
  import subprocess

  from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS, PERSIST_TRIGGER_BASH
  from minicode.tools._common import _clamp_timeout
  from minicode.tools.persisted_output import maybe_persist_output
  ```

  函数体:从原 `minicode/tools.py` 的 `def run_bash(...)` 整段复制(原行号约 26-40)。

- [ ] **Step 4**: 写 `minicode/tools/read.py`

  顶部:
  ```python
  """Read tool."""
  from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS
  from minicode.tools.persisted_output import maybe_persist_output
  from minicode.services.security import safe_path
  ```

  函数体:从原 `tools.py` 的 `def run_read(...)` 整段复制(约 42-56)。

- [ ] **Step 5**: 写 `minicode/tools/write.py`

  顶部:
  ```python
  """Write tool."""
  from minicode.config import WORKDIR
  from minicode.services.security import safe_path
  ```

  函数体:`def run_write(...)`(约 57-66)整段复制。

- [ ] **Step 6**: 写 `minicode/tools/edit.py`

  顶部:
  ```python
  """Edit tool: single-occurrence string replacement."""
  from minicode.config import WORKDIR
  from minicode.services.security import safe_path
  ```

  函数体:`def run_edit(...)`(约 67-80)整段复制。

- [ ] **Step 7**: 写 `minicode/tools/grep.py`

  顶部:
  ```python
  """Recursive regex grep across WORKDIR."""
  import subprocess

  from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS, PERSIST_TRIGGER_BASH
  from minicode.tools.persisted_output import maybe_persist_output
  from minicode.services.security import safe_path
  ```

  函数体:`def run_grep(...)`(约 81-92)整段复制。

- [ ] **Step 8**: 写 `minicode/tools/glob.py`

  顶部:
  ```python
  """Glob match files relative to WORKDIR."""
  from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS
  from minicode.tools.persisted_output import maybe_persist_output
  from minicode.services.security import safe_path
  ```

  函数体:`def run_glob(...)`(约 93-100)整段复制。

  > 各文件顶部 import 列表的精确范围以函数体内实际引用的符号为准 —— 执行者读完原函数后再增删,YAGNI。

- [ ] **Step 9**: 写 `minicode/tools/__init__.py`

  ```python
  """Tool implementations registered with the agent dispatcher.

  Only the 6 leaf I/O tools are re-exported here for the convenience of
  `minicode.agent.dispatch`. Other singletons (SKILLS, TODO, TASK_MGR,
  BG, MEMORY, MEMORY_TYPES, CRON, WORKTREES, MCP, BUS, TEAM,
  run_subagent, handle_*, maybe_persist_output) must be imported from
  their specific submodules to avoid circular import during package
  initialization.
  """
  from minicode.tools.bash import run_bash
  from minicode.tools.read import run_read
  from minicode.tools.write import run_write
  from minicode.tools.edit import run_edit
  from minicode.tools.grep import run_grep
  from minicode.tools.glob import run_glob

  __all__ = ["run_bash", "run_read", "run_write", "run_edit", "run_grep", "run_glob"]
  ```

- [ ] **Step 10**: 删除旧 `minicode/tools.py`

  ```bash
  git rm minicode/tools.py
  ```

### (c) 重写引用

- [ ] **Step 11**: 批量更新跨文件引用

  ```bash
  python - <<'PY'
  import pathlib, re
  mods = ["subagent","todos","tasks","memory","scheduling","worktree","mcp","team","skills","persisted_output"]
  patterns = []
  for m in mods:
      patterns.append((rf"from minicode\.{m} import",   f"from minicode.tools.{m} import"))
      patterns.append((rf"import minicode\.{m}\b",      f"import minicode.tools.{m}"))
  files = list(pathlib.Path("minicode").rglob("*.py")) + [pathlib.Path("tui.py"), pathlib.Path("main.py")]
  for p in files:
      if not p.exists(): continue
      s = str(p)
      if "/.venv/" in s or "/__pycache__/" in s: continue
      t = p.read_text(); new = t
      for pat, rep in patterns: new = re.sub(pat, rep, new)
      if new != t: p.write_text(new); print("updated", p)
  PY
  ```

- [ ] **Step 12**: 修 `tools/tasks.py` 内部:原 `from minicode.tools import _clamp_timeout`(若存在)在新布局下应改成 `from minicode.tools._common import _clamp_timeout`,因为 `_clamp_timeout` 不在 `tools/__init__.py` re-export。

  ```bash
  python - <<'PY'
  import pathlib, re
  p = pathlib.Path("minicode/tools/tasks.py")
  s = p.read_text()
  new = re.sub(r"from minicode\.tools import _clamp_timeout",
               "from minicode.tools._common import _clamp_timeout", s)
  if new != s: p.write_text(new); print("patched tools/tasks.py")
  else: print("tools/tasks.py: no change needed")
  PY
  grep -n "_clamp_timeout\|^from minicode\|^import minicode" minicode/tools/tasks.py
  ```

- [ ] **Step 13**: 检查 `tools/team.py`、`tools/subagent.py` 内部 `from minicode.tools import run_*` 这种 re-export 风格保持不变(合法,因为是 `__init__.py` 暴露的符号)。

  ```bash
  grep -n "^from minicode\|^import minicode" minicode/tools/team.py minicode/tools/subagent.py
  ```

  期望:所有 import 形如 `from minicode.config`、`from minicode.tools.<X>`、`from minicode.tools import run_*`、`from minicode.services.<X>` 之一。

- [ ] **Step 14**: 全局验证旧顶层模块无残留

  ```bash
  git grep -nE "from minicode\.(subagent|todos|tasks|memory|scheduling|worktree|mcp|team|skills|persisted_output)\b|import minicode\.(subagent|todos|tasks|memory|scheduling|worktree|mcp|team|skills|persisted_output)\b" -- "*.py"
  ```

  Expected: 无输出。

- [ ] **Step 15**: 烟测 — 逐个工具子模块 import

  ```bash
  python -c "
  from minicode.tools import run_bash, run_read, run_write, run_edit, run_grep, run_glob
  from minicode.tools.skills import SKILLS
  from minicode.tools.todos import TODO
  from minicode.tools.tasks import TASK_MGR, BG
  from minicode.tools.memory import MEMORY, MEMORY_TYPES
  from minicode.tools.scheduling import CRON
  from minicode.tools.worktree import WORKTREES
  from minicode.tools.mcp import MCP
  from minicode.tools.team import BUS, TEAM, handle_shutdown_request, handle_plan_review
  from minicode.tools.subagent import run_subagent
  from minicode.tools.persisted_output import maybe_persist_output
  from minicode.tools._common import _clamp_timeout
  print('all tools importable')
  "
  ```

  Expected: `all tools importable`。

- [ ] **Step 16**: Commit

  ```bash
  git add -A
  git commit -m "$(cat <<'EOF'
  refactor(minicode): consolidate tool implementations under tools/

  Split tools.py into one-file-per-tool (bash/read/write/edit/grep/glob)
  with _common.py for shared helpers. Move subagent, todos, tasks, memory,
  scheduling, worktree, mcp, team, skills, persisted_output into tools/
  since each backs an agent-callable tool. tools/__init__.py re-exports
  only the 6 leaf run_* functions; other singletons must be imported from
  their specific submodules.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Task 4: 迁移 agent/(loop、dispatch、compression)

**Files (Move):**
- `minicode/loop.py`        → `minicode/agent/loop.py`
- `minicode/dispatch.py`    → `minicode/agent/dispatch.py`
- `minicode/compression.py` → `minicode/agent/compression.py`

- [ ] **Step 1**: 搬

  ```bash
  git mv minicode/loop.py minicode/agent/loop.py
  git mv minicode/dispatch.py minicode/agent/dispatch.py
  git mv minicode/compression.py minicode/agent/compression.py
  ```

- [ ] **Step 2**: 批量更新引用

  ```bash
  python - <<'PY'
  import pathlib, re
  patterns = [
      (r"from minicode\.loop import",        "from minicode.agent.loop import"),
      (r"import minicode\.loop\b",           "import minicode.agent.loop"),
      (r"from minicode\.dispatch import",    "from minicode.agent.dispatch import"),
      (r"import minicode\.dispatch\b",       "import minicode.agent.dispatch"),
      (r"from minicode\.compression import", "from minicode.agent.compression import"),
      (r"import minicode\.compression\b",    "import minicode.agent.compression"),
  ]
  files = list(pathlib.Path("minicode").rglob("*.py")) + [pathlib.Path("tui.py"), pathlib.Path("main.py")]
  for p in files:
      if not p.exists(): continue
      s = str(p)
      if "/.venv/" in s or "/__pycache__/" in s: continue
      t = p.read_text(); new = t
      for pat, rep in patterns: new = re.sub(pat, rep, new)
      if new != t: p.write_text(new); print("updated", p)
  PY
  ```

- [ ] **Step 3**: 验证

  ```bash
  git grep -nE "from minicode\.(loop|dispatch|compression)\b|import minicode\.(loop|dispatch|compression)\b" -- "*.py"
  ```

  Expected: 无输出。

- [ ] **Step 4**: 烟测

  ```bash
  python -c "
  from minicode.agent.loop import agent_loop
  from minicode.agent.dispatch import all_tools, execute_one_tool, system_blocks_cached, tools_cached, PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS, CACHE_ENABLED
  from minicode.agent.compression import auto_compact, estimate_tokens, microcompact, append_user_text
  print('agent ok')
  "
  ```

  Expected: `agent ok`。

- [ ] **Step 5**: Commit

  ```bash
  git add -A
  git commit -m "$(cat <<'EOF'
  refactor(minicode): move loop/dispatch/compression under agent/

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Task 5: 拆 cli.py 成 commands/

**Files:**
- Create: `minicode/commands/__init__.py` (覆写,做 `agent_runner` 注入)
- Create: `minicode/commands/repl.py`     (含 `repl()` 和内部斜杠命令逻辑)
- Create: `minicode/commands/batch.py`    (含 `_arg()` 和 `run_prompt()`)
- Delete: `minicode/cli.py`
- Modify: `main.py`(根目录)

执行者**必须**先 `Read minicode/cli.py` 拿到 `repl`、`_arg`、`run_prompt` 的完整函数体,逐字复制;以下示例仅作骨架与 import 指南。

- [ ] **Step 1**: 读 cli.py 确认结构

  ```bash
  grep -n "^def \|^class \|^import\|^from" minicode/cli.py
  ```

  预期:`repl()` 在 31,`_arg()` 在 119,`run_prompt()` 在 129。`import minicode.scheduling as _sched` 等注入逻辑在文件顶部(约 24-28)。

- [ ] **Step 2**: 覆写 `minicode/commands/__init__.py`

  ```python
  """Command-line entrypoints (REPL + batch prompt) and runtime wiring.

  Importing this package (or any submodule) triggers the agent_runner
  injection that scheduling and team need.
  """
  from minicode.agent.loop import agent_loop
  import minicode.tools.scheduling as _sched
  import minicode.tools.team as _team

  _sched.agent_runner = agent_loop
  _team.agent_runner = agent_loop
  ```

- [ ] **Step 3**: 写 `minicode/commands/repl.py`

  顶部 import(根据 cli.py 顶部抄写并按新路径调整):

  ```python
  """Interactive REPL entrypoint."""
  import json
  import sys
  import time
  from pathlib import Path

  from minicode.config import (
      WORKDIR, MODEL, STATE_DIR, TRUST_MARKER,
  )
  from minicode.services.security import PERMS, PERM_MODES
  from minicode.services.hooks import HOOKS
  from minicode.tools.memory import MEMORY
  from minicode.tools.tasks import TASK_MGR
  from minicode.tools.skills import SKILLS
  from minicode.tools.scheduling import CRON
  from minicode.tools.worktree import WORKTREES
  from minicode.tools.mcp import MCP
  from minicode.tools.team import BUS, TEAM
  from minicode.agent.compression import auto_compact
  from minicode.agent.loop import agent_loop
  from minicode.prompts import HELP_TEXT
  ```

  函数体:从 cli.py 的 `def repl():` 整段复制(约 31-118)到 `def _arg(` 之前为止。

  > **不要**在本文件再写 `_sched.agent_runner = agent_loop` 等注入语句 —— 已经在 `commands/__init__.py` 完成。Python import `minicode.commands.repl` 时会先执行 `minicode/commands/__init__.py`。

- [ ] **Step 4**: 写 `minicode/commands/batch.py`

  ```python
  """Batch prompt entrypoint (--prompt / --prompt-file)."""
  ```

  顶部 import:执行者读 cli.py 的 119 行之后,**只**搬 `_arg` 和 `run_prompt` 实际引用的符号(YAGNI)。已知至少需要:

  ```python
  import json
  import sys
  import time
  from pathlib import Path

  from minicode.config import WORKDIR, MODEL, STATE_DIR
  from minicode.agent.loop import agent_loop
  ```

  其余按函数体补足。函数体:`def _arg(...)` 和 `def run_prompt(...)` 整段复制。

- [ ] **Step 5**: 删除 cli.py

  ```bash
  git rm minicode/cli.py
  ```

- [ ] **Step 6**: 改 `main.py`

  ```python
  #!/usr/bin/env python3
  """MiniCode entrypoint - see minicode/ package for implementation."""
  import sys

  from minicode.commands.repl import repl
  from minicode.commands.batch import run_prompt
  from minicode.prompts import HELP_TEXT


  if __name__ == "__main__":
      if "--help" in sys.argv:
          print(HELP_TEXT)
          sys.exit(0)
      if "--version" in sys.argv:
          print("minicode 0.1")
          sys.exit(0)
      if ("--prompt" in sys.argv
              or any(a.startswith("--prompt=") for a in sys.argv)
              or "--prompt-file" in sys.argv
              or any(a.startswith("--prompt-file=") for a in sys.argv)):
          run_prompt()
      repl()
  ```

- [ ] **Step 7**: 修对 `minicode.cli` 的残留引用

  ```bash
  git grep -nE "from minicode\.cli\b|import minicode\.cli\b" -- "*.py"
  ```

  对每条命中:`repl` 改成 `from minicode.commands.repl import repl`,`run_prompt` 改成 `from minicode.commands.batch import run_prompt`。

- [ ] **Step 8**: 烟测

  ```bash
  python -c "from minicode.commands.repl import repl; from minicode.commands.batch import run_prompt; print('cli ok')"
  python main.py --help
  python main.py --version
  ```

  Expected: 第一条打印 `cli ok`;第二条打印帮助文本退出 0;第三条打印 `minicode 0.1` 退出 0。

- [ ] **Step 9**: Commit

  ```bash
  git add -A
  git commit -m "$(cat <<'EOF'
  refactor(minicode): split cli.py into commands/repl.py + commands/batch.py

  agent_runner injection moved into commands/__init__.py so importing
  either repl or batch wires it before first use.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Task 6: 拆根 tui.py 成 minicode/ui/

**Files:**
- Create: `minicode/ui/stream_capture.py`         (`_StreamCapture`)
- Create: `minicode/ui/screens/permission.py`     (`_PermissionModal`)
- Create: `minicode/ui/components/side_panel.py`  (`_SidePanel`)
- Create: `minicode/ui/app.py`                    (`_resolve_workdir`、模块级初始化、`MiniCodeApp`、`run_app`)
- Modify: `minicode/ui/__init__.py`               (暴露 `run_app`)
- Delete: 根 `tui.py`

执行者必须先逐段 Read 原 `tui.py`,逐字复制类体,**不改任何 Textual 装饰器 / reactive / CSS / event handler**。

- [ ] **Step 1**: 划分

  ```bash
  grep -n "^def \|^class " tui.py
  ```

  预期:
  - `_resolve_workdir` 约 37
  - `_StreamCapture`   约 76-107
  - `_PermissionModal` 约 109-151
  - `_SidePanel`       约 153-212
  - `MiniCodeApp`      约 214-577
  - `run_app`          约 579-591

- [ ] **Step 2**: 写 `minicode/ui/stream_capture.py`

  - 把 `class _StreamCapture:` 整段从原 tui.py 复制。
  - 顶部 import:照原 tui.py 顶部摘取本类实际用到的(`import io`、`from textual.message import Message` 等 —— 以原代码为准)。

- [ ] **Step 3**: 写 `minicode/ui/screens/permission.py`

  - `class _PermissionModal(ModalScreen[str]):` 整段复制。
  - 顶部 import:`from textual.screen import ModalScreen`、`from textual.widgets import ...` 等,按类体实际引用裁剪。

- [ ] **Step 4**: 写 `minicode/ui/components/side_panel.py`

  - `class _SidePanel(Static):` 整段复制。
  - 顶部:`from textual.widgets import Static` 等。

- [ ] **Step 5**: 写 `minicode/ui/app.py`

  顶部 import(按新路径调整):

  ```python
  """MiniCode Textual TUI application."""
  import json
  import os
  import sys
  import threading
  import time
  from pathlib import Path

  from textual.app import App, ComposeResult
  # (再补 Textual 容器 / 控件,以原 tui.py 顶部为准)

  from minicode.config import MODEL, STATE_DIR, TRUST_MARKER
  from minicode.services.security import PERMS, PERM_MODES
  from minicode.services.hooks import HOOKS
  from minicode.tools.memory import MEMORY
  from minicode.tools.skills import SKILLS
  from minicode.tools.tasks import TASK_MGR, BG
  from minicode.tools.scheduling import CRON
  from minicode.tools.worktree import WORKTREES
  from minicode.tools.mcp import MCP
  from minicode.tools.team import BUS, TEAM
  from minicode.agent.compression import auto_compact
  from minicode.agent.loop import agent_loop

  from minicode.ui.stream_capture import _StreamCapture
  from minicode.ui.screens.permission import _PermissionModal
  from minicode.ui.components.side_panel import _SidePanel
  ```

  函数 / 类体:把 `_resolve_workdir`、所有模块级初始化语句(原 tui.py 顶部 sys.path / 环境处理那段)、`class MiniCodeApp(App):`、`def run_app():` 整段复制。

  > 原 tui.py 顶部可能有 `sys.path.insert(...)` 之类把仓库根加入 path 的代码。在 ui/app.py 中应改为基于 `Path(__file__)` 推导,或干脆删除(模块从包内 import,不再需要把仓库根插入 sys.path)。**执行者复制这段前要先判断**:若仅为旧 `tui.py` 在根目录直接执行所需,可整段删除;若被其它逻辑依赖,保留并改成相对推导。

- [ ] **Step 6**: 覆写 `minicode/ui/__init__.py`

  ```python
  """Textual TUI for MiniCode."""
  from minicode.ui.app import run_app

  __all__ = ["run_app"]
  ```

- [ ] **Step 7**: 删根 `tui.py`

  ```bash
  git rm tui.py
  ```

- [ ] **Step 8**: 检查仓库其它文件对根 `tui` 的引用

  ```bash
  git grep -nE "tui\.py|from tui\b|import tui\b|\btui:run_app\b" -- "*.py" "*.toml" "bin/*" "README*"
  ```

  对命中项:
  - `pyproject.toml` 若有 `[project.scripts]` 入口 `minicode-tui = "tui:run_app"`,改成 `minicode.ui:run_app`。
  - `bin/*` 脚本若 `python tui.py`,改成 `python -m minicode.ui` 或 `python -c "from minicode.ui import run_app; run_app()"`。
  - README 中提到 `tui.py` 的位置同步更新。

- [ ] **Step 9**: 烟测

  ```bash
  python -c "from minicode.ui import run_app; print('ui ok')"
  python -c "from minicode.ui.app import MiniCodeApp; print('app class ok')"
  ```

  Expected: 两行各打印一条 "ok"。

  > **不**实际启动 TUI(它需要 TTY 且会阻塞)。Textual 渲染本身的回归只能靠人工启动验收。

- [ ] **Step 10**: Commit

  ```bash
  git add -A
  git commit -m "$(cat <<'EOF'
  refactor(minicode): move TUI into minicode/ui/ with screens + components

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Task 7: 全量验证

- [ ] **Step 1**: 全局检查旧顶层模块引用残留

  ```bash
  git grep -nE "from minicode\.(loop|dispatch|compression|subagent|todos|tasks|memory|scheduling|worktree|mcp|team|skills|persisted_output|hooks|security|cli)\b|import minicode\.(loop|dispatch|compression|subagent|todos|tasks|memory|scheduling|worktree|mcp|team|skills|persisted_output|hooks|security|cli)\b" -- "*.py"
  ```

  Expected: 无输出。

- [ ] **Step 2**: 检查 `from minicode.tools import X` 中 X 只能是 6 个 `run_*`

  ```bash
  python - <<'PY'
  import pathlib, re
  ok = {"run_bash","run_read","run_write","run_edit","run_grep","run_glob"}
  bad_any = False
  for p in pathlib.Path(".").rglob("*.py"):
      s = str(p)
      if "/.venv/" in s or "/__pycache__/" in s or "/.claude/" in s: continue
      for ln in p.read_text().splitlines():
          m = re.match(r"\s*from minicode\.tools import (.+?)(?:\s*#.*)?$", ln)
          if not m: continue
          names = [n.strip() for n in m.group(1).split(",")]
          bad = [n for n in names if n and n not in ok]
          if bad:
              print(p, "->", bad)
              bad_any = True
  print("FAIL" if bad_any else "ok")
  PY
  ```

  Expected: `ok`。

- [ ] **Step 3**: 包级 import 烟测

  ```bash
  python -c "
  import minicode
  from minicode.agent.loop import agent_loop
  from minicode.agent.dispatch import all_tools, execute_one_tool
  from minicode.agent.compression import auto_compact
  from minicode.services.hooks import HOOKS
  from minicode.services.security import PERMS
  from minicode.tools import run_bash, run_read, run_write, run_edit, run_grep, run_glob
  from minicode.tools.skills import SKILLS
  from minicode.tools.team import BUS, TEAM
  from minicode.tools.tasks import TASK_MGR, BG
  from minicode.tools.memory import MEMORY, MEMORY_TYPES
  from minicode.commands.repl import repl
  from minicode.commands.batch import run_prompt
  from minicode.ui import run_app
  print('all imports ok')
  "
  ```

  Expected: `all imports ok`。

- [ ] **Step 4**: 入口烟测

  ```bash
  python main.py --help
  python main.py --version
  ```

  Expected: 第一条打印帮助文本退出 0;第二条打印 `minicode 0.1` 退出 0。

- [ ] **Step 5**: 现有 pytest 套件(应与重组前结果一致;tests/ 不引用 minicode)

  ```bash
  pytest -q tests/
  ```

  Expected: 与 main 分支同等执行结果。

- [ ] **Step 6**: 列出最终包结构供留档

  ```bash
  find minicode -name "*.py" -not -path "*/__pycache__/*" | sort
  ```

  Expected: 与 spec 设计文档列出的目录布局一致,无残留旧顶层 .py。

- [ ] **Step 7**: 本 Task 仅为验收,无文件改动,不 commit。若发现遗漏,回到对应 Task 补修并独立 commit;不要把修补藏在"验证"提交里。

---

## 失败回滚约定

任一 Task 烟测失败时:

1. **不要进入下一 Task**。
2. `git status` 查看未提交改动。如本 Task 还未 commit,可 `git restore .` + `git clean -fd minicode/<new_subdir>` 回退重做。
3. 已 commit 的 Task,如发现影响后续,优先 `git revert <sha>`(而非 `git reset --hard`),保留可见的修正历史。
4. 如 Python 抛 `CircularImportError`:几乎可以确定是有人在 `tools/__init__.py` re-export 了 6 个 `run_*` 之外的符号。重读"通用约定"中的 re-export 规则。
