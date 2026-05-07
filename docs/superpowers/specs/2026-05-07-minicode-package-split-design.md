# MiniCode Package Split — Design

**Date:** 2026-05-07
**Branch:** feat/swebench-eval (refactor work to land on a follow-up branch)
**Goal:** Split the 2563-line `main.py` into a `minicode/` package organized by topic, without changing behavior.

## 1. Motivation

`main.py` currently holds the entire harness: config, security, tools, managers, MCP, team, scheduling, system prompt, dispatch, agent loop, REPL — ~30 named `# === SECTION ===` blocks in one file. This makes the file slow to navigate, painful to grep within, and forces every consumer (`tui.py`) to import the whole thing as a namespace.

Splitting into a topic-organized package gives the codebase clear unit boundaries while keeping the change surgical: no API changes, no behavior changes, no new abstractions.

## 2. Non-Goals

- No dependency injection container, no `Session`/`AgentContext` class.
- No renames of public names (`MODEL`, `PERMS`, `TASK_MGR`, `agent_loop`, …).
- No edits to existing logic — including known global-state coupling.
- No changes to `bench/`, `tests/`, `bin/`, `pyproject.toml`, `skills/`.
- No new documentation outside this spec; no README updates.

## 3. Target Layout

```
MiniCode/
├── main.py                    # ~10-line thin entrypoint
├── tui.py                     # rewritten: imports from minicode.* directly
├── bench/                     # unchanged
├── tests/                     # unchanged
├── bin/minicode               # unchanged
├── pyproject.toml             # unchanged (entry points still resolve)
└── minicode/
    ├── __init__.py
    ├── config.py              # bootstrap: load_dotenv, MODEL, WORKDIR, STATE_DIR & friends, Anthropic client, all constants
    ├── persisted_output.py    # _persist_tool_result, maybe_persist_output, _build_persisted_marker, _format_size, _preview_slice
    ├── security.py            # safe_path, BashSecurityValidator, PermissionManager, PERMS, PERM_MODES
    ├── hooks.py               # HookManager, HOOKS
    ├── memory.py              # MemoryManager, MEMORY
    ├── tools.py               # _clamp_timeout, run_bash, run_read, run_write, run_edit, run_grep, run_glob
    ├── skills.py              # SkillLoader, SKILLS
    ├── todos.py               # TodoManager, TODO
    ├── subagent.py            # run_subagent
    ├── compression.py         # estimate_tokens, microcompact, auto_compact
    ├── tasks.py               # TaskManager + BackgroundManager + TASK_MGR + BG
    ├── scheduling.py          # cron_matches, _cron_field, CronScheduler, CRON
    ├── worktree.py            # WorktreeManager, WORKTREES
    ├── mcp.py                 # MCPClient, MCPManager, MCP
    ├── team.py                # MessageBus + BUS + TeammateManager + TEAM + handle_shutdown_request + handle_plan_review
    ├── prompts.py             # build_system_prompt, HELP_TEXT
    ├── dispatch.py            # TOOLS_BASE, TOOL_HANDLERS, all_tools, append_user_text,
    │                          # system_blocks_cached, tools_cached, PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS,
    │                          # _PERMS_ASK_LOCK, execute_one_tool
    ├── loop.py                # agent_loop
    └── cli.py                 # repl, run_prompt, _arg, batch entry (_BATCH)
```

19 modules, each corresponding to 1-3 of the existing `# === SECTION ===` blocks. `persisted_output.py` is split out from `tools.py` because it is a tool-agnostic IO helper.

## 4. Dependency Layering

Topological order (no internal cycles after lazy injection of two callbacks):

| Layer | Modules | Depends on |
|-------|---------|------------|
| L0 | `config` | (stdlib + anthropic + dotenv) |
| L1 | `persisted_output`, `hooks`, `memory`, `skills`, `todos`, `worktree`, `mcp` | `config` |
| L1 | `scheduling` (class skeleton, no agent runner yet) | `config` |
| L2 | `security` | `config` |
| L3 | `tools` | `config`, `security`, `persisted_output` |
| L4 | `subagent` | `config`, `tools` |
| L5 | `compression` | `config` |
| L6 | `tasks` | `config`, `hooks` |
| L7 | `team` | `config`, `tasks`, `hooks` |
| L8 | `prompts` | `memory`, `skills`, `mcp`, `team`, `todos`, `scheduling`, `worktree`, `tasks` |
| L9 | `dispatch` | all of the above |
| L10 | `loop` | `dispatch`, `compression`, `prompts`, `hooks`, `security` |
| L11 | `cli` | `loop` + all manager singletons |

### 4.1 Cycle resolution

Two real cycles exist if we import naively:

1. **`scheduling.CronScheduler.fire()` runs an agent loop** when a scheduled prompt fires.
2. **`team.TeammateManager.spawn()` runs an agent loop** for each teammate.

Both are resolved by **callback injection** rather than direct import:

- `scheduling.py` declares a module-level `agent_runner = None`, used as `agent_runner(history)`.
- `team.py` declares a module-level `agent_runner = None` similarly.
- `cli.repl()` (and `run_prompt()`) wires them on startup:
  ```python
  import minicode.scheduling as _sched
  import minicode.team as _team
  from minicode.loop import agent_loop
  _sched.agent_runner = agent_loop
  _team.agent_runner = agent_loop
  ```

This keeps modules acyclic and matches the existing "runtime composition" pattern of `main.py`.

## 5. main.py and tui.py

### 5.1 New `main.py` (thin entrypoint, ~15 lines)

The current `if __name__ == "__main__"` block in `main.py` handles `--help`, `--version`, `--prompt`, and `--prompt-file`. The thin entrypoint preserves that exact dispatch:

```python
#!/usr/bin/env python3
# MiniCode entrypoint — see minicode/ package for implementation.
import sys

from minicode.cli import repl, run_prompt
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

The `pyproject.toml` entry point `minicode = "main:repl"` still resolves because `main.py` re-exports `repl`.

### 5.2 Rewritten `tui.py`

All ~30 `main.X` references are replaced with explicit submodule imports:

| Old | New |
|---|---|
| `import main` | (removed) |
| `main.TASK_MGR` | `from minicode.tasks import TASK_MGR` |
| `main.TEAM`, `main.BUS` | `from minicode.team import TEAM, BUS` |
| `main.MEMORY` | `from minicode.memory import MEMORY` |
| `main.CRON` | `from minicode.scheduling import CRON` |
| `main.MCP` | `from minicode.mcp import MCP` |
| `main.HOOKS` | `from minicode.hooks import HOOKS` |
| `main.SKILLS` | `from minicode.skills import SKILLS` |
| `main.WORKTREES` | `from minicode.worktree import WORKTREES` |
| `main.PERMS`, `main.PERM_MODES` | `from minicode.security import PERMS, PERM_MODES` |
| `main.MODEL`, `main.WORKDIR`, `main.STATE_DIR`, `main.TRUST_MARKER` | `from minicode.config import MODEL, WORKDIR, STATE_DIR, TRUST_MARKER` |
| `main.agent_loop` | `from minicode.loop import agent_loop` |
| `main.auto_compact` | `from minicode.compression import auto_compact` |
| `main.json` | top-of-file `import json` |

`bin/minicode` is unchanged — it still runs `tui.py` or `main.py`.

## 6. Migration Plan

Land in 6 small commits, each one independently runnable (`from main import repl` works, `pytest tests/` passes):

| # | Scope |
|---|---|
| 1 | Create `minicode/` skeleton + `config.py` + `persisted_output.py` + L1 leaf managers (`hooks`, `memory`, `skills`, `todos`, `worktree`, `mcp`). `main.py` imports them back during transition. |
| 2 | Add `security.py`, `tools.py`, `subagent.py`, `compression.py`, `tasks.py`, `scheduling.py`, `team.py`. |
| 3 | Add `prompts.py`, `dispatch.py`, `loop.py`, `cli.py`. |
| 4 | Shrink `main.py` to the thin entrypoint. |
| 5 | Rewrite `tui.py` to import from `minicode.*`. |
| 6 | Sweep: delete any dead code left in `main.py`, clear `__pycache__`. |

### 6.1 Mechanical-split rules

1. **Cut by SECTION, paste verbatim** — keep code order, comments, blank lines.
2. **Per-module imports**: each new module's top declares only what it actually uses (`from minicode.config import WORKDIR, MODEL, client`, etc.). Module-level singleton instantiations stay at the bottom of their owning module.
3. **No renames** — `MODEL`, `PERMS`, `TASK_MGR`, `agent_loop`, etc. keep their names.
4. **Cross-module cycles → callback injection** (see §4.1).
5. **`minicode/__init__.py`** stays empty (or minimal). Consumers import explicit submodule paths; no namespace magic.

## 7. Verification

After each commit:

```bash
# 1. Import sanity
uv run python -c "from main import repl, run_prompt"
uv run python -c "import tui"

# 2. Existing tests (bench tests act as a baseline; behavior must be unchanged)
uv run pytest tests/ -q

# 3. REPL smoke
echo "/help"  | uv run python main.py
echo "/tasks" | uv run python main.py

# 4. TUI launch (start, then immediately exit)
uv run python tui.py . </dev/null &
sleep 2 && kill %1

# 5. Single-prompt end-to-end (optional, real API call)
uv run python main.py --prompt "echo hello via bash"
```

After commit 4, also: `wc -l main.py` should report well under 50 lines.

## 8. Risk Register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Hidden circular import surfaces during commit 2 or 3 | Medium | Callback-injection pattern documented; if a fresh cycle appears, prefer lazy `import` inside the function over restructuring layers. |
| `tui.py` references a name we missed in the rename table | Low-Medium | After commit 5, run `grep -n "^.*\bmain\." tui.py` — must return zero matches. |
| `pyproject.toml` entry-point regression | Low | `minicode = "main:repl"` still valid since `main.py` re-exports `repl`. Verified by `uv run minicode --help` post-refactor. |
| Hooks (`HOOKS.run("SessionStart")` etc.) fire in different order | Low | `cli.repl()` reproduces the exact startup/shutdown sequence from current `main.repl()`. |
| Cron/teammate agent runs blow up because `agent_runner` is `None` | Low | Wired in `cli.repl()` and `cli.run_prompt()` before any cron/teammate code can fire. Add a guard: `if agent_runner is None: raise RuntimeError(...)`. |

## 9. Out of Scope (Future Work)

- Replacing module-level singletons with a `Session` object (deferred — explicitly chosen against in brainstorming).
- Fixing existing global-state coupling between `dispatch.TOOL_HANDLERS` and managers.
- Splitting `bench/swebench_run.py` similarly (it's only 452 lines, not a current pain point).
- Test coverage for the harness itself (currently only `bench/` is tested).
