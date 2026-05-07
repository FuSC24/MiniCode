# MiniCode Package Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `main.py` (2563 lines) into a topic-organized `minicode/` package without changing behavior.

**Architecture:** Mechanical extract-by-section. Each new module owns 1-3 of the existing `# === SECTION: ... ===` blocks. During migration, `main.py` re-exports from new modules to keep `tui.py` and `pyproject.toml` entry points working. Two cycle points (`scheduling.CronScheduler.fire` → agent_loop, `team.TeammateManager.spawn` → agent_loop) are resolved by injecting `agent_runner = agent_loop` from `cli.py` at startup. No public names are renamed.

**Tech Stack:** Python 3.10+, uv, pytest, anthropic SDK.

**Spec:** `docs/superpowers/specs/2026-05-07-minicode-package-split-design.md`

---

## Verification commands (used in every task)

These three commands constitute the "test suite" for this mechanical refactor. Every task ends by running them; they MUST all succeed before commit.

```bash
# (1) entrypoint imports still work
uv run python -c "from main import repl, run_prompt; print('ok')"

# (2) tui imports still work (until Task 22 it imports `main`; after Task 22 it imports minicode.*)
uv run python -c "import tui; print('ok')"

# (3) bench tests still pass
uv run pytest tests/ -q
```

If any one fails, stop and diagnose before proceeding. Do NOT commit a red task.

## File Structure (target end state)

```
MiniCode/
├── main.py                    # ~25 lines — thin entry, re-exports during migration
├── tui.py                     # rewritten in Task 22
├── bench/                     # untouched
├── tests/                     # untouched
├── bin/minicode               # untouched
├── pyproject.toml             # untouched
└── minicode/
    ├── __init__.py            # empty
    ├── config.py              # bootstrap, paths, constants, Anthropic client
    ├── persisted_output.py    # _persist_tool_result, maybe_persist_output, helpers
    ├── security.py            # safe_path, BashSecurityValidator, PermissionManager, PERMS, PERM_MODES
    ├── hooks.py               # HookManager, HOOKS
    ├── memory.py              # MemoryManager, MEMORY
    ├── tools.py               # _clamp_timeout, run_bash/read/write/edit/grep/glob
    ├── skills.py              # SkillLoader, SKILLS
    ├── todos.py               # TodoManager, TODO
    ├── subagent.py            # run_subagent
    ├── compression.py         # estimate_tokens, microcompact, auto_compact
    ├── tasks.py               # TaskManager, BackgroundManager, TASK_MGR, BG
    ├── scheduling.py          # cron_matches, _cron_field, CronScheduler, CRON, agent_runner
    ├── worktree.py            # WorktreeManager, WORKTREES
    ├── mcp.py                 # MCPClient, MCPManager, MCP
    ├── team.py                # MessageBus, BUS, TeammateManager, TEAM, handle_shutdown_request, handle_plan_review, agent_runner
    ├── prompts.py             # build_system_prompt, HELP_TEXT
    ├── dispatch.py            # TOOLS_BASE, TOOL_HANDLERS, all_tools, append_user_text, system_blocks_cached, tools_cached, PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS, _PERMS_ASK_LOCK, execute_one_tool, CACHE_ENABLED
    ├── loop.py                # agent_loop
    └── cli.py                 # repl, run_prompt, _arg; wires agent_runner injection
```

## Migration pattern (used by Tasks 2-20)

Every module-extraction task follows the same recipe:

1. Identify the section line range in `main.py` (e.g. `1135-1194` for messaging).
2. Create `minicode/<module>.py` with:
   - A focused import header (only what the module actually uses).
   - The verbatim code body copied from those line ranges.
   - The corresponding singleton instantiation line(s) (originally in `# === SECTION: instances ===` at lines 1786-1800) appended to the bottom.
3. In `main.py`, replace the original section body with a single `from minicode.<module> import <names>` line that re-exports every public name. Keep the `# === SECTION: ... ===` comment so navigation still works.
4. In `main.py`'s `# === SECTION: instances ===`, delete the singleton line that was just moved.
5. Run the three verification commands above. All three must succeed.
6. Commit.

**Why re-export instead of full removal in main.py:** This keeps `tui.py` (which still does `import main; main.HOOKS`) green throughout the migration. `tui.py` is rewritten in Task 22, after all extractions are done.

---

## Task 1: Create `minicode/` package skeleton

**Files:**
- Create: `minicode/__init__.py`

- [ ] **Step 1: Create the empty package**

```bash
mkdir -p minicode
: > minicode/__init__.py
```

- [ ] **Step 2: Verify package imports**

```bash
uv run python -c "import minicode; print('ok')"
```

Expected: `ok`

- [ ] **Step 3: Verify baseline still passes**

Run the three verification commands listed under "Verification commands" above. All three must print `ok` (or pytest passes).

- [ ] **Step 4: Commit**

```bash
git add minicode/__init__.py
git commit -m "refactor(minicode): scaffold empty package"
```

---

## Task 2: Extract `config.py`

**Source range in `main.py`:** lines 23-65 (`# === SECTION: bootstrap ===`).

**Names this module owns:** `WORKDIR`, `client`, `MODEL`, `STATE_DIR`, `TASKS_DIR`, `TEAM_DIR`, `INBOX_DIR`, `TASK_OUTPUT_DIR`, `TOOL_RESULTS_DIR`, `TRANSCRIPT_DIR`, `CRON_DIR`, `WORKTREE_DIR`, `MCP_DIR`, `MEMORY_DIR`, `SKILLS_DIR`, `HOOKS_FILE`, `TRUST_MARKER`, `TOKEN_THRESHOLD`, `PERSIST_TRIGGER_DEFAULT`, `PERSIST_TRIGGER_BASH`, `PERSIST_PREVIEW_CHARS`, `CONTEXT_TRUNCATE_CHARS`, `KEEP_RECENT_RESULTS`, `PRESERVE_RESULT_TOOLS`, `POLL_INTERVAL`, `IDLE_TIMEOUT`, `TEAM_MAX_CONSECUTIVE_TURNS`, `VALID_MSG_TYPES`.

**Files:**
- Create: `minicode/config.py`
- Modify: `main.py` (replace lines 23-65 with re-export)

- [ ] **Step 1: Create `minicode/config.py`**

Header:
```python
"""Bootstrap: env loading, paths, constants, shared Anthropic client."""
import os
from pathlib import Path

from anthropic import Anthropic
from dotenv import load_dotenv
```

Body: copy the section body from `main.py:23-65` verbatim (everything from `load_dotenv(override=True)` down through the `VALID_MSG_TYPES = {...}` block).

- [ ] **Step 2: Replace section in `main.py`**

Replace lines 23-65 with:
```python
# === SECTION: bootstrap ===
from minicode.config import (
    WORKDIR, client, MODEL,
    STATE_DIR, TASKS_DIR, TEAM_DIR, INBOX_DIR, TASK_OUTPUT_DIR, TOOL_RESULTS_DIR,
    TRANSCRIPT_DIR, CRON_DIR, WORKTREE_DIR, MCP_DIR, MEMORY_DIR, SKILLS_DIR,
    HOOKS_FILE, TRUST_MARKER,
    TOKEN_THRESHOLD, PERSIST_TRIGGER_DEFAULT, PERSIST_TRIGGER_BASH,
    PERSIST_PREVIEW_CHARS, CONTEXT_TRUNCATE_CHARS, KEEP_RECENT_RESULTS,
    PRESERVE_RESULT_TOOLS, POLL_INTERVAL, IDLE_TIMEOUT,
    TEAM_MAX_CONSECUTIVE_TURNS, VALID_MSG_TYPES,
)
```

Also remove the now-unused top-of-file imports for `os` and `load_dotenv` IF they are no longer referenced elsewhere in `main.py` (grep first; `os.environ` is still likely used by `PERMS = PermissionManager(mode=os.getenv(...))` in the `instances` section, so `import os` probably stays for now).

- [ ] **Step 3: Run verification**

Run the three commands from "Verification commands". All must succeed.

- [ ] **Step 4: Commit**

```bash
git add minicode/config.py main.py
git commit -m "refactor(minicode): extract bootstrap into minicode.config"
```

---

## Task 3: Extract `persisted_output.py`

**Source range in `main.py`:** lines 67-120 (`# === SECTION: persisted_output ===`).

**Names:** `_persist_tool_result`, `_format_size`, `_preview_slice`, `_build_persisted_marker`, `maybe_persist_output`.

**Files:**
- Create: `minicode/persisted_output.py`
- Modify: `main.py`

- [ ] **Step 1: Create `minicode/persisted_output.py`**

Header:
```python
"""Persist large tool outputs to disk; replace in transcript with a marker."""
import uuid
from pathlib import Path

from minicode.config import (
    TOOL_RESULTS_DIR, PERSIST_TRIGGER_DEFAULT, PERSIST_TRIGGER_BASH,
    PERSIST_PREVIEW_CHARS,
)
```

Body: copy `main.py:67-120` verbatim (the five functions).

- [ ] **Step 2: Replace section in `main.py`**

Replace the section body (preserving the section comment) with:
```python
# === SECTION: persisted_output =========================================
from minicode.persisted_output import (
    _persist_tool_result, _format_size, _preview_slice,
    _build_persisted_marker, maybe_persist_output,
)
```

- [ ] **Step 3: Run verification**

Run the three commands. All must succeed.

- [ ] **Step 4: Commit**

```bash
git add minicode/persisted_output.py main.py
git commit -m "refactor(minicode): extract persisted_output module"
```

---

## Task 4: Extract `security.py`

**Source ranges:** lines 121-131 (`path_safety`), 132-165 (`bash_security`), 166-278 (`permissions`).

**Names:** `safe_path`, `BashSecurityValidator`, `PermissionManager`, `PERM_MODES`, `PERMS`.

**Files:**
- Create: `minicode/security.py`
- Modify: `main.py` (replace 3 sections + remove `PERMS = PermissionManager(...)` from `instances` section)

- [ ] **Step 1: Create `minicode/security.py`**

Header:
```python
"""Filesystem path safety, bash command validation, and permission prompting."""
import os
import re
import shlex
from pathlib import Path

from minicode.config import WORKDIR, TRUST_MARKER
```

Body: paste, in order, the bodies of all three sections (`path_safety`, `bash_security`, `permissions`) from `main.py:121-278`. Keep the `# === SECTION: ... ===` separator comments inside the new file as documentation.

At the bottom, add the singleton (originally in `instances`):
```python
PERMS = PermissionManager(mode=os.getenv("MINICODE_PERM_MODE", "default"))
```

Note: `PERM_MODES` is defined inside `PermissionManager`'s class body at the top of that section — verify it's the module-level constant by checking around `main.py:174`. If `PERM_MODES` is at module level (it should be — it's referenced from `tui.py` as `main.PERM_MODES`), include it.

- [ ] **Step 2: Replace sections in `main.py`**

Replace `main.py:121-278` with:
```python
# === SECTION: path_safety ====================================================
# === SECTION: bash_security ============================================
# === SECTION: permissions ==============================================
from minicode.security import (
    safe_path,
    BashSecurityValidator,
    PermissionManager, PERM_MODES, PERMS,
)
```

Also delete the `PERMS = PermissionManager(...)` line from `main.py`'s `# === SECTION: instances ===` block.

- [ ] **Step 3: Run verification**

All three commands must succeed.

- [ ] **Step 4: Commit**

```bash
git add minicode/security.py main.py
git commit -m "refactor(minicode): extract path/bash/permission security"
```

---

## Task 5: Extract `hooks.py`

**Source range:** lines 279-364 (`# === SECTION: hooks ===`).

**Names:** `HookManager`, `HOOKS`.

**Files:**
- Create: `minicode/hooks.py`
- Modify: `main.py`

- [ ] **Step 1: Create `minicode/hooks.py`**

Header (verify against the section's actual usage):
```python
"""User-configured shell hooks (PreToolUse, PostToolUse, SessionStart, SessionEnd)."""
import json
import os
import subprocess
from pathlib import Path

from minicode.config import HOOKS_FILE, WORKDIR
```

Body: copy `main.py:279-364` verbatim.

Append singleton at bottom:
```python
HOOKS = HookManager()
```

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: hooks ====================================================
from minicode.hooks import HookManager, HOOKS
```

Delete `HOOKS = HookManager()` from `main.py`'s `instances` section.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/hooks.py main.py
git commit -m "refactor(minicode): extract hooks module"
```

---

## Task 6: Extract `memory.py`

**Source range:** lines 365-469 (`# === SECTION: memory ===`).

**Names:** `MemoryManager`, `MEMORY`.

- [ ] **Step 1: Create `minicode/memory.py`**

Header:
```python
"""On-disk persistent memory entries (.memory/MEMORY.md + per-entry files)."""
from pathlib import Path

from minicode.config import MEMORY_DIR
```

(Inspect the section to confirm imports — there may also be `re`, `os`, `json`. Add only what is used.)

Body: copy `main.py:365-469` verbatim. Append `MEMORY = MemoryManager()`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: memory ===================================================
from minicode.memory import MemoryManager, MEMORY
```

Delete `MEMORY = MemoryManager()` from `instances`.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/memory.py main.py
git commit -m "refactor(minicode): extract memory module"
```

---

## Task 7: Extract `tools.py`

**Source range:** lines 470-563 (`# === SECTION: base_tools ===`).

**Names:** `_clamp_timeout`, `run_bash`, `run_read`, `run_write`, `run_edit`, `run_grep`, `run_glob`.

- [ ] **Step 1: Create `minicode/tools.py`**

Header:
```python
"""Base tool implementations: bash, file IO, grep, glob."""
import os
import subprocess
from pathlib import Path

from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS, PERSIST_TRIGGER_BASH
from minicode.persisted_output import maybe_persist_output
from minicode.security import safe_path, BashSecurityValidator, PERMS
```

(Confirm `PERMS` reference: if `run_bash` or others call permission prompts directly, they need `PERMS`. Otherwise drop. Inspect `main.py:487-562` to see actual references.)

Body: copy `main.py:470-563` verbatim.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: base_tools ===============================================
from minicode.tools import (
    _clamp_timeout, run_bash, run_read, run_write, run_edit, run_grep, run_glob,
)
```

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/tools.py main.py
git commit -m "refactor(minicode): extract base tools module"
```

---

## Task 8: Extract `skills.py`

**Source range:** lines 564-612 (`# === SECTION: skills ===`).

**Names:** `SkillLoader`, `SKILLS`.

- [ ] **Step 1: Create `minicode/skills.py`**

Header (verify against actual section):
```python
"""Skill discovery and on-demand loading from skills/ directory."""
from pathlib import Path

from minicode.config import SKILLS_DIR
```

Body: `main.py:564-612`. Append `SKILLS = SkillLoader(SKILLS_DIR)`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: skills ===================================================
from minicode.skills import SkillLoader, SKILLS
```

Delete `SKILLS = SkillLoader(SKILLS_DIR)` from `instances`.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/skills.py main.py
git commit -m "refactor(minicode): extract skills module"
```

---

## Task 9: Extract `todos.py`

**Source range:** lines 613-657 (`# === SECTION: todos ===`).

**Names:** `TodoManager`, `TODO`.

- [ ] **Step 1: Create `minicode/todos.py`**

Header (verify):
```python
"""In-memory TodoWrite list."""
```

Body: `main.py:613-657`. Append `TODO = TodoManager()`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: todos ====================================================
from minicode.todos import TodoManager, TODO
```

Delete `TODO = TodoManager()` from `instances`.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/todos.py main.py
git commit -m "refactor(minicode): extract todos module"
```

---

## Task 10: Extract `subagent.py`

**Source range:** lines 658-731 (`# === SECTION: subagent ===`).

**Names:** `run_subagent`.

- [ ] **Step 1: Create `minicode/subagent.py`**

Header:
```python
"""Spawn a one-shot subagent with a restricted tool set."""
from minicode.config import WORKDIR, MODEL, CONTEXT_TRUNCATE_CHARS, client
from minicode.tools import run_bash, run_read, run_write, run_edit, run_grep
```

Body: `main.py:658-731`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: subagent =================================================
from minicode.subagent import run_subagent
```

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/subagent.py main.py
git commit -m "refactor(minicode): extract subagent module"
```

---

## Task 11: Extract `compression.py`

**Source range:** lines 732-799 (`# === SECTION: compression ===`).

**Names:** `estimate_tokens`, `microcompact`, `auto_compact`.

- [ ] **Step 1: Create `minicode/compression.py`**

Header (verify):
```python
"""Token estimation + history compaction."""
from minicode.config import (
    TOKEN_THRESHOLD, KEEP_RECENT_RESULTS, PRESERVE_RESULT_TOOLS,
    CONTEXT_TRUNCATE_CHARS, MODEL, client,
)
```

Body: `main.py:732-799`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: compression ==============================================
from minicode.compression import estimate_tokens, microcompact, auto_compact
```

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/compression.py main.py
git commit -m "refactor(minicode): extract compression module"
```

---

## Task 12: Extract `tasks.py`

**Source ranges:** lines 800-918 (`tasks`) + 919-975 (`background`).

**Names:** `TaskManager`, `BackgroundManager`, `TASK_MGR`, `BG`.

- [ ] **Step 1: Create `minicode/tasks.py`**

Header (verify against both sections):
```python
"""File-backed durable task tracker + background subprocess manager."""
import json
import subprocess
import threading
import time
import uuid
from pathlib import Path

from minicode.config import TASKS_DIR, WORKDIR
```

Body: paste both sections (`main.py:800-975`) in order. Keep their `# === SECTION ===` separator comments.

Append singletons:
```python
TASK_MGR = TaskManager()
BG = BackgroundManager()
```

- [ ] **Step 2: Replace sections in `main.py`**

```python
# === SECTION: tasks ====================================================
# === SECTION: background ===============================================
from minicode.tasks import TaskManager, BackgroundManager, TASK_MGR, BG
```

Delete `TASK_MGR = TaskManager()` and `BG = BackgroundManager()` from `instances`.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/tasks.py main.py
git commit -m "refactor(minicode): extract tasks + background module"
```

---

## Task 13: Extract `scheduling.py`

**Source range:** lines 976-1134 (`# === SECTION: cron ===`).

**Names:** `cron_matches`, `_cron_field`, `CronScheduler`, `CRON`, `agent_runner` (new injection point).

- [ ] **Step 1: Create `minicode/scheduling.py`**

Header (verify):
```python
"""Cron-style scheduler. agent_runner is injected by minicode.cli at startup."""
import json
import threading
import time
from datetime import datetime
from pathlib import Path

from minicode.config import CRON_DIR
```

Body: `main.py:976-1134`.

**Important:** Find the spot inside `CronScheduler.fire()` (or wherever) that calls `agent_loop(history)`. Replace that direct reference with:
```python
agent_runner(history)
```

At the top of the module (after imports, before classes), add:
```python
agent_runner = None  # set by minicode.cli at startup; takes a history list and runs one turn-cycle.
```

Append singleton at bottom:
```python
CRON = CronScheduler()
```

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: cron =====================================================
from minicode.scheduling import cron_matches, _cron_field, CronScheduler, CRON
```

Delete `CRON = CronScheduler()` from `instances`.

- [ ] **Step 3: Run verification**

Note: `agent_runner` will still be `None` at this point. That's fine — verification commands don't fire any cron jobs. But add a guard in the original `fire()` location:
```python
if agent_runner is None:
    raise RuntimeError("scheduling.agent_runner not wired; cli.repl/run_prompt must inject it")
agent_runner(history)
```

- [ ] **Step 4: Commit**

```bash
git add minicode/scheduling.py main.py
git commit -m "refactor(minicode): extract scheduling with agent_runner injection point"
```

---

## Task 14: Extract `worktree.py`

**Source range:** lines 1195-1302 (`# === SECTION: worktree ===`).

**Names:** `WorktreeManager`, `WORKTREES`.

- [ ] **Step 1: Create `minicode/worktree.py`**

Header (verify):
```python
"""Git worktree manager."""
import json
import subprocess
from pathlib import Path

from minicode.config import WORKDIR, WORKTREE_DIR
```

Body: `main.py:1195-1302`. Append `WORKTREES = WorktreeManager()`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: worktree =================================================
from minicode.worktree import WorktreeManager, WORKTREES
```

Delete `WORKTREES = WorktreeManager()` from `instances`.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/worktree.py main.py
git commit -m "refactor(minicode): extract worktree module"
```

---

## Task 15: Extract `mcp.py`

**Source range:** lines 1303-1475 (`# === SECTION: mcp ===`).

**Names:** `MCPClient`, `MCPManager`, `MCP`.

- [ ] **Step 1: Create `minicode/mcp.py`**

Header (verify against actual section — likely uses `subprocess`, `json`, `threading`, `queue`):
```python
"""MCP (Model Context Protocol) client manager."""
import json
import subprocess
import threading
from pathlib import Path
from queue import Queue

from minicode.config import MCP_DIR, WORKDIR
```

Body: `main.py:1303-1475`. Append `MCP = MCPManager()`.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: mcp ======================================================
from minicode.mcp import MCPClient, MCPManager, MCP
```

Delete `MCP = MCPManager()` from `instances`.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/mcp.py main.py
git commit -m "refactor(minicode): extract mcp module"
```

---

## Task 16: Extract `team.py`

**Source ranges:** lines 1135-1194 (`messaging`), 1476-1480 (`team_protocol`), 1481-1765 (`teammates`), 1766-1785 (`shutdown / plan_approval`).

**Names:** `MessageBus`, `BUS`, `TeammateManager`, `TEAM`, `handle_shutdown_request`, `handle_plan_review`, plus any constants from team_protocol section, plus `agent_runner` injection.

- [ ] **Step 1: Create `minicode/team.py`**

Header (verify):
```python
"""Inbox-based message bus + teammate manager + protocol handlers.

agent_runner is injected by minicode.cli at startup.
"""
import json
import threading
import time
import uuid
from pathlib import Path

from minicode.config import (
    INBOX_DIR, TEAM_DIR, TEAM_MAX_CONSECUTIVE_TURNS, VALID_MSG_TYPES,
    POLL_INTERVAL, IDLE_TIMEOUT,
)
from minicode.tasks import TASK_MGR
from minicode.security import PERMS
from minicode.hooks import HOOKS
from minicode.mcp import MCP
```

Body: paste, in order, the bodies of `messaging`, `team_protocol`, `teammates`, `shutdown / plan_approval` from `main.py:1135-1785`. Keep their separator comments.

After the imports, add:
```python
agent_runner = None  # set by minicode.cli at startup.
```

In `TeammateManager.spawn()` (or wherever a teammate session calls `agent_loop`), replace `agent_loop(history)` with:
```python
if agent_runner is None:
    raise RuntimeError("team.agent_runner not wired; cli.repl/run_prompt must inject it")
agent_runner(history)
```

Append singletons at bottom:
```python
BUS = MessageBus()
TEAM = TeammateManager(BUS, TASK_MGR, PERMS, HOOKS, MCP)
```

- [ ] **Step 2: Replace sections in `main.py`**

```python
# === SECTION: messaging ================================================
# === SECTION: team_protocol ============================================
# === SECTION: teammates ============================================
# === SECTION: shutdown / plan_approval =================================
from minicode.team import (
    MessageBus, BUS,
    TeammateManager, TEAM,
    handle_shutdown_request, handle_plan_review,
)
```

Delete `BUS = MessageBus()` and `TEAM = TeammateManager(...)` from `instances`. At this point the `instances` section should be empty (or contain only the section comment) — leave the comment as a marker, the section comment will be removed in Task 21.

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/team.py main.py
git commit -m "refactor(minicode): extract team (messaging, teammates, protocol)"
```

---

## Task 17: Extract `prompts.py`

**Source range:** lines 1801-1822 (`# === SECTION: system_prompt ===`) + the `HELP_TEXT = """..."""` block at line 2365 (read it to find its closing line).

**Names:** `build_system_prompt`, `HELP_TEXT`.

- [ ] **Step 1: Identify HELP_TEXT range**

```bash
grep -n '^HELP_TEXT\|^"""' main.py | head -20
```

Note the line numbers for `HELP_TEXT = """\\` and the closing `"""`.

- [ ] **Step 2: Create `minicode/prompts.py`**

Header:
```python
"""System prompt builder + REPL HELP_TEXT."""
from minicode.config import WORKDIR
from minicode.security import PERMS
from minicode.skills import SKILLS
from minicode.memory import MEMORY
```

Body: paste `build_system_prompt` from `main.py:1801-1822`, then paste the `HELP_TEXT = """..."""` string from the repl section.

- [ ] **Step 3: Replace section in `main.py`**

Replace lines 1801-1822 with:
```python
# === SECTION: system_prompt ============================================
from minicode.prompts import build_system_prompt, HELP_TEXT
```

Delete the original `HELP_TEXT = """..."""` block from the repl section (it's now imported via the line above).

- [ ] **Step 4: Run verification**

- [ ] **Step 5: Commit**

```bash
git add minicode/prompts.py main.py
git commit -m "refactor(minicode): extract prompts (system_prompt + HELP_TEXT)"
```

---

## Task 18: Extract `dispatch.py`

**Source ranges:** lines 1823-2068 (`tool_dispatch`), 2069-2120 (`prompt_caching`), 2121-2139 (`parallel_dispatch`), AND the helper `execute_one_tool` at the start of `agent_loop` section (line 2141).

**Names:** `TOOL_HANDLERS`, `TOOLS_BASE`, `all_tools`, `append_user_text`, `system_blocks_cached`, `tools_cached`, `CACHE_ENABLED`, `PARALLEL_SAFE_TOOLS`, `PARALLEL_MAX_WORKERS`, `_PERMS_ASK_LOCK`, `execute_one_tool`.

- [ ] **Step 1: Locate `execute_one_tool` body**

```bash
grep -n "^def execute_one_tool\|^def agent_loop\|^# === SECTION" main.py | head -30
```

Note the line range from `def execute_one_tool` to the line before `def agent_loop`.

- [ ] **Step 2: Create `minicode/dispatch.py`**

Header:
```python
"""Tool registry, parallel safety, prompt caching, single-tool execution."""
import json
import os
import threading

from minicode.config import client
from minicode.security import PermissionManager, PERMS
from minicode.hooks import HookManager, HOOKS
from minicode.tools import (
    run_bash, run_read, run_write, run_edit, run_grep, run_glob,
)
from minicode.subagent import run_subagent
from minicode.todos import TODO
from minicode.skills import SKILLS
from minicode.tasks import TASK_MGR, BG
from minicode.memory import MEMORY
from minicode.scheduling import CRON
from minicode.worktree import WORKTREES
from minicode.mcp import MCP
from minicode.team import BUS, TEAM, handle_shutdown_request, handle_plan_review
from minicode.prompts import build_system_prompt
```

Body: paste in order — `tool_dispatch`, `prompt_caching`, `parallel_dispatch`, and `execute_one_tool` (only that function from the agent_loop section). Keep `# === SECTION ===` separator comments inside the file.

- [ ] **Step 3: Replace sections in `main.py`**

```python
# === SECTION: tool_dispatch ============================================
# === SECTION: prompt_caching =================================================
# === SECTION: parallel_dispatch ==============================================
from minicode.dispatch import (
    TOOL_HANDLERS, TOOLS_BASE, all_tools, append_user_text,
    system_blocks_cached, tools_cached, CACHE_ENABLED,
    PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS, _PERMS_ASK_LOCK,
    execute_one_tool,
)
```

Inside `# === SECTION: agent_loop ===`, delete the `execute_one_tool` function (it now lives in dispatch.py and is imported via the block above).

- [ ] **Step 4: Run verification**

- [ ] **Step 5: Commit**

```bash
git add minicode/dispatch.py main.py
git commit -m "refactor(minicode): extract dispatch (handlers, caching, parallel)"
```

---

## Task 19: Extract `loop.py`

**Source range:** lines 2200-2363 (the `agent_loop` function itself, not including `execute_one_tool` which moved to dispatch in Task 18).

**Names:** `agent_loop`.

- [ ] **Step 1: Create `minicode/loop.py`**

Header (verify against actual function body for what it uses):
```python
"""Main agent message loop."""
import time

from minicode.config import client, MODEL, TOKEN_THRESHOLD
from minicode.security import PERMS
from minicode.hooks import HOOKS
from minicode.compression import auto_compact, microcompact, estimate_tokens
from minicode.dispatch import (
    all_tools, system_blocks_cached, tools_cached, append_user_text,
    execute_one_tool, PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS,
)
```

Body: paste the `agent_loop` function from `main.py:2200-2363`.

`agent_loop` references `_BATCH` (e.g. `_BATCH["turns"] += 1`). The cleanest mechanical move is to **own `_BATCH` from `loop.py`** so `agent_loop` keeps reading a module-global, and have `cli.run_prompt` (Task 20) reassign it via `loop._BATCH = {...}`.

At the top of `loop.py`, just below imports, add:
```python
_BATCH = None  # Set by cli.run_prompt(); agent_loop checks this to record usage.
```

Inside `agent_loop`, leave `_BATCH` references unchanged (they bind to the module global of `loop.py`). Verify with:
```bash
grep -n "_BATCH" main.py
```
The references inside `agent_loop` (lines 2200-2363) stay as bare `_BATCH`. The reference inside `run_prompt` (which becomes `cli.run_prompt` in Task 20) is rewritten there.

- [ ] **Step 2: Replace section in `main.py`**

```python
# === SECTION: agent_loop =========================================
from minicode.loop import agent_loop
```

- [ ] **Step 3: Run verification**

- [ ] **Step 4: Commit**

```bash
git add minicode/loop.py main.py
git commit -m "refactor(minicode): extract agent_loop module"
```

---

## Task 20: Extract `cli.py`

**Source ranges:** lines 2364-2471 (`repl`), 2472-2551 (`batch entry`).

**Names:** `repl`, `run_prompt`, `_arg`. (`_BATCH` is owned by `loop.py` per Task 19; `cli.run_prompt` reassigns `loop._BATCH`.)

This task also wires the `agent_runner` injection points.

- [ ] **Step 1: Create `minicode/cli.py`**

Header:
```python
"""Interactive REPL and batch entrypoint."""
import json
import sys
import time
from pathlib import Path

from minicode.config import (
    WORKDIR, MODEL, STATE_DIR, TRUST_MARKER,
)
from minicode.security import PERMS, PERM_MODES
from minicode.hooks import HOOKS
from minicode.memory import MEMORY
from minicode.tasks import TASK_MGR
from minicode.skills import SKILLS
from minicode.scheduling import CRON
from minicode.worktree import WORKTREES
from minicode.mcp import MCP
from minicode.team import BUS, TEAM
from minicode.compression import auto_compact
from minicode.prompts import HELP_TEXT
from minicode.loop import agent_loop

# Wire the agent_runner injection points referenced by scheduling and team.
import minicode.scheduling as _sched
import minicode.team as _team
_sched.agent_runner = agent_loop
_team.agent_runner = agent_loop
```

Body: paste `repl()`, `_arg()`, `run_prompt()` from `main.py:2364-2551`. **Do NOT paste the `_BATCH = None` line** (it now lives in `loop.py`). Inside `run_prompt`, rewrite the original:
```python
global _BATCH
_BATCH = { ... }
```
to:
```python
loop._BATCH = { ... }
```
And replace any subsequent `_BATCH[...]` reads/writes inside `run_prompt` with `loop._BATCH[...]`. Add `from minicode import loop` to the imports if not already present.

- [ ] **Step 2: Replace sections in `main.py`**

```python
# === SECTION: repl ===========================================================
# === SECTION: batch entry ====================================================
from minicode.cli import repl, run_prompt, _arg
```

- [ ] **Step 3: Run verification**

This is the first task where the full integration is exercised. Run:

```bash
uv run python -c "from main import repl, run_prompt; print('ok')"
uv run python -c "import tui; print('ok')"
uv run pytest tests/ -q
echo "/help" | uv run python main.py    # should print HELP_TEXT
```

The `/help` smoke confirms `repl` actually starts and the help text round-trips.

- [ ] **Step 4: Commit**

```bash
git add minicode/cli.py main.py
git commit -m "refactor(minicode): extract cli + wire agent_runner injection"
```

---

## Task 21: Shrink `main.py` to thin entrypoint

At this point `main.py` is a long stack of `from minicode.X import ...` lines plus the `if __name__ == "__main__"` block.

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Replace `main.py` contents**

```python
#!/usr/bin/env python3
# MiniCode entrypoint - see minicode/ package for implementation.
import sys

from minicode.cli import repl, run_prompt
from minicode.prompts import HELP_TEXT

# Re-exports for legacy `import main; main.X` usage (TUI rewrite is Task 22).
from minicode.config import *  # noqa: F401,F403
from minicode.security import PERMS, PERM_MODES, PermissionManager  # noqa: F401
from minicode.hooks import HOOKS, HookManager  # noqa: F401
from minicode.memory import MEMORY, MemoryManager  # noqa: F401
from minicode.skills import SKILLS, SkillLoader  # noqa: F401
from minicode.todos import TODO, TodoManager  # noqa: F401
from minicode.tasks import TASK_MGR, BG, TaskManager, BackgroundManager  # noqa: F401
from minicode.scheduling import CRON, CronScheduler  # noqa: F401
from minicode.worktree import WORKTREES, WorktreeManager  # noqa: F401
from minicode.mcp import MCP, MCPManager  # noqa: F401
from minicode.team import BUS, TEAM, MessageBus, TeammateManager  # noqa: F401
from minicode.compression import auto_compact  # noqa: F401
from minicode.loop import agent_loop  # noqa: F401
import json  # noqa: F401  -- tui.py uses main.json

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

- [ ] **Step 2: Run verification**

```bash
uv run python -c "from main import repl, run_prompt; print('ok')"
uv run python -c "import tui; print('ok')"
uv run pytest tests/ -q
echo "/help" | uv run python main.py
wc -l main.py        # expect well under 60 lines
```

- [ ] **Step 3: Commit**

```bash
git add main.py
git commit -m "refactor(main): shrink to thin entrypoint with legacy re-exports"
```

---

## Task 22: Rewrite `tui.py` to import from `minicode.*`

**Files:**
- Modify: `tui.py`

- [ ] **Step 1: Inventory `main.X` references**

```bash
grep -nE '\bmain\.' tui.py
```

Save the list. The expected names (per spec §5.2): `TASK_MGR`, `TEAM`, `BUS`, `MEMORY`, `CRON`, `MCP`, `HOOKS`, `SKILLS`, `WORKTREES`, `PERMS`, `PERM_MODES`, `MODEL`, `WORKDIR`, `STATE_DIR`, `TRUST_MARKER`, `agent_loop`, `auto_compact`, `json`.

- [ ] **Step 2: Replace `import main` block**

Find the line `import main  # noqa: E402  -- must come after chdir so WORKDIR resolves correctly` (around line 58). Replace it with:

```python
# Imports must come after chdir() so WORKDIR resolves correctly.
import json  # noqa: E402

from minicode.config import MODEL, WORKDIR, STATE_DIR, TRUST_MARKER  # noqa: E402
from minicode.security import PERMS, PERM_MODES  # noqa: E402
from minicode.hooks import HOOKS  # noqa: E402
from minicode.memory import MEMORY  # noqa: E402
from minicode.skills import SKILLS  # noqa: E402
from minicode.tasks import TASK_MGR  # noqa: E402
from minicode.scheduling import CRON  # noqa: E402
from minicode.worktree import WORKTREES  # noqa: E402
from minicode.mcp import MCP  # noqa: E402
from minicode.team import BUS, TEAM  # noqa: E402
from minicode.compression import auto_compact  # noqa: E402
from minicode.loop import agent_loop  # noqa: E402
```

- [ ] **Step 3: Replace each `main.X` occurrence**

For each match from Step 1, replace `main.X` with bare `X`. Use sed for the safe rewrites:

```bash
sed -i.bak \
  -e 's/\bmain\.TASK_MGR\b/TASK_MGR/g' \
  -e 's/\bmain\.TEAM\b/TEAM/g' \
  -e 's/\bmain\.BUS\b/BUS/g' \
  -e 's/\bmain\.MEMORY\b/MEMORY/g' \
  -e 's/\bmain\.CRON\b/CRON/g' \
  -e 's/\bmain\.MCP\b/MCP/g' \
  -e 's/\bmain\.HOOKS\b/HOOKS/g' \
  -e 's/\bmain\.SKILLS\b/SKILLS/g' \
  -e 's/\bmain\.WORKTREES\b/WORKTREES/g' \
  -e 's/\bmain\.PERMS\b/PERMS/g' \
  -e 's/\bmain\.PERM_MODES\b/PERM_MODES/g' \
  -e 's/\bmain\.MODEL\b/MODEL/g' \
  -e 's/\bmain\.WORKDIR\b/WORKDIR/g' \
  -e 's/\bmain\.STATE_DIR\b/STATE_DIR/g' \
  -e 's/\bmain\.TRUST_MARKER\b/TRUST_MARKER/g' \
  -e 's/\bmain\.agent_loop\b/agent_loop/g' \
  -e 's/\bmain\.auto_compact\b/auto_compact/g' \
  -e 's/\bmain\.json\b/json/g' \
  tui.py
rm tui.py.bak
```

- [ ] **Step 4: Verify zero `main.X` references remain**

```bash
grep -nE '\bmain\.' tui.py
```

Expected: empty output (or only matches inside string literals/comments — eyeball them).

- [ ] **Step 5: Run verification**

```bash
uv run python -c "import tui; print('ok')"
uv run python tui.py . </dev/null &
sleep 2 && kill %1 || true
```

The TUI should reach the main screen before being killed. If it crashes on import, restore from git and inspect.

- [ ] **Step 6: Commit**

```bash
git add tui.py
git commit -m "refactor(tui): import from minicode.* directly"
```

---

## Task 23: Drop legacy re-exports from `main.py`

Now that `tui.py` no longer imports `main`, the wildcard re-exports in `main.py` can go.

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Confirm no other consumers reference `main.X`**

```bash
grep -RnE 'import main\b|from main import|main\.[A-Z_a-z]+' \
  --include='*.py' --exclude-dir=__pycache__ --exclude-dir=.minicode . \
  | grep -v '^./main.py:'
```

Expected: empty (`tui.py` was the only consumer; bench is independent).

- [ ] **Step 2: Replace `main.py` with the minimal version**

```python
#!/usr/bin/env python3
# MiniCode entrypoint - see minicode/ package for implementation.
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

- [ ] **Step 3: Run final verification**

```bash
uv run python -c "from main import repl, run_prompt; print('ok')"
uv run python -c "import tui; print('ok')"
uv run pytest tests/ -q
echo "/help" | uv run python main.py
echo "/tasks" | uv run python main.py
uv run python tui.py . </dev/null &
sleep 2 && kill %1 || true
wc -l main.py    # expect ~20 lines
find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
```

All commands must succeed.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "refactor(main): drop legacy re-exports; thin entrypoint only"
```

---

## Task 24: Final smoke + push

- [ ] **Step 1: Optional real-API smoke**

If you have `ANTHROPIC_API_KEY` set, do one end-to-end prompt:
```bash
uv run python main.py --prompt "Say 'hello world' and exit."
```

Expected: agent responds, no Python errors. (Skip if you'd rather not spend tokens.)

- [ ] **Step 2: Repo health check**

```bash
git status                # working tree clean
git log --oneline -25     # check the refactor commit chain
uv run pytest tests/ -q   # final pass
wc -l main.py minicode/*.py | sort -n  # sanity: no module > ~600 lines (team.py will be biggest)
```

- [ ] **Step 3: (Optional) Open PR**

If working on a feature branch, push and open a PR. Otherwise, this is the end of the plan.

---

## Self-Review Checklist (run before handing off)

- [ ] Every section in `main.py` (per `grep -n "^# === SECTION" main.py` at start of work) maps to exactly one task.
- [ ] Every public name listed in spec §3 has a known new home (config / security / hooks / ... / cli).
- [ ] Two cycle points (`scheduling.fire`, `team.spawn`) are wired via `agent_runner` in cli.py (Task 20).
- [ ] `tui.py`'s 18 imported names from spec §5.2 are all covered by Task 22's sed block.
- [ ] No "TBD", "TODO", or "implement later" remains in this plan.
- [ ] Every task ends with `git commit` and the three verification commands have been run.
