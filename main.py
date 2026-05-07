#!/usr/bin/env python3
# MiniCode - a complete, runnable coding-agent harness in one file.


import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# === SECTION: bootstrap ===
from minicode.config import (
    WORKDIR, client, MODEL,
    STATE_DIR, TRANSCRIPT_DIR,
    TRUST_MARKER,
    PERSIST_TRIGGER_DEFAULT,
    PERSIST_PREVIEW_CHARS,
)


# === SECTION: persisted_output =========================================
from minicode.persisted_output import (
    _persist_tool_result, _format_size, _preview_slice,
    _build_persisted_marker, maybe_persist_output,
)


# === SECTION: path_safety ====================================================
# === SECTION: bash_security ============================================
# === SECTION: permissions ==============================================
from minicode.security import (
    safe_path,
    BashSecurityValidator,
    PermissionManager, PERM_MODES, PERMS,
)


# === SECTION: hooks ====================================================
from minicode.hooks import HookManager, HOOKS


# === SECTION: memory ===================================================
from minicode.memory import MemoryManager, MEMORY


# === SECTION: base_tools ===============================================
from minicode.tools import (
    run_bash, run_read, run_write, run_edit, run_grep, run_glob,
)


# === SECTION: skills ===================================================
from minicode.skills import SkillLoader, SKILLS


# === SECTION: todos ====================================================
from minicode.todos import TodoManager, TODO


# === SECTION: subagent =================================================
from minicode.subagent import run_subagent

# === SECTION: compression ==============================================
from minicode.compression import auto_compact


# === SECTION: tasks ====================================================
# === SECTION: background ===============================================
from minicode.tasks import TaskManager, BackgroundManager, TASK_MGR, BG


# === SECTION: cron =====================================================
from minicode.scheduling import cron_matches, _cron_field, CronScheduler, CRON


# === SECTION: messaging ================================================
# === SECTION: team_protocol ============================================
# === SECTION: teammates ============================================
# === SECTION: shutdown / plan_approval =================================
from minicode.team import (
    MessageBus, BUS,
    TeammateManager, TEAM,
    handle_shutdown_request, handle_plan_review,
)
# === SECTION: worktree =================================================
from minicode.worktree import WorktreeManager, WORKTREES


# === SECTION: mcp ======================================================
from minicode.mcp import MCPClient, MCPManager, MCP


# === SECTION: instances ======================================================


# === SECTION: system_prompt ============================================
from minicode.prompts import HELP_TEXT


# === SECTION: tool_dispatch ============================================
# === SECTION: prompt_caching =================================================
# === SECTION: parallel_dispatch ==============================================


# === SECTION: agent_loop =========================================
from minicode.loop import agent_loop


# === SECTION: repl ===========================================================
# === SECTION: batch entry ====================================================
from minicode.cli import repl, run_prompt, _arg


# === SECTION: main ===========================================================
if __name__ == "__main__":
    if "--help" in sys.argv:
        print(HELP_TEXT)
        sys.exit(0)
    if "--version" in sys.argv:
        print("minicode 0.1")
        sys.exit(0)
    if "--prompt" in sys.argv or any(a.startswith("--prompt=") for a in sys.argv) \
       or "--prompt-file" in sys.argv or any(a.startswith("--prompt-file=") for a in sys.argv):
        run_prompt()
    repl()
