#!/usr/bin/env python3
"""MiniCode entrypoint - see minicode/ package for implementation."""
import sys

from minicode.cli import repl, run_prompt
from minicode.prompts import HELP_TEXT

# Legacy re-exports for `import main; main.X` callers (TUI rewrite is Task 22).
from minicode.config import (  # noqa: F401
    WORKDIR, MODEL, STATE_DIR, TRUST_MARKER, client,
)
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
