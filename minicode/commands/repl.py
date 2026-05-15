"""Interactive REPL entrypoint."""
import json

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


def repl():
    print(f"MiniCode @ {WORKDIR} (model: {MODEL}, perm-mode: {PERMS.mode})")
    print("Type /help for commands. Ctrl-D to exit.")

    # SessionStart hook + initial loads.
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY.load_all()
    CRON.start()
    MCP.start()
    HOOKS.run("SessionStart")

    history = []
    try:
        while True:
            try:
                query = input("\033[36mminicode >> \033[0m")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            q = query.strip()
            if not q:
                continue
            if q.lower() in ("q", "/quit", "/exit", "exit"):
                break
            if q in ("/help", "?"):
                print(HELP_TEXT)
                continue
            if q == "/tasks":
                print(TASK_MGR.list_all())
                continue
            if q == "/team":
                print(TEAM.list_all())
                continue
            if q == "/inbox":
                print(json.dumps(BUS.read_inbox("lead"), indent=2))
                continue
            if q == "/memory":
                print(MEMORY.list_all())
                continue
            if q == "/skills":
                SKILLS.reload()
                print(SKILLS.list_all())
                continue
            if q == "/cron":
                print(CRON.list_tasks())
                continue
            if q == "/worktree":
                print(WORKTREES.list_all())
                continue
            if q == "/mcp":
                print(MCP.list_tools())
                continue
            if q == "/trust":
                TRUST_MARKER.parent.mkdir(parents=True, exist_ok=True)
                TRUST_MARKER.write_text("trusted")
                print(f"Created trust marker at {TRUST_MARKER.relative_to(WORKDIR)}")
                continue
            if q.startswith("/mode"):
                parts = q.split(maxsplit=1)
                if len(parts) == 1:
                    print(f"Current perm mode: {PERMS.mode} (modes: {PERM_MODES})")
                else:
                    try:
                        PERMS.set_mode(parts[1].strip())
                        print(f"Perm mode -> {PERMS.mode}")
                    except ValueError as e:
                        print(f"Error: {e}")
                continue
            if q.startswith("/compact"):
                parts = q.split(maxsplit=1)
                focus = parts[1] if len(parts) > 1 else None
                if history:
                    print(f"[manual compact{f' focus={focus}' if focus else ''}]")
                    history[:] = auto_compact(history, focus=focus)
                continue

            history.append({"role": "user", "content": q})
            try:
                agent_loop(history)
            except KeyboardInterrupt:
                print("\n[interrupted; entering REPL]")
            print()
    finally:
        HOOKS.run("SessionEnd")
        CRON.stop()
        MCP.stop()
