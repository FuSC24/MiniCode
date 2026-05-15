"""System prompt builder + REPL HELP_TEXT."""

from minicode.config import WORKDIR
from minicode.services.security import PERMS
from minicode.skills import SKILLS
from minicode.memory import MEMORY


def build_system_prompt() -> str:
    parts = [
        f"You are MiniCode, a coding agent operating at {WORKDIR}.",
        "Use tools to solve tasks. Prefer surgical changes that trace back to the user's request.",
        "Use TodoWrite for short multi-step plans (<= 20 items, one in_progress at a time).",
        "Use task_create / task_update / task_list for durable file-backed work.",
        "Use task (subagent) for isolated exploration that should not pollute the main context.",
        "Use load_skill before specialized work; available skills are listed below.",
        "Before destructive actions, prefer compress and explain your plan.",
        f"Permission mode: {PERMS.mode}.",
        "",
        "## Skills",
        SKILLS.descriptions(),
    ]
    mem_block = MEMORY.render_for_prompt()
    if mem_block:
        parts.append("")
        parts.append(mem_block)
    return "\n".join(parts)


HELP_TEXT = """\
MiniCode REPL commands:
  /help              show this help
  /quit | /exit | q  exit
  /tasks             list tasks
  /team              list teammates
  /inbox             show & drain lead inbox
  /memory            list memories
  /skills            list skills (also reloads)
  /cron              list scheduled tasks
  /worktree          list worktrees
  /mcp               list MCP tools
  /mode <mode>       set permission mode (default|plan|auto|yolo)
  /compact [focus]   manually compact context
  /trust             create the trust marker (enables hooks)
Anything else is sent to the agent.
"""
