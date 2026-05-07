"""Bootstrap: env loading, paths, constants, shared Anthropic client."""
import os
from pathlib import Path

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv(override=True)
if os.getenv("ANTHROPIC_BASE_URL"):
    # Some proxies require dropping the auth-token env when base_url is set.
    os.environ.pop("ANTHROPIC_AUTH_TOKEN", None)

WORKDIR = Path.cwd()
client = Anthropic(base_url=os.getenv("ANTHROPIC_BASE_URL"))
MODEL = os.environ.get("MODEL_ID", "claude-opus-4-6")

# Filesystem layout. Every directory is created lazily.
STATE_DIR = WORKDIR / ".minicode"
TASKS_DIR = STATE_DIR / "tasks"
TEAM_DIR = STATE_DIR / "team"
INBOX_DIR = TEAM_DIR / "inbox"
TASK_OUTPUT_DIR = STATE_DIR / "task_outputs"
TOOL_RESULTS_DIR = TASK_OUTPUT_DIR / "tool-results"
TRANSCRIPT_DIR = STATE_DIR / "transcripts"
CRON_DIR = STATE_DIR / "cron"
WORKTREE_DIR = STATE_DIR / "worktrees"
MCP_DIR = STATE_DIR / "mcp"
MEMORY_DIR = WORKDIR / ".memory"
SKILLS_DIR = WORKDIR / "skills"
HOOKS_FILE = WORKDIR / ".hooks.json"
TRUST_MARKER = STATE_DIR / ".trusted"

TOKEN_THRESHOLD = 100000
PERSIST_TRIGGER_DEFAULT = 50000
PERSIST_TRIGGER_BASH = 30000
PERSIST_PREVIEW_CHARS = 2000
CONTEXT_TRUNCATE_CHARS = 50000
KEEP_RECENT_RESULTS = 3
PRESERVE_RESULT_TOOLS = {"read_file"}
POLL_INTERVAL = 5
IDLE_TIMEOUT = 60
TEAM_MAX_CONSECUTIVE_TURNS = 50

VALID_MSG_TYPES = {
    "message", "broadcast",
    "shutdown_request", "shutdown_response",
    "plan_approval_request", "plan_approval_response",
}
