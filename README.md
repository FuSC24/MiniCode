# MiniCode

A runnable, mechanism-faithful coding agent for local use.

The `minicode/` package implements the agent loop, tool dispatch, subagents, skills, context compaction, permissions, hooks, cross-session memory, task board, background jobs, cron scheduler, multi-agent collaboration, worktrees, and MCP. `main.py` is a thin entrypoint; `minicode/ui/` is a Textual TUI on top of the same runtime.

```
minicode/
├── config.py · prompts.py
├── agent/      loop · dispatch · compression
├── tools/      bash · read · write · edit · grep · glob
│               subagent · todos · tasks · memory · scheduling
│               worktree · mcp · team · skills · persisted_output
├── services/   hooks · security
├── commands/   repl · batch
└── ui/         app · stream_capture
                screens/permission · components/side_panel
```

## Install

You need [uv](https://docs.astral.sh/uv/) and an API key for any Anthropic-compatible endpoint (official or proxy).

```bash
git clone https://github.com/FuSC24/MiniCode.git && cd MiniCode
uv sync
cp .env.example .env   # fill in ANTHROPIC_API_KEY and MODEL_ID
```

Optional — symlink the launcher onto your `PATH`:

```bash
ln -s "$(pwd)/bin/minicode" ~/.local/bin/minicode
```

## Usage

![MiniCode TUI](docs/tui.png)

```bash
uv run python -c "from minicode.ui import run_app; run_app()"  # TUI (recommended)
uv run python main.py       # plain-text REPL

# global launcher (after the symlink above)
minicode                    # start the TUI in the current directory
minicode ~/some-project     # start it pointed at another directory
minicode --repl             # fall back to the plain REPL
minicode --mode yolo        # boot directly into yolo permission mode
```

Type `/help` once the REPL/TUI is up to see every command. Common ones:

| Command | What it does |
|---|---|
| `/mode <name>` | Permission mode: `default` / `plan` / `auto` / `yolo` |
| `/tasks` `/team` `/memory` `/skills` | Show the corresponding state |
| `/trust` | Mark workspace as trusted (required for hooks to fire) |
| `/compact <focus>` | Manually compact the conversation context |
| `/quit` | Exit |

Anything that doesn't start with `/` is sent straight to the model.

## Configuration

`.env` fields:

```bash
ANTHROPIC_API_KEY=sk-...           # required
MODEL_ID=claude-opus-4-6           # required, set to the model you actually use
ANTHROPIC_BASE_URL=https://...     # optional, Anthropic-compatible proxy
MINICODE_PERM_MODE=default         # optional, initial permission mode
MINICODE_CACHE=0                   # optional, disable prompt caching
```

## Extending

- **Skill** — drop a `skills/<name>/SKILL.md` with frontmatter; the model will call `load_skill` on demand.
- **Hook** — put a `.hooks.json` in the workspace; runs only after `/trust`.
- **MCP** — register stdio MCP servers in `.minicode/mcp/config.json`.
- **Memory** — the model calls `save_memory` to persist cross-session info under `.memory/`; loaded automatically on next launch.

## License

MIT
