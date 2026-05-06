# SWE-bench-Verified 70-case Eval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure minicode's resolved rate on a fixed random 70-sample of SWE-bench-Verified using sb-cli for cloud grading, while recording per-case token usage.

**Architecture:** Add a non-interactive `--prompt-file` entry to `main.py` that runs `agent_loop` once and writes per-run token usage to JSON. A standalone harness `bench/swebench_run.py` samples 70 instances (seed=42), prepares an isolated git worktree per case at `base_commit`, runs minicode as a subprocess, extracts the diff into `predictions.jsonl`, and aggregates token totals.

**Tech Stack:** Python 3.10+, `anthropic` SDK (already in deps), `datasets` (new dep, HuggingFace), `git worktree`, `concurrent.futures`, `sb-cli` (post-run, used out-of-band).

**Spec:** `docs/superpowers/specs/2026-05-06-swebench-verified-eval-design.md`

---

## File Structure

**Modified:**
- `main.py` — add `--prompt-file` / `--max-turns` / `--usage-out` CLI flags, a `run_prompt(...)` entry function, and a module-level `_BATCH` tracker that `agent_loop` updates.
- `pyproject.toml` — add `datasets` to deps.

**Created:**
- `bench/__init__.py` — empty package marker.
- `bench/swebench_run.py` — harness CLI: `prepare`, `run`, `report` subcommands.
- `bench/sample_70.txt` — generated artifact, 70 instance IDs (one per line). Committed for reproducibility.
- `bench/.gitignore` — ignore `repo_cache/`, `workspaces/`, `runs/`.
- `tests/bench/test_extract_patch.py` — unit tests for diff extraction.
- `tests/bench/test_prepare_workspace.py` — unit tests for worktree setup.

**Out of scope this plan:**
- TUI changes
- sb-cli automation (we run it manually after)
- Resolved-rate analysis scripts

---

## Task 1: Add `--prompt-file` / `--max-turns` / `--usage-out` flags to `main.py`

**Files:**
- Modify: `main.py` — bottom `if __name__ == "__main__":` block (~line 2456-2463) and add a new `run_prompt()` function before it.

The existing `__main__` block uses ad-hoc `if "--help" in sys.argv` checks. Keep that style — don't pull in argparse — to minimize churn. Read flags by simple `sys.argv` scanning.

- [ ] **Step 1: Add `run_prompt()` function above `if __name__ == "__main__":`**

In `main.py`, just above line `# === SECTION: main ===========================================================` (around line 2455), insert:

```python
# === SECTION: batch entry ====================================================
_BATCH = None  # Set by run_prompt(); agent_loop checks this to record usage.


def _arg(name: str, default=None):
    """Tiny CLI helper: read --name VALUE or --name=VALUE from sys.argv."""
    for i, a in enumerate(sys.argv):
        if a == name and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def run_prompt():
    """Non-interactive entry: read a prompt, run agent_loop once, exit.

    Flags (read from sys.argv):
      --prompt <text> | --prompt-file <path>   prompt source (one required)
      --max-turns <N>                          hard turn cap (default: no cap)
      --usage-out <path>                       write per-run token usage JSON
    """
    global _BATCH
    prompt = _arg("--prompt")
    prompt_file = _arg("--prompt-file")
    if prompt is None and prompt_file is None:
        print("error: --prompt or --prompt-file required", file=sys.stderr)
        sys.exit(2)
    if prompt_file is not None:
        prompt = Path(prompt_file).read_text()

    max_turns = _arg("--max-turns")
    max_turns = int(max_turns) if max_turns else None
    usage_out = _arg("--usage-out")

    _BATCH = {
        "turns": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "max_turns": max_turns,
        "stop_reason": None,
        "started_at": time.time(),
    }

    print(f"MiniCode batch @ {WORKDIR} (model: {MODEL}, perm-mode: {PERMS.mode})")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY.load_all()
    CRON.start()
    MCP.start()
    HOOKS.run("SessionStart")

    history = [{"role": "user", "content": prompt}]
    exit_code = 0
    try:
        agent_loop(history)
        if _BATCH["stop_reason"] is None:
            _BATCH["stop_reason"] = "end_turn"
    except KeyboardInterrupt:
        _BATCH["stop_reason"] = "interrupted"
        exit_code = 130
    except Exception as e:
        print(f"[batch] agent_loop raised: {e}", file=sys.stderr)
        _BATCH["stop_reason"] = "exception"
        exit_code = 1
    finally:
        _BATCH["wall_clock_seconds"] = round(time.time() - _BATCH["started_at"], 2)
        if usage_out:
            Path(usage_out).parent.mkdir(parents=True, exist_ok=True)
            Path(usage_out).write_text(json.dumps({
                k: v for k, v in _BATCH.items() if k != "started_at"
            }, indent=2))
        HOOKS.run("SessionEnd")
        CRON.stop()
        MCP.stop()
    sys.exit(exit_code)
```

- [ ] **Step 2: Hook `--prompt`/`--prompt-file` detection into `__main__`**

Replace the `__main__` block (around line 2455-2463) with:

```python
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
```

- [ ] **Step 3: Smoke-test the flag wiring (no model call yet)**

Run:

```bash
cd /Users/fscnb/Project/MiniCode
uv run python main.py --prompt-file /tmp/nonexistent --max-turns 1 --usage-out /tmp/u.json 2>&1 | head -5
```

Expected: a `FileNotFoundError` traceback referencing `/tmp/nonexistent` (proves we entered `run_prompt`, not `repl`). If it dropped into the `minicode >>` prompt, the dispatch in step 2 is wrong — fix and re-run.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "feat(main): add non-interactive --prompt-file entry"
```

---

## Task 2: Wire usage accumulation and `--max-turns` enforcement into `agent_loop`

**Files:**
- Modify: `main.py` — `agent_loop` (around line 2200-2345). Two small additions, no signature change.

- [ ] **Step 1: After `response = stream.get_final_message()` succeeds, accumulate usage and bump turn count**

Find the line at ~2253: `consecutive_errors = 0`. Right after it, before `except Exception as e:`, insert:

```python
            if _BATCH is not None:
                u = getattr(response, "usage", None)
                if u is not None:
                    _BATCH["input_tokens"] += getattr(u, "input_tokens", 0) or 0
                    _BATCH["output_tokens"] += getattr(u, "output_tokens", 0) or 0
                    _BATCH["cache_creation_input_tokens"] += (
                        getattr(u, "cache_creation_input_tokens", 0) or 0)
                    _BATCH["cache_read_input_tokens"] += (
                        getattr(u, "cache_read_input_tokens", 0) or 0)
                _BATCH["turns"] += 1
```

- [ ] **Step 2: Enforce `--max-turns` after appending the assistant message**

Find the line at ~2268: `messages.append({"role": "assistant", "content": response.content})`. Right after the `if response.stop_reason != "tool_use": return` block at ~2273-2274, insert a max-turns check:

```python
        # --max-turns hard cap (batch mode only).
        if _BATCH is not None and _BATCH.get("max_turns"):
            if _BATCH["turns"] >= _BATCH["max_turns"]:
                _BATCH["stop_reason"] = "max_turns"
                print(f"[batch] hit --max-turns ({_BATCH['max_turns']}); stopping")
                return
```

Place it AFTER the `if response.stop_reason != "tool_use": return` line and BEFORE `tool_blocks = [b for b in response.content if b.type == "tool_use"]`.

- [ ] **Step 3: Smoke-test usage tracking with a real (cheap) model call**

This actually hits the model. Use a workdir we don't care about:

```bash
cd /tmp && rm -rf minicode_smoke && mkdir minicode_smoke && cd minicode_smoke
git init -q
uv run --project /Users/fscnb/Project/MiniCode python /Users/fscnb/Project/MiniCode/main.py \
    --prompt "Reply with exactly the word: pong. Do not call any tool." \
    --max-turns 2 \
    --usage-out /tmp/u.json
cat /tmp/u.json
```

Expected: `/tmp/u.json` contains non-zero `input_tokens` / `output_tokens`, `turns: 1`, `stop_reason: "end_turn"`. If `turns: 0`, accumulator is in the wrong place.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "feat(main): track per-batch token usage and enforce --max-turns"
```

---

## Task 3: Add `datasets` dependency and create `bench/` skeleton

**Files:**
- Modify: `pyproject.toml`
- Create: `bench/__init__.py`, `bench/.gitignore`, `bench/swebench_run.py` (skeleton with `prepare` subcommand only)

- [ ] **Step 1: Add `datasets` to `pyproject.toml`**

Edit `pyproject.toml`:

```toml
dependencies = [
    "anthropic>=0.25.0",
    "python-dotenv>=1.0.0",
    "textual>=0.85",
    "datasets>=2.14",
]
```

Then run:

```bash
cd /Users/fscnb/Project/MiniCode
uv sync
```

Expected: lockfile updates, `datasets` is installed.

- [ ] **Step 2: Create `bench/__init__.py` (empty) and `bench/.gitignore`**

`bench/__init__.py`:

```python
```

`bench/.gitignore`:

```
repo_cache/
workspaces/
runs/
```

- [ ] **Step 3: Create `bench/swebench_run.py` with the CLI scaffolding and `prepare` subcommand**

```python
"""Harness to run minicode against a fixed random sample of SWE-bench-Verified.

Subcommands:
  prepare   sample N instance_ids with a fixed seed, write to sample_70.txt
  run       run minicode against each sampled instance, write predictions.jsonl
  report    aggregate per-case usage JSON into token_report.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BENCH_DIR.parent
SAMPLE_FILE = BENCH_DIR / "sample_70.txt"
REPO_CACHE = BENCH_DIR / "repo_cache"
WORKSPACES = BENCH_DIR / "workspaces"
RUNS_DIR = BENCH_DIR / "runs"

DATASET_NAME = "princeton-nlp/SWE-bench_Verified"
DATASET_SPLIT = "test"


def _load_dataset():
    from datasets import load_dataset
    return load_dataset(DATASET_NAME, split=DATASET_SPLIT)


def cmd_prepare(args: argparse.Namespace) -> int:
    ds = _load_dataset()
    rng = random.Random(args.seed)
    indices = rng.sample(range(len(ds)), args.n)
    ids = sorted(ds[i]["instance_id"] for i in indices)
    SAMPLE_FILE.write_text("\n".join(ids) + "\n")
    print(f"wrote {len(ids)} ids to {SAMPLE_FILE}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    print("not implemented yet")
    return 1


def cmd_report(args: argparse.Namespace) -> int:
    print("not implemented yet")
    return 1


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("prepare")
    pp.add_argument("--seed", type=int, default=42)
    pp.add_argument("--n", type=int, default=70)
    pp.set_defaults(func=cmd_prepare)

    pr = sub.add_parser("run")
    pr.add_argument("--run-id", required=True)
    pr.add_argument("--workers", type=int, default=4)
    pr.add_argument("--max-turns", type=int, default=60)
    pr.add_argument("--timeout", type=int, default=1800)
    pr.set_defaults(func=cmd_run)

    rp = sub.add_parser("report")
    rp.add_argument("--run-id", required=True)
    rp.set_defaults(func=cmd_report)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run `prepare` to materialize `sample_70.txt`**

```bash
cd /Users/fscnb/Project/MiniCode
uv run python bench/swebench_run.py prepare --seed 42 --n 70
wc -l bench/sample_70.txt
head -3 bench/sample_70.txt
```

Expected: `70 bench/sample_70.txt`, three plausible instance_ids like `astropy__astropy-12907`. The dataset download happens once and is cached under `~/.cache/huggingface/`.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock bench/__init__.py bench/.gitignore bench/swebench_run.py bench/sample_70.txt
git commit -m "feat(bench): add SWE-bench harness scaffolding and 70-id sample"
```

---

## Task 4: Implement `extract_patch()` (TDD)

`extract_patch(repo_path)` returns the unified diff that minicode produced inside `repo_path`, including untracked files but excluding minicode's own state dirs and the prompt file. Resets staging when done so the workspace is left clean.

**Files:**
- Create: `tests/bench/__init__.py` (empty), `tests/bench/test_extract_patch.py`
- Modify: `bench/swebench_run.py` — add `extract_patch` function

- [ ] **Step 1: Create `tests/bench/__init__.py`** (empty file)

- [ ] **Step 2: Write the failing test**

`tests/bench/test_extract_patch.py`:

```python
import subprocess
from pathlib import Path

from bench.swebench_run import extract_patch


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True)


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "a.py").write_text("def f():\n    return 1\n")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-qm", "init")
    return repo


def test_modified_file_appears_in_diff(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("def f():\n    return 2\n")
    patch = extract_patch(repo)
    assert "-    return 1" in patch
    assert "+    return 2" in patch


def test_untracked_file_appears_in_diff(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "b.py").write_text("print('new')\n")
    patch = extract_patch(repo)
    assert "b.py" in patch
    assert "+print('new')" in patch


def test_minicode_state_dirs_excluded(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / ".minicode").mkdir()
    (repo / ".minicode" / "x").write_text("internal")
    (repo / ".memory").mkdir()
    (repo / ".memory" / "m").write_text("memo")
    (repo / "prompt.txt").write_text("the prompt")
    (repo / "a.py").write_text("def f():\n    return 3\n")
    patch = extract_patch(repo)
    assert ".minicode" not in patch
    assert ".memory" not in patch
    assert "prompt.txt" not in patch
    assert "+    return 3" in patch


def test_workspace_left_unstaged(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("def f():\n    return 9\n")
    extract_patch(repo)
    out = subprocess.run(["git", "-C", str(repo), "diff", "--cached"],
                         check=True, capture_output=True, text=True).stdout
    assert out == ""  # nothing staged after extract


def test_no_changes_returns_empty(tmp_path):
    repo = _init_repo(tmp_path)
    assert extract_patch(repo) == ""
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cd /Users/fscnb/Project/MiniCode
uv run pytest tests/bench/test_extract_patch.py -v
```

Expected: ImportError or all tests fail because `extract_patch` doesn't exist.

- [ ] **Step 4: Implement `extract_patch` in `bench/swebench_run.py`**

Add to `bench/swebench_run.py` (above `cmd_prepare`):

```python
EXCLUDE_PATHSPEC = [
    ":!.minicode",
    ":!.memory",
    ":!prompt.txt",
]


def _git(cwd: Path, *args: str, check: bool = True,
         capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=check, capture_output=capture, text=True,
    )


def extract_patch(repo_path: Path) -> str:
    """Return unified diff of all changes in repo_path, including untracked
    files, excluding minicode-internal paths. Leaves workspace unstaged."""
    _git(repo_path, "add", "-A", "--", *EXCLUDE_PATHSPEC)
    diff = _git(repo_path, "diff", "--cached", "HEAD").stdout
    _git(repo_path, "reset", "-q")
    return diff
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
uv run pytest tests/bench/test_extract_patch.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add bench/swebench_run.py tests/bench/__init__.py tests/bench/test_extract_patch.py
git commit -m "feat(bench): extract_patch with untracked-file support and state-dir exclusion"
```

---

## Task 5: Implement `prepare_workspace()` with `git worktree` (TDD)

`prepare_workspace(repo_slug, base_commit, instance_id)` ensures `repo_cache/<slug>` is cloned, then creates an isolated worktree at `workspaces/<instance_id>` checked out at `base_commit`. Idempotent: if the worktree already exists at the right commit, returns its path.

**Files:**
- Create: `tests/bench/test_prepare_workspace.py`
- Modify: `bench/swebench_run.py`

- [ ] **Step 1: Write the failing test**

`tests/bench/test_prepare_workspace.py`:

```python
import subprocess
from pathlib import Path

from bench.swebench_run import prepare_workspace


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True)


def _make_origin(tmp_path: Path) -> tuple[Path, str, str]:
    """Create a bare-ish origin repo with two commits. Returns (path, c1, c2)."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "t@t")
    _git(origin, "config", "user.name", "t")
    (origin / "f.py").write_text("v1\n")
    _git(origin, "add", "f.py")
    _git(origin, "commit", "-qm", "c1")
    c1 = _git(origin, "rev-parse", "HEAD").stdout.strip()
    (origin / "f.py").write_text("v2\n")
    _git(origin, "commit", "-aqm", "c2")
    c2 = _git(origin, "rev-parse", "HEAD").stdout.strip()
    return origin, c1, c2


def test_creates_worktree_at_base_commit(tmp_path, monkeypatch):
    origin, c1, c2 = _make_origin(tmp_path)
    cache = tmp_path / "cache"
    ws_root = tmp_path / "ws"
    monkeypatch.setattr("bench.swebench_run.REPO_CACHE", cache)
    monkeypatch.setattr("bench.swebench_run.WORKSPACES", ws_root)

    ws = prepare_workspace(repo_slug="local/origin", base_commit=c1,
                           instance_id="inst-1", clone_url=str(origin))

    assert ws.exists()
    assert (ws / "f.py").read_text() == "v1\n"
    head = _git(ws, "rev-parse", "HEAD").stdout.strip()
    assert head == c1


def test_idempotent_when_already_at_commit(tmp_path, monkeypatch):
    origin, c1, c2 = _make_origin(tmp_path)
    cache = tmp_path / "cache"
    ws_root = tmp_path / "ws"
    monkeypatch.setattr("bench.swebench_run.REPO_CACHE", cache)
    monkeypatch.setattr("bench.swebench_run.WORKSPACES", ws_root)

    ws1 = prepare_workspace("local/origin", c1, "inst-1", clone_url=str(origin))
    ws2 = prepare_workspace("local/origin", c1, "inst-1", clone_url=str(origin))
    assert ws1 == ws2
    assert (ws2 / "f.py").read_text() == "v1\n"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/bench/test_prepare_workspace.py -v
```

Expected: ImportError on `prepare_workspace`.

- [ ] **Step 3: Implement `prepare_workspace`**

Add to `bench/swebench_run.py`:

```python
def _ensure_clone(slug: str, clone_url: str) -> Path:
    """Idempotently clone <slug> into REPO_CACHE/<slug>."""
    target = REPO_CACHE / slug.replace("/", "__")
    if target.exists():
        return target
    REPO_CACHE.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--quiet", clone_url, str(target)],
        check=True,
    )
    return target


def prepare_workspace(repo_slug: str, base_commit: str, instance_id: str,
                      clone_url: str | None = None) -> Path:
    """Return a workspace path checked out at base_commit. Idempotent."""
    if clone_url is None:
        clone_url = f"https://github.com/{repo_slug}.git"
    cache = _ensure_clone(repo_slug, clone_url)

    # Make sure the cache has the requested commit (it might be a recent push).
    have = subprocess.run(
        ["git", "-C", str(cache), "cat-file", "-e", base_commit + "^{commit}"],
        capture_output=True,
    )
    if have.returncode != 0:
        subprocess.run(["git", "-C", str(cache), "fetch", "--quiet", "origin"],
                       check=True)

    ws = WORKSPACES / instance_id
    if ws.exists():
        head = _git(ws, "rev-parse", "HEAD").stdout.strip()
        if head == base_commit:
            # already at right commit; reset working tree to clean state
            _git(ws, "reset", "--hard", "-q", base_commit)
            _git(ws, "clean", "-fdq", "--", *EXCLUDE_PATHSPEC, ":(exclude).git")
            return ws
        # wrong commit: nuke and recreate
        _git(cache, "worktree", "remove", "--force", str(ws), check=False)
        if ws.exists():
            shutil.rmtree(ws)

    WORKSPACES.mkdir(parents=True, exist_ok=True)
    _git(cache, "worktree", "add", "--detach", "-f", str(ws), base_commit)
    return ws
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/bench/test_prepare_workspace.py -v
```

Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add bench/swebench_run.py tests/bench/test_prepare_workspace.py
git commit -m "feat(bench): prepare_workspace via git worktree, idempotent"
```

---

## Task 6: Implement `run_one_case()`

Single function that, given a dataset row + run dir, prepares the workspace, runs minicode as a subprocess with timeout, captures the patch, writes the prediction line, and returns a status dict. Designed to be called from a `ProcessPoolExecutor` worker.

**Files:**
- Modify: `bench/swebench_run.py`

- [ ] **Step 1: Add the prompt template constant**

Near the top of `bench/swebench_run.py` (after imports/constants):

```python
PROMPT_TEMPLATE = """\
You are fixing a real GitHub issue in this repository.

<issue>
{problem_statement}
</issue>

Constraints:
- Modify only source files needed to fix the issue.
- Do NOT modify test files.
- Do NOT add new dependencies.
- When done, stop. The git diff of your changes will be graded.

Repository root: {repo_path}
Base commit: {base_commit}
"""
```

- [ ] **Step 2: Add `run_one_case()`**

```python
def _prediction_line(instance_id: str, model_label: str, patch: str) -> str:
    return json.dumps({
        "instance_id": instance_id,
        "model_name_or_path": model_label,
        "model_patch": patch,
    }, ensure_ascii=False) + "\n"


def run_one_case(row: dict, run_dir: Path, max_turns: int, timeout: int,
                 model_label: str) -> dict:
    """Run minicode against one SWE-bench case. Returns status dict."""
    instance_id = row["instance_id"]
    repo_slug = row["repo"]
    base_commit = row["base_commit"]
    problem = row["problem_statement"]

    log_path = run_dir / "logs" / f"{instance_id}.log"
    usage_path = run_dir / "usage" / f"{instance_id}.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    usage_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    try:
        ws = prepare_workspace(repo_slug, base_commit, instance_id)
    except Exception as e:
        return {"instance_id": instance_id, "status": "prep_failed",
                "error": str(e), "wall_s": round(time.time() - started, 2)}

    prompt_path = ws / "prompt.txt"
    prompt_path.write_text(PROMPT_TEMPLATE.format(
        problem_statement=problem, repo_path=str(ws), base_commit=base_commit,
    ))

    cmd = [
        "uv", "run", "--project", str(PROJECT_ROOT),
        "python", str(PROJECT_ROOT / "main.py"),
        "--prompt-file", str(prompt_path),
        "--max-turns", str(max_turns),
        "--usage-out", str(usage_path),
    ]
    env = os.environ.copy()
    env["MINICODE_PERM_MODE"] = "yolo"
    env["MINICODE_CACHE"] = env.get("MINICODE_CACHE", "1")

    status = "done"
    with log_path.open("w") as logf:
        try:
            subprocess.run(cmd, cwd=ws, env=env, stdout=logf, stderr=logf,
                           timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            status = "timeout"

    try:
        patch = extract_patch(ws)
    except Exception as e:
        return {"instance_id": instance_id, "status": "diff_failed",
                "error": str(e), "wall_s": round(time.time() - started, 2)}

    pred_path = run_dir / "predictions.jsonl"
    line = _prediction_line(instance_id, model_label, patch)
    # Append-with-lock so concurrent workers don't tear lines.
    import fcntl
    pred_path.parent.mkdir(parents=True, exist_ok=True)
    with pred_path.open("a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(line)
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    # Clean up prompt.txt so the next idempotent call doesn't see it.
    prompt_path.unlink(missing_ok=True)

    return {"instance_id": instance_id, "status": status,
            "patch_bytes": len(patch),
            "wall_s": round(time.time() - started, 2)}
```

- [ ] **Step 3: Smoke-test on a single instance**

This actually invokes minicode for one case. Use the smallest-looking repo from sample_70 so it's fast. First, pick one:

```bash
cd /Users/fscnb/Project/MiniCode
head -1 bench/sample_70.txt
```

Then in a Python REPL or quick script:

```bash
uv run python -c "
from bench.swebench_run import run_one_case, _load_dataset, RUNS_DIR
from pathlib import Path
ds = _load_dataset()
sample = open('bench/sample_70.txt').read().split()
target_id = sample[0]
row = next(r for r in ds if r['instance_id'] == target_id)
run_dir = RUNS_DIR / 'smoke'
run_dir.mkdir(parents=True, exist_ok=True)
print(run_one_case(row, run_dir, max_turns=20, timeout=600, model_label='minicode-glm-5.1'))
"
```

Expected: a dict like `{"instance_id": "...", "status": "done", "patch_bytes": <int>, "wall_s": <float>}`. `bench/runs/smoke/predictions.jsonl` has one line; `bench/runs/smoke/usage/<id>.json` exists.

If clone takes >5 min you can let it run; subsequent calls reuse the cache.

- [ ] **Step 4: Commit**

```bash
git add bench/swebench_run.py
git commit -m "feat(bench): run_one_case orchestrates per-case minicode subprocess"
```

---

## Task 7: Wire up the `run` subcommand with concurrency and resume

`cmd_run` reads `sample_70.txt`, filters out cases already marked `done` in `status.json`, dispatches the rest to a `ProcessPoolExecutor` of size `--workers`, and updates `status.json` after each case.

**Files:**
- Modify: `bench/swebench_run.py`

- [ ] **Step 1: Implement `cmd_run`**

Replace the placeholder `cmd_run` in `bench/swebench_run.py` with:

```python
def _read_status(run_dir: Path) -> dict:
    p = run_dir / "status.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _write_status(run_dir: Path, status: dict) -> None:
    (run_dir / "status.json").write_text(json.dumps(status, indent=2,
                                                     sort_keys=True))


def _run_one_safe(row, run_dir_str, max_turns, timeout, model_label):
    """Top-level wrapper for ProcessPoolExecutor (must be picklable)."""
    try:
        return run_one_case(row, Path(run_dir_str), max_turns, timeout,
                            model_label)
    except Exception as e:
        return {"instance_id": row["instance_id"], "status": "crashed",
                "error": repr(e)}


def cmd_run(args: argparse.Namespace) -> int:
    if not SAMPLE_FILE.exists():
        print(f"error: {SAMPLE_FILE} missing -- run `prepare` first",
              file=sys.stderr)
        return 2
    ids = [s.strip() for s in SAMPLE_FILE.read_text().splitlines() if s.strip()]
    print(f"loaded {len(ids)} instance ids")

    ds = _load_dataset()
    by_id = {r["instance_id"]: r for r in ds}
    rows = [by_id[i] for i in ids if i in by_id]
    missing = [i for i in ids if i not in by_id]
    if missing:
        print(f"warning: {len(missing)} ids not in dataset (skipped): "
              f"{missing[:3]}...")

    run_dir = RUNS_DIR / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    status = _read_status(run_dir)
    todo = [r for r in rows if status.get(r["instance_id"], {}).get("status")
            != "done"]
    print(f"resuming: {len(rows) - len(todo)} done, {len(todo)} to run")

    model_label = f"minicode-{os.environ.get('MODEL_ID', 'unknown')}"

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_run_one_safe, r, str(run_dir), args.max_turns,
                        args.timeout, model_label): r["instance_id"]
            for r in todo
        }
        for fut in as_completed(futures):
            iid = futures[fut]
            try:
                result = fut.result()
            except Exception as e:
                result = {"instance_id": iid, "status": "crashed",
                          "error": repr(e)}
            status[iid] = result
            _write_status(run_dir, status)
            print(f"[{result['status']}] {iid} "
                  f"patch={result.get('patch_bytes', 0)}B "
                  f"wall={result.get('wall_s', '?')}s")

    n_done = sum(1 for v in status.values() if v.get("status") == "done")
    print(f"\ncompleted {n_done}/{len(rows)}")
    print(f"predictions: {run_dir / 'predictions.jsonl'}")
    return 0
```

- [ ] **Step 2: Run a 2-case mini batch to verify concurrency + resume**

```bash
cd /Users/fscnb/Project/MiniCode
# Use a tiny custom sample for the smoke test
head -2 bench/sample_70.txt > /tmp/mini2.txt
mv bench/sample_70.txt bench/sample_70.txt.bak
mv /tmp/mini2.txt bench/sample_70.txt

uv run python bench/swebench_run.py run --run-id smoke2 --workers 2 \
    --max-turns 20 --timeout 600

# resume should report 2 done, 0 to run
uv run python bench/swebench_run.py run --run-id smoke2 --workers 2 \
    --max-turns 20 --timeout 600

# restore real sample
mv bench/sample_70.txt.bak bench/sample_70.txt
```

Expected: first invocation prints two `[done]`/`[timeout]` lines, second prints `resuming: 2 done, 0 to run`.

- [ ] **Step 3: Commit**

```bash
git add bench/swebench_run.py
git commit -m "feat(bench): run subcommand with worker pool and resume-on-status"
```

---

## Task 8: Implement `report` subcommand

Aggregate per-case `usage/*.json` files into a single `token_report.json` plus a brief terminal summary.

**Files:**
- Modify: `bench/swebench_run.py`

- [ ] **Step 1: Replace placeholder `cmd_report`**

```python
USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = RUNS_DIR / args.run_id
    usage_dir = run_dir / "usage"
    if not usage_dir.exists():
        print(f"error: {usage_dir} missing", file=sys.stderr)
        return 2

    per_case = []
    totals = {k: 0 for k in USAGE_KEYS}
    totals["turns"] = 0
    totals["wall_s"] = 0.0
    n_completed = 0

    for f in sorted(usage_dir.glob("*.json")):
        d = json.loads(f.read_text())
        iid = f.stem
        per_case.append({"instance_id": iid, **{k: d.get(k, 0)
                                                for k in USAGE_KEYS},
                         "turns": d.get("turns", 0),
                         "wall_s": d.get("wall_clock_seconds", 0.0),
                         "stop_reason": d.get("stop_reason")})
        for k in USAGE_KEYS:
            totals[k] += d.get(k, 0) or 0
        totals["turns"] += d.get("turns", 0) or 0
        totals["wall_s"] += d.get("wall_clock_seconds", 0.0) or 0.0
        if d.get("stop_reason") == "end_turn":
            n_completed += 1

    report = {
        "run_id": args.run_id,
        "model": os.environ.get("MODEL_ID", "unknown"),
        "n_cases": len(per_case),
        "n_completed": n_completed,
        "totals": totals,
        "per_case": per_case,
    }
    out = run_dir / "token_report.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"wrote {out}")
    print(f"completed {n_completed}/{len(per_case)} | "
          f"in={totals['input_tokens']} out={totals['output_tokens']} "
          f"cache_w={totals['cache_creation_input_tokens']} "
          f"cache_r={totals['cache_read_input_tokens']} "
          f"turns={totals['turns']} wall={totals['wall_s']:.0f}s")
    return 0
```

- [ ] **Step 2: Smoke-test the report against the smoke run from Task 7**

```bash
uv run python bench/swebench_run.py report --run-id smoke2
cat bench/runs/smoke2/token_report.json | python -m json.tool | head -25
```

Expected: a `token_report.json` with non-zero totals and `n_cases: 2`.

- [ ] **Step 3: Commit**

```bash
git add bench/swebench_run.py
git commit -m "feat(bench): report subcommand aggregates per-case usage"
```

---

## Task 9: Run all 70 cases

This is the actual experiment. No code changes — just kicking off the pipeline.

- [ ] **Step 1: Confirm inputs**

```bash
cd /Users/fscnb/Project/MiniCode
wc -l bench/sample_70.txt          # expect 70
cat .env | grep MODEL_ID           # expect MODEL_ID=glm-5.1
```

- [ ] **Step 2: Kick off the run**

```bash
mkdir -p bench/runs/main
uv run python bench/swebench_run.py run --run-id main --workers 4 \
    --max-turns 60 --timeout 1800 \
    2>&1 | tee bench/runs/main/driver.log
```

Expected: ~3-6 hours wall-clock at 4-way concurrency. Per-case lines printed as they finish. If interrupted, re-running the same command resumes (status.json drives skip-list).

- [ ] **Step 3: Aggregate token report**

```bash
uv run python bench/swebench_run.py report --run-id main
```

Expected: prints completion ratio + token totals; writes `bench/runs/main/token_report.json`.

- [ ] **Step 4: Sanity-check predictions.jsonl**

```bash
wc -l bench/runs/main/predictions.jsonl              # ~70
head -1 bench/runs/main/predictions.jsonl | python -m json.tool | head
```

Expected: ~70 lines (could be fewer if some cases failed to even produce a diff path); each line has `instance_id`, `model_name_or_path`, `model_patch`.

- [ ] **Step 5: Submit to sb-cli for grading**

This step is run by the user, not automated:

```bash
pip install sb-cli                          # in any env, doesn't need uv
export SWEBENCH_API_KEY=<key from https://www.swebench.com/sb-cli/>
sb-cli submit swe-bench_verified test \
    --predictions_path bench/runs/main/predictions.jsonl \
    --run_id minicode-glm-5.1-main
sb-cli get-report swe-bench_verified minicode-glm-5.1-main
```

Expected: a JSON report with `resolved` count out of 70.

- [ ] **Step 6: Commit final artifacts**

```bash
# predictions.jsonl and token_report.json are interesting to keep;
# logs and usage/ are bulky, leave them gitignored.
git add bench/runs/main/predictions.jsonl bench/runs/main/token_report.json bench/runs/main/status.json
# (You'll need to remove bench/runs/ from bench/.gitignore for these
# specific files, OR git add -f.)
git add -f bench/runs/main/predictions.jsonl bench/runs/main/token_report.json bench/runs/main/status.json
git commit -m "chore: SWE-bench-Verified 70-case run results (predictions + tokens)"
```

---

## Self-Review Checklist (Run by Implementer Before Final Submit)

- [ ] All 70 cases have a status entry (`done` / `timeout` / `crashed` / `prep_failed` / `diff_failed`).
- [ ] `predictions.jsonl` line count matches the count of cases with a successful `extract_patch` call (may include empty patches).
- [ ] `token_report.json` totals sum to roughly the `usage/*.json` sum (no obvious zero-fill bug).
- [ ] `bench/runs/main/logs/<id>.log` for at least one timeout case shows minicode hit `--max-turns` or wall-clock, not crashed silently.
- [ ] sb-cli report received and `resolved/total` recorded somewhere (e.g. paste into a final commit message).
