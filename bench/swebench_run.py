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

from dotenv import load_dotenv

BENCH_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BENCH_DIR.parent
load_dotenv(PROJECT_ROOT / ".env")
SAMPLE_FILE = BENCH_DIR / "sample_70.txt"
REPO_CACHE = BENCH_DIR / "repo_cache"
WORKSPACES = BENCH_DIR / "workspaces"
RUNS_DIR = BENCH_DIR / "runs"

DATASET_NAME = "princeton-nlp/SWE-bench_Verified"
DATASET_SPLIT = "test"

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


def _load_dataset():
    from datasets import load_dataset
    return load_dataset(DATASET_NAME, split=DATASET_SPLIT)


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


def _prediction_line(instance_id: str, model_label: str, patch: str) -> str:
    return json.dumps({
        "instance_id": instance_id,
        "model_name_or_path": model_label,
        "model_patch": patch,
    }, ensure_ascii=False) + "\n"


def _run_minicode(prompt_path: Path, ws: Path, log_path: Path, usage_path: Path,
                  max_turns: int, timeout: int) -> str:
    """Run minicode subprocess. Returns status string."""
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
    with log_path.open("w") as logf:
        try:
            subprocess.run(cmd, cwd=ws, env=env, stdout=logf, stderr=logf,
                           timeout=timeout, check=False)
            return "done"
        except subprocess.TimeoutExpired:
            return "timeout"


def _run_claude(prompt_path: Path, ws: Path, log_path: Path, usage_path: Path,
                model: str, max_budget_usd: float, timeout: int,
                started: float) -> str:
    """Run `claude --print` subprocess on prompt_path inside ws.
    Parses claude's final JSON result, writes usage_path in minicode's shape."""
    prompt = prompt_path.read_text()
    cmd = [
        "claude", "--print",
        "--model", model,
        "--permission-mode", "bypassPermissions",
        "--allow-dangerously-skip-permissions",
        "--max-budget-usd", str(max_budget_usd),
        "--output-format", "json",
        prompt,
    ]
    # Strip minicode's .env vars so claude uses its own (Anthropic) auth, not
    # the 智谱 proxy that .env is configured for.
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
                        "ANTHROPIC_AUTH_TOKEN")}
    status = "done"
    stdout_data = ""
    with log_path.open("w") as logf:
        try:
            r = subprocess.run(cmd, cwd=ws, env=env, capture_output=True,
                               text=True, timeout=timeout, check=False)
            stdout_data = r.stdout
            logf.write("--- STDOUT ---\n" + r.stdout +
                       "\n--- STDERR ---\n" + r.stderr)
            if r.returncode != 0:
                status = "claude_error"
        except subprocess.TimeoutExpired as e:
            status = "timeout"
            stdout_data = (e.stdout.decode() if isinstance(e.stdout, bytes)
                           else (e.stdout or ""))
            logf.write("--- TIMEOUT ---\n" + stdout_data)

    try:
        result = json.loads(stdout_data)
        u = result.get("usage", {}) or {}
        usage_path.write_text(json.dumps({
            "turns": result.get("num_turns", 0),
            "input_tokens": u.get("input_tokens", 0) or 0,
            "output_tokens": u.get("output_tokens", 0) or 0,
            "cache_creation_input_tokens": u.get("cache_creation_input_tokens", 0) or 0,
            "cache_read_input_tokens": u.get("cache_read_input_tokens", 0) or 0,
            "stop_reason": result.get("stop_reason"),
            "wall_clock_seconds": round(time.time() - started, 2),
            "total_cost_usd": result.get("total_cost_usd", 0.0),
        }, indent=2))
    except Exception:
        # JSON malformed or missing — write minimal record so report still works.
        usage_path.write_text(json.dumps({
            "turns": 0, "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            "stop_reason": status, "wall_clock_seconds": round(time.time()-started, 2),
            "total_cost_usd": 0.0,
        }, indent=2))
    return status


def run_one_case(row: dict, run_dir: Path, max_turns: int, timeout: int,
                 model_label: str, engine: str = "minicode") -> dict:
    """Run an engine against one SWE-bench case. Returns status dict."""
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

    if engine == "minicode":
        status = _run_minicode(prompt_path, ws, log_path, usage_path,
                               max_turns, timeout)
    elif engine == "claude":
        status = _run_claude(prompt_path, ws, log_path, usage_path,
                             model="claude-sonnet-4-6", max_budget_usd=2.0,
                             timeout=timeout, started=started)
    else:
        raise ValueError(f"unknown engine: {engine}")

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


def cmd_prepare(args: argparse.Namespace) -> int:
    ds = _load_dataset()
    rng = random.Random(args.seed)
    indices = rng.sample(range(len(ds)), args.n)
    ids = sorted(ds[i]["instance_id"] for i in indices)
    SAMPLE_FILE.write_text("\n".join(ids) + "\n")
    print(f"wrote {len(ids)} ids to {SAMPLE_FILE}")
    return 0


def _read_status(run_dir: Path) -> dict:
    p = run_dir / "status.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _write_status(run_dir: Path, status: dict) -> None:
    (run_dir / "status.json").write_text(json.dumps(status, indent=2,
                                                     sort_keys=True))


def _run_one_safe(row, run_dir_str, max_turns, timeout, model_label, engine):
    """Top-level wrapper for ProcessPoolExecutor (must be picklable)."""
    try:
        return run_one_case(row, Path(run_dir_str), max_turns, timeout,
                            model_label, engine=engine)
    except Exception as e:
        return {"instance_id": row["instance_id"], "status": "crashed",
                "error": repr(e)}


def cmd_run(args: argparse.Namespace) -> int:
    sample_file = Path(args.sample_file) if args.sample_file else SAMPLE_FILE
    if not sample_file.exists():
        print(f"error: {sample_file} missing -- run `prepare` first",
              file=sys.stderr)
        return 2
    ids = [s.strip() for s in sample_file.read_text().splitlines() if s.strip()]
    print(f"loaded {len(ids)} instance ids from {sample_file.name}")

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

    if args.engine == "minicode":
        model_label = f"minicode-{os.environ.get('MODEL_ID', 'unknown')}"
    elif args.engine == "claude":
        model_label = "claude-code-sonnet-4-6"
    else:
        raise ValueError(f"unknown engine: {args.engine}")

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_run_one_safe, r, str(run_dir), args.max_turns,
                        args.timeout, model_label, args.engine): r["instance_id"]
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
    pr.add_argument("--engine", choices=("minicode", "claude"),
                    default="minicode")
    pr.add_argument("--sample-file", default=None,
                    help="path to a sample-id file (default: bench/sample_70.txt)")
    pr.set_defaults(func=cmd_run)

    rp = sub.add_parser("report")
    rp.add_argument("--run-id", required=True)
    rp.set_defaults(func=cmd_report)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
