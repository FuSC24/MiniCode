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
