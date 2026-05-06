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
