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
