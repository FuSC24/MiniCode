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
