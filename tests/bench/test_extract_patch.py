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
