"""Tests for the GitHub helpers. The clone uses a small repository made on the spot."""

# Run from the repo root: python tests\test_repo.py
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

from pipeline.repo import c_files, clone, parse_github_url

# Only plain GitHub addresses pass, and the URL that comes out is rebuilt.
ok = "https://github.com/octocat/Hello-World.git"
assert parse_github_url("https://github.com/octocat/Hello-World") == ok
assert parse_github_url("  https://github.com/octocat/Hello-World.git ") == ok
assert parse_github_url("https://github.com/octocat/Hello-World/") == ok
for bad in ["http://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a",
            "https://github.com/a/b/tree/main", "ext::sh -c touch% /tmp/x",
            "-u./evil", "https://github.com/a/b c", "file:///etc", ""]:
    assert parse_github_url(bad) is None, bad

with tempfile.TemporaryDirectory() as folder:
    source = Path(folder) / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "small.c").write_text("int a;\n")
    (source / "src" / "medium.c").write_text("int b;\n" * 10)
    (source / "big.c").write_text("int c;\n" * 1000)
    (source / "header.h").write_text("int d;\n")
    run = lambda *args: subprocess.run(["git", *args], cwd=source, check=True, capture_output=True)
    run("init", "-q")
    run("-c", "user.name=t", "-c", "user.email=t@t", "add", ".")
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x")

    copy = Path(folder) / "copy"
    clone(str(source), copy)                      # a local path stands in for GitHub
    assert (copy / "src" / "small.c").exists()

    found = c_files(copy, max_bytes=200)
    assert [p.name for p in found] == ["small.c", "medium.c"]   # smallest first, no big.c, no .h
    assert not any(".git" in p.parts for p in found)
    assert [p.name for p in c_files(copy, max_bytes=200, limit=1)] == ["small.c"]

print("All repo tests passed")