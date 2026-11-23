"""Fetches a public GitHub repository so its C files can be scanned."""

import re
from pathlib import Path

MAX_FILES = 10  # the model is slow, so a demo scan stays short

GITHUB = re.compile(r"https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?")


def parse_github_url(text):
    """Return a clean clone URL for a GitHub repository address, or None.
    The URL is rebuilt from the two names, so nothing else the user typed
    ever reaches git."""
    match = GITHUB.fullmatch(text.strip())
    if match is None:
        return None
    return f"https://github.com/{match.group(1)}/{match.group(2)}.git"


def clone(url, folder):
    """Download the newest commit only, with no history."""
    from git import Repo  # GitPython, from requirements.txt
    Repo.clone_from(url, str(folder), depth=1)


def c_files(folder, max_bytes, limit=MAX_FILES):
    """The .c files of a cloned repository: skips .git and large files, and
    takes the smallest first so a short scan finishes."""
    found = [path for path in Path(folder).rglob("*.c")
             if ".git" not in path.parts and path.is_file()
             and path.stat().st_size <= max_bytes]
    return sorted(found, key=lambda path: (path.stat().st_size, str(path)))[:limit]