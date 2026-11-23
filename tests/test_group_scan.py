"""Tests for scanning a whole multi-file case, with fake tools and an in-memory database."""

# Run from the repo root: python tests\test_group_scan.py
import logging
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

import config
import pipeline.group_scan as group_scan

logging.disable(logging.CRITICAL)

conn = sqlite3.connect(":memory:")
conn.executescript((config.BASE_DIR / "schema.sql").read_text())

A, B = Path("C:/J/case_51a.c"), Path("C:/J/case_51b.c")
KEYS = ["c:/j/case_51a.c", "c:/j/case_51b.c"]


def finding(file, line):
    return {"source_tool": "cppcheck", "file": str(file), "line": line, "cwe": "CWE-121",
            "severity": "error", "message": "m", "suggested_fix": None}


def counts(tool):
    rows = conn.execute(
        "SELECT s.input_name, COUNT(f.id) FROM scans s LEFT JOIN findings f"
        " ON f.scan_id = s.id WHERE s.tool = ? GROUP BY s.id ORDER BY s.id", (tool,))
    return dict(rows)


# cppcheck_group: one run for both files, and the findings go to the right file.
calls = []

def fake_cppcheck(paths, include_dir=None):
    calls.append(paths)
    return [finding(A, 9), finding("c:\\J\\CASE_51B.c", 4),    # another spelling of b's name
            finding(B, 7), finding("C:/J/other_header.c", 1)]  # not part of the case

group_scan.run_cppcheck = fake_cppcheck
found, stats = group_scan.scan_group(conn, [A, B], "cppcheck_group")
assert calls == [[A, B]], "Cppcheck must run once, on both files together"
assert found == {KEYS[0]: 1, KEYS[1]: 2} and stats == {}
assert counts("cppcheck_group") == {KEYS[0]: 1, KEYS[1]: 2}
assert conn.execute("SELECT model_name FROM scans WHERE tool = 'cppcheck_group'").fetchone() == (None,)

# llm_group: each file is reviewed with the other files beside it.
reviews = []

def fake_model(path, hide_answers=False, siblings=()):
    reviews.append((path, list(siblings), hide_answers))
    return ([finding(path, 3)],
            {"chunks": 1, "parse_failures": 0, "retries": 0, "dropped": 0})

group_scan.review_file = fake_model
found, stats = group_scan.scan_group(conn, [A, B], "llm_group", hide_answers=True)
assert reviews == [(A, [B], True), (B, [A], True)], "each file must see the other"
assert stats == {"chunks": 2, "parse_failures": 0, "retries": 0, "dropped": 0}
assert counts("llm_group") == {KEYS[0]: 1, KEYS[1]: 1}
model, prompt = conn.execute("SELECT model_name, prompt_version FROM scans"
                             " WHERE tool = 'llm_group'").fetchone()
assert model and prompt, "group model scans must record the model and the prompt"

try:
    group_scan.scan_group(conn, [A, B], "llm")
    raise AssertionError("a plain tool name must be refused")
except ValueError:
    pass

print("All group scan tests passed")