"""Tests for run_scan, with fake tools so nothing real is started."""

# Run from the repo root: python tests\test_runner.py
import logging
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

import config
import pipeline.runner as runner


def new_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript((config.BASE_DIR / "schema.sql").read_text())
    return conn


def finding(tool, line):
    return {"source_tool": tool, "file": r"C:\Work\Case_01.c", "line": line,
            "cwe": "CWE-121", "severity": "high", "message": "m",
            "suggested_fix": "use a bigger buffer" if tool == "llm" else None}


runner.run_cppcheck = lambda path, include_dir=None: [finding("cppcheck", 4), finding("cppcheck", 9)]
runner.run_flawfinder = lambda path: [finding("flawfinder", 4)]
runner.review_file = lambda path, hide_answers=False: (
    [finding("llm", 5)], {"chunks": 1, "parse_failures": 0, "retries": 0, "dropped": 0})

# All three tools run: one scan row each, under one normalized name.
conn = new_db()
result = runner.run_scan(conn, r"C:\Work\Case_01.c")
assert result["name"] == "c:/work/case_01.c"
assert result["counts"] == {"cppcheck": 2, "flawfinder": 1, "llm": 1}
assert sorted(result["ids"]) == ["cppcheck", "flawfinder", "llm"]
assert result["errors"] == {} and result["stats"]["chunks"] == 1
rows = conn.execute("SELECT tool, input_name FROM scans ORDER BY id").fetchall()
assert rows == [("cppcheck", "c:/work/case_01.c"), ("flawfinder", "c:/work/case_01.c"),
                ("llm", "c:/work/case_01.c")]
assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 4

# The suggested fix is saved for the model and empty for the analyzers.
fixes = conn.execute("SELECT source_tool, suggested_fix FROM findings ORDER BY id").fetchall()
assert ("llm", "use a bigger buffer") in fixes and ("cppcheck", None) in fixes

# Only the chosen tools run.
conn = new_db()
result = runner.run_scan(conn, "x.c", tools=["flawfinder"])
assert list(result["ids"]) == ["flawfinder"]
assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


# A tool that fails is reported and not saved. The others still run.
def broken(path, hide_answers=False):
    raise ConnectionError("Ollama is not running")


runner.review_file = broken
logging.disable(logging.CRITICAL)  # run_scan logs the failure on purpose
conn = new_db()
result = runner.run_scan(conn, "x.c")
assert "llm" in result["errors"] and "Ollama is not running" in result["errors"]["llm"]
assert sorted(result["ids"]) == ["cppcheck", "flawfinder"]
tools_saved = [row[0] for row in conn.execute("SELECT tool FROM scans")]
assert "llm" not in tools_saved, "a failed tool must not leave an empty scan behind"

print("All runner tests passed")