"""Tests for the report data, with a hand-made database."""

# Run from the repo root: python tests\test_report.py
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

import config
from pipeline.report import build_report, is_inside, read_source
from pipeline.store import save_scan

NAME = "c:/x/case_01.c"
conn = sqlite3.connect(":memory:")
conn.executescript((config.BASE_DIR / "schema.sql").read_text())

# Two labelled functions: bad is lines 3-6 (flawed), good1 is lines 8-11 (safe).
conn.executemany(
    "INSERT INTO ground_truth (dataset, file, function_name, start_line, end_line, cwe, is_vulnerable)"
    " VALUES ('juliet', ?, ?, ?, ?, 'CWE-121', ?)",
    [(NAME, "case_01_bad", 3, 6, 1), (NAME, "good1", 8, 11, 0)])


def item(tool, line, file=NAME, fix=None):
    return {"source_tool": tool, "file": file, "line": line, "cwe": "CWE-121",
            "severity": "high", "message": f"{tool} at {line}", "suggested_fix": fix}


# An old Cppcheck scan, which the newer one must replace.
save_scan(conn, NAME, "cppcheck", [item("cppcheck", 20)])
save_scan(conn, NAME, "cppcheck",
          [item("cppcheck", 4), item("cppcheck", 9), item("cppcheck", 1, file="c:/x/std.h")])
save_scan(conn, NAME, "flawfinder", [item("flawfinder", 4)])

source = [f"line {n}" for n in range(1, 13)]
report = build_report(conn, NAME, source)

assert build_report(conn, "c:/x/nothing.c") is None

# Rows: only lines with a finding, in order, with the code and the right cells.
assert [row["line"] for row in report["rows"]] == [4, 9]   # not 20, not the header's line 1
row4 = report["rows"][0]
assert row4["code"] == "line 4"
assert len(row4["cells"]["cppcheck"]) == 1 and len(row4["cells"]["flawfinder"]) == 1
assert row4["cells"]["llm"] == []

# Header cards: counts in this file, findings elsewhere, and a tool that did not run.
cards = {t["tool"]: t for t in report["tools"]}
assert cards["cppcheck"]["count"] == 2 and cards["cppcheck"]["elsewhere"] == 1
assert cards["flawfinder"]["count"] == 1 and cards["flawfinder"]["elsewhere"] == 0
assert cards["llm"]["ran"] is False

# Against the answer key: bad has findings from both tools, good1 from Cppcheck only.
by_name = {fn["name"]: fn for fn in report["functions"]}
assert by_name["case_01_bad"]["flags"] == {"cppcheck": 1, "flawfinder": 1}
assert by_name["good1"]["flags"] == {"cppcheck": 1, "flawfinder": 0}
assert report["summary"]["cppcheck"] == {"flawed": 1, "detected": 1, "safe": 1, "false_alarms": 1}
assert report["summary"]["flawfinder"] == {"flawed": 1, "detected": 1, "safe": 1, "false_alarms": 0}

# The model's suggested fix reaches the page data.
save_scan(conn, NAME, "llm", [item("llm", 5, fix="Check the length first")])
report = build_report(conn, NAME, source)
assert [row["line"] for row in report["rows"]] == [4, 5, 9]
cell = report["rows"][1]["cells"]["llm"]
assert [f["suggested_fix"] for f in cell] == ["Check the length first"]
assert report["rows"][0]["cells"]["llm"] == []

# A file that is not a labelled one has no answer-key section.
save_scan(conn, "c:/y/own.c", "cppcheck", [item("cppcheck", 2, file="c:/y/own.c")])
own = build_report(conn, "c:/y/own.c", None)
assert own["functions"] is None and own["summary"] is None and own["has_code"] is False

# read_source reads only uploads and Juliet files.
with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder)
    config.UPLOAD_DIR = folder / "uploads"
    config.JULIET_DIR = folder / "juliet"
    (config.UPLOAD_DIR / "ab").mkdir(parents=True)
    inside = config.UPLOAD_DIR / "ab" / "a.c"
    inside.write_text("one\ntwo\n")
    outside = folder / "secret.txt"
    outside.write_text("private")
    assert read_source(str(inside)) == ["one", "two"]
    assert read_source(str(outside)) is None
    assert read_source(str(config.UPLOAD_DIR / "ab" / ".." / ".." / "secret.txt")) is None
    assert read_source(str(config.UPLOAD_DIR / "ab" / "missing.c")) is None
    assert is_inside(inside, config.UPLOAD_DIR) and not is_inside(outside, config.UPLOAD_DIR)

print("All report tests passed")