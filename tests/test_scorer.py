"""Hand-checked tests for the scorer."""

# Run from the repo root: python tests\test_scorer.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

from pipeline.scorer import compare_tools, score, score_by_cwe


def fn(name, first, last, flawed):
    return {"file": "a.c", "function_name": name, "start_line": first,
            "end_line": last, "cwe": "CWE-121", "is_vulnerable": flawed}


FUNCTIONS = [
    fn("bad1", 10, 20, 1), fn("bad2", 50, 60, 1), fn("bad3", 90, 100, 1),
    fn("good1", 30, 40, 0), fn("good2", 70, 80, 0), fn("good3", 110, 120, 0),
    fn("good4", 130, 140, 0), fn("good5", 150, 160, 0),
]


def finding(line, cwe):
    return {"file": "a.c", "line": line, "cwe": cwe}


FINDINGS = [
    finding(10, "CWE-121"),   # first line of bad1, right CWE
    finding(18, "CWE-121"),   # second finding in bad1: a duplicate
    finding(100, "CWE-120"),  # last line of bad3, wrong CWE
    finding(35, "CWE-121"),   # false alarm in good1
    finding(115, "CWE-121"),  # false alarm in good3
    finding(200, "CWE-121"),  # outside every function: not scored
]
# bad2 is never reported: a miss.

r = score(FINDINGS, FUNCTIONS)
assert (r["flawed"], r["safe"]) == (3, 5)
assert (r["tp"], r["fp"], r["fn"]) == (2, 2, 1)
assert r["right_cwe"] == 1
assert r["unscored"] == 1
assert r["precision"] == 0.5
assert abs(r["recall"] - 2 / 3) < 1e-9
assert abs(r["recall_cwe"] - 1 / 3) < 1e-9
assert abs(r["f1"] - 4 / 7) < 1e-9
assert r["fp_rate"] == 0.4

empty = score([], FUNCTIONS)  # a tool that reports nothing
assert empty["precision"] is None and empty["recall"] == 0 and empty["f1"] == 0

assert score_by_cwe(FINDINGS, FUNCTIONS)["CWE-121"]["tp"] == 2

a = {"detected_keys": {("a.c", "bad1"), ("a.c", "bad3")}}
b = {"detected_keys": {("a.c", "bad1")}}
assert compare_tools({"A": a, "B": b}) == (1, {"A": 1, "B": 0})

print("All scorer tests passed")