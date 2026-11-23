"""Score tools on the files they were all run on, print the tables and save
the numbers to the metrics table.

Examples:
    python score_all.py
    python score_all.py cppcheck flawfinder llm
    python score_all.py --cwe-only
    python score_all.py cppcheck flawfinder llm --files multi
    python score_all.py cppcheck_group flawfinder llm_group --files multi
"""

import argparse
import sqlite3
import sys
from datetime import date

import config
from pipeline.groups import case_counts, file_kind
from pipeline.scorer import (compare_tools, latest_scans, load_findings,
                             load_functions, score_by_cwe)
from pipeline.store import PROMPT_FINGERPRINT, PROMPT_VERSION


def show(value):
    return "n/a" if value is None else f"{value:.2f}"


parser = argparse.ArgumentParser()
parser.add_argument("tools", nargs="*", default=["cppcheck", "flawfinder"])
parser.add_argument("--prompt", default=f"{PROMPT_VERSION}-{PROMPT_FINGERPRINT}",
                    help="which prompt version of the model scans to score")
parser.add_argument("--cwe-only", action="store_true",
                    help="ignore findings that carry no CWE")
parser.add_argument("--files", choices=["single", "multi", "all"], default="single",
                    help="score single-file cases (the baseline), multi-file cases, or both")
args = parser.parse_args()

conn = sqlite3.connect(config.DB_PATH)
scans = {tool: latest_scans(conn, tool, args.prompt if tool.startswith("llm") else None)
         for tool in args.tools}
for tool, found in scans.items():
    if not found:
        sys.exit(f"No saved scans for {tool}. Run run_batch.py first.")

# Score every tool on the files that all of them were run on.
labelled = {fn["file"] for fn in load_functions(conn)}  # files that are in the answer key
common = set.intersection(*(set(found) for found in scans.values())) & labelled
if args.files != "all":
    common = {name for name in common if file_kind(name) == args.files}
if not common:
    sys.exit("The tools were run on different files, so there is nothing to compare.")
functions = [fn for fn in load_functions(conn) if fn["file"] in common]

pooled, results = [], {}
for tool in args.tools:
    findings = load_findings(conn, [scans[tool][name] for name in common])
    if args.cwe_only:
        findings = [f for f in findings if f["cwe"]]
    results[tool] = score_by_cwe(findings, functions)
    pooled += findings
results["combined"] = score_by_cwe(pooled, functions)
agreement, unique = compare_tools({t: results[t]["ALL"] for t in args.tools})

kind = "" if args.files == "single" else f"   {args.files}-file cases"
print(f"Date {date.today()}   files {len(common)}   CWE-only {args.cwe_only}{kind}")
if any(tool.startswith("llm") for tool in args.tools):
    print(f"Model scans scored: prompt {args.prompt}")
for scope in results["combined"]:
    first = results["combined"][scope]
    print()
    print(f"{scope}: {first['flawed']} flawed and {first['safe']} safe functions")
    print(f"{'tool':<11}{'found':>6}{'w/CWE':>7}{'false':>7}{'prec':>7}"
          f"{'recall':>8}{'rec+CWE':>9}{'F1':>6}{'FPrate':>8}{'unscored':>10}")
    for tool in results:
        r = results[tool][scope]
        print(f"{tool:<11}{r['tp']:>6}{r['right_cwe']:>7}{r['fp']:>7}"
              f"{show(r['precision']):>7}{show(r['recall']):>8}"
              f"{show(r['recall_cwe']):>9}{show(r['f1']):>6}"
              f"{show(r['fp_rate']):>8}{r['unscored']:>10}")
print()
print(f"Flawed functions found by two or more tools: {agreement}")
print(f"Found by one tool only: {unique}")
if args.files != "single":
    for tool in args.tools:
        caught, total = case_counts(functions, results[tool]["ALL"]["detected_keys"])
        print(f"Multi-file cases caught by {tool}: {caught} of {total}")

# Keep the latest numbers for each tool in the metrics table.
suffix = (" cwe-only" if args.cwe_only else "") + ("" if args.files == "single" else f" {args.files}")
for tool, by_scope in results.items():
    conn.execute("DELETE FROM metrics WHERE tool = ?", (tool + suffix,))
    for scope, r in by_scope.items():
        conn.execute(
            "INSERT INTO metrics (scan_id, tool, cwe, true_pos, false_pos,"
            " false_neg, precision, recall, f1) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool + suffix, scope, r["tp"], r["fp"], r["fn"],
             r["precision"], r["recall"], r["f1"]))
conn.commit()
conn.close()