"""Run tools over a fixed sample of Juliet files and save every scan.

Examples:
    python run_batch.py cppcheck flawfinder --per-cwe 5
    python run_batch.py llm --per-cwe 20
    python run_batch.py cppcheck flawfinder llm --groups --per-cwe 5
    python run_batch.py cppcheck_group llm_group --groups --per-cwe 5
"""

import argparse
import random
import sqlite3
import time
from pathlib import Path

import config
from pipeline.analyzer import run_cppcheck, run_flawfinder
from pipeline.group_scan import GROUP_TOOLS, scan_group
from pipeline.groups import SINGLE_FILE, sample_groups
from pipeline.labels import normalize_path
from pipeline.llm_client import review_file
from pipeline.store import PROMPT_FINGERPRINT, PROMPT_VERSION, save_scan
from pipeline.scorer import latest_scans


def sample_files(per_cwe):
    """Pick the same files every time: a seeded shuffle, then the first N."""
    chosen = []
    for prefix in config.CHOSEN_CWES:
        pattern = f"{prefix}*/**/*.c"
        files = sorted((Path(config.JULIET_DIR) / "testcases").glob(pattern))
        files = [f for f in files if SINGLE_FILE.search(f.name)]
        random.Random(0).shuffle(files)
        chosen += files[:per_cwe]
    return chosen


def run_tool(tool, path, stats):
    if tool == "cppcheck":
        return run_cppcheck(path, config.JULIET_DIR / "testcasesupport")
    if tool == "flawfinder":
        return run_flawfinder(path)
    findings, file_stats = review_file(path, hide_answers=True)
    for key in ("chunks", "parse_failures", "retries", "dropped"):
        stats[key] = stats.get(key, 0) + file_stats[key]
    return findings


parser = argparse.ArgumentParser()
parser.add_argument("tools", nargs="+",
                    choices=["cppcheck", "flawfinder", "llm", *GROUP_TOOLS])
parser.add_argument("--per-cwe", type=int, default=5,
                    help="files (or multi-file cases, with --groups) for each chosen CWE")
parser.add_argument("--groups", action="store_true",
                    help="sample multi-file cases instead of single files")
args = parser.parse_args()
if any(tool in GROUP_TOOLS for tool in args.tools) and not args.groups:
    parser.error("cppcheck_group and llm_group need --groups")

conn = sqlite3.connect(config.DB_PATH)
if args.groups:
    cases = sample_groups(config.JULIET_DIR, config.CHOSEN_CWES, args.per_cwe)
else:
    cases = [[path] for path in sample_files(args.per_cwe)]  # a single file is a case of one
total = sum(len(case) for case in cases)
print(f"{len(cases)} {'cases' if args.groups else 'files'} selected ({total} files)")

for tool in args.tools:
    prompt = f"{PROMPT_VERSION}-{PROMPT_FINGERPRINT}" if tool.startswith("llm") else None
    done = latest_scans(conn, tool, prompt)  # already saved, so a rerun skips them
    stats, started = {}, time.time()
    for number, case in enumerate(cases, start=1):
        names = [normalize_path(path) for path in case]
        if all(name in done for name in names):
            continue
        if tool in GROUP_TOOLS:
            counts, case_stats = scan_group(conn, case, tool,
                                            config.JULIET_DIR / "testcasesupport",
                                            hide_answers=True)
            for key, value in case_stats.items():
                stats[key] = stats.get(key, 0) + value
            print(f"{tool} {number}/{len(cases)} {case[0].name} + {len(case) - 1} more:"
                  f" {sum(counts.values())} findings")
            continue
        for path, name in zip(case, names):
            if name in done:
                continue
            findings = run_tool(tool, path, stats)
            save_scan(conn, name, tool, findings)
            print(f"{tool} {number}/{len(cases)} {path.name}: {len(findings)} findings")
    print(f"{tool} finished in {time.time() - started:.0f} s {stats if stats else ''}")
conn.close()