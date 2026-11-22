"""Run tools over a fixed sample of Juliet files and save every scan.

Examples:
    python run_batch.py cppcheck flawfinder --per-cwe 5
    python run_batch.py llm --per-cwe 20
"""

import argparse
import random
import re
import sqlite3
import time
from pathlib import Path

import config
from pipeline.analyzer import run_cppcheck, run_flawfinder
from pipeline.labels import normalize_path
from pipeline.llm_client import review_file
from pipeline.store import PROMPT_FINGERPRINT, PROMPT_VERSION, save_scan
from pipeline.scorer import latest_scans

SINGLE_FILE = re.compile(r"_\d+\.c$")  # ..._01.c is one file; ..._51a.c is not


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
parser.add_argument("tools", nargs="+", choices=["cppcheck", "flawfinder", "llm"])
parser.add_argument("--per-cwe", type=int, default=5,
                    help="files to scan for each chosen CWE")
args = parser.parse_args()

conn = sqlite3.connect(config.DB_PATH)
files = sample_files(args.per_cwe)
print(f"{len(files)} files selected")

for tool in args.tools:
    prompt = f"{PROMPT_VERSION}-{PROMPT_FINGERPRINT}" if tool == "llm" else None
    done = latest_scans(conn, tool, prompt)  # already saved, so a rerun skips them
    stats, started = {}, time.time()
    for number, path in enumerate(files, start=1):
        name = normalize_path(path)
        if name in done:
            continue
        findings = run_tool(tool, path, stats)
        save_scan(conn, name, tool, findings)
        print(f"{tool} {number}/{len(files)} {path.name}: {len(findings)} findings")
    print(f"{tool} finished in {time.time() - started:.0f} s {stats if stats else ''}")
conn.close()