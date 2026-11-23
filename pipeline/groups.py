"""Finds the files that belong together in Juliet's multi-file test cases."""

import random
import re
from pathlib import Path

SINGLE_FILE = re.compile(r"_\d+\.c$")             # ..._01.c is one file
GROUP_PART = re.compile(r"^(.+_\d+)([a-z])\.c$")  # ..._51a.c is part of a case


def group_key(path):
    """The shared start of a multi-file case's file names, or None for a
    single file. ..._51a.c and ..._51b.c both give ..._51."""
    match = GROUP_PART.match(Path(path).name.lower())
    return match.group(1) if match else None


def file_kind(name):
    """"multi", "single" or "other", from a file name or a saved input name."""
    last = str(name).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if GROUP_PART.match(last):
        return "multi"
    return "single" if SINGLE_FILE.search(last) else "other"


def case_id(name):
    """One id for every file of a case, or None for a single file."""
    name = str(name).replace("\\", "/").lower()
    key = group_key(name)
    return None if key is None else name.rsplit("/", 1)[0] + "/" + key


def sample_groups(juliet_dir, prefixes, per_cwe, seed=0):
    """Pick the same cases every time: a seeded shuffle, then the first N.
    Returns a list of cases, and each case is a sorted list of file paths."""
    chosen = []
    for prefix in prefixes:
        found = {}
        pattern = f"{prefix}*/**/*.c"
        for path in sorted((Path(juliet_dir) / "testcases").glob(pattern)):
            key = group_key(path)
            if key:
                found.setdefault((str(path.parent), key), []).append(path)
        cases = [sorted(found[key]) for key in sorted(found) if len(found[key]) > 1]
        random.Random(seed).shuffle(cases)
        chosen += cases[:per_cwe]
    return chosen


def case_counts(functions, detected_keys):
    """How many flawed cases a tool caught, counting a case as caught when any
    of its flawed functions was detected.

    functions:     the labelled functions, as load_functions returns them
    detected_keys: {(file, function_name)} from the scorer
    Returns (caught, total)."""
    flawed, caught = set(), set()
    for fn in functions:
        case = case_id(fn["file"])
        if case is None or not fn["is_vulnerable"]:
            continue
        flawed.add(case)
        if (fn["file"], fn["function_name"]) in detected_keys:
            caught.add(case)
    return len(caught), len(flawed)