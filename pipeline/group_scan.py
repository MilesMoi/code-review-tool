"""Scans all the files of one multi-file case together and saves one scan per file."""

from pipeline.analyzer import run_cppcheck
from pipeline.labels import normalize_path
from pipeline.llm_client import review_file
from pipeline.store import save_scan

GROUP_TOOLS = ("cppcheck_group", "llm_group")


def scan_group(conn, paths, tool, include_dir=None, hide_answers=False):
    """Scan the files of one case with a group tool. Each file still gets its
    own saved scan under the group tool's name, so scoring works as before.

    cppcheck_group  one Cppcheck run over every file, so it can follow a call
                    from one file into another
    llm_group       each file reviewed with the other files' called code beside it

    Returns (counts, stats): {file name: findings saved} and the model's totals.
    """
    names = [normalize_path(path) for path in paths]
    by_file = {name: [] for name in names}
    stats = {}

    if tool == "cppcheck_group":
        for finding in run_cppcheck(list(paths), include_dir):
            key = normalize_path(finding["file"])
            if key in by_file:  # a finding in some other file is not part of this case
                by_file[key].append(finding)
    elif tool == "llm_group":
        for path, name in zip(paths, names):
            others = [p for p in paths if p != path]
            by_file[name], file_stats = review_file(path, hide_answers=hide_answers,
                                                    siblings=others)
            for key in ("chunks", "parse_failures", "retries", "dropped"):
                stats[key] = stats.get(key, 0) + file_stats[key]
    else:
        raise ValueError(f"{tool!r} is not a group tool")

    for name in names:
        save_scan(conn, name, tool, by_file[name])
    return {name: len(found) for name, found in by_file.items()}, stats