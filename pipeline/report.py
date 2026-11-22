"""Collects what the report page shows for one scanned file."""

from pathlib import Path

import config
from pipeline.scorer import find_function

TOOLS = ("cppcheck", "flawfinder", "llm")
LABELS = {"cppcheck": "Cppcheck", "flawfinder": "Flawfinder", "llm": "Model"}


def load_scans(conn, name):
    """The newest scan of each tool for one input, with its findings.
    {tool: {...}}; a tool with no scan is not in the dictionary."""
    scans = {}
    for tool in TOOLS:
        row = conn.execute(
            "SELECT id, started_at, model_name, prompt_version FROM scans"
            " WHERE input_name = ? AND tool = ? ORDER BY id DESC LIMIT 1",
            (name, tool)).fetchone()
        if row is None:
            continue
        scan_id, started_at, model, prompt = row
        cursor = conn.execute(
            "SELECT file, line, cwe, severity, message, suggested_fix FROM findings"
            " WHERE scan_id = ? ORDER BY line, id", (scan_id,))
        columns = [column[0] for column in cursor.description]
        scans[tool] = {
            "id": scan_id, "started_at": started_at,
            "model": model, "prompt": prompt,
            "findings": [dict(zip(columns, values)) for values in cursor],
        }
    return scans


def load_file_functions(conn, name):
    """The labelled functions of one Juliet file. Empty for any other file."""
    cursor = conn.execute(
        "SELECT function_name, start_line, end_line, cwe, is_vulnerable"
        " FROM ground_truth WHERE dataset = 'juliet' AND file = ?"
        " ORDER BY start_line", (name,))
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, values)) for values in cursor]


def build_report(conn, name, source_lines=None):
    """Everything the page needs, or None when no scan exists for this name."""
    scans = load_scans(conn, name)
    if not scans:
        return None

    # A finding only belongs on this page's lines if it is in this file.
    # Cppcheck also reports lines in headers; those are counted, not placed.
    here = {tool: [f for f in scan["findings"]
                   if f["file"] == name and f["line"] is not None]
            for tool, scan in scans.items()}

    tools = []
    for tool in TOOLS:
        scan = scans.get(tool)
        tools.append({
            "tool": tool, "label": LABELS[tool], "ran": scan is not None,
            "count": len(here.get(tool, [])),
            "elsewhere": len(scan["findings"]) - len(here[tool]) if scan else 0,
            "started_at": scan["started_at"] if scan else None,
            "model": scan["model"] if scan else None,
            "prompt": scan["prompt"] if scan else None,
        })

    lines = sorted({f["line"] for findings in here.values() for f in findings})
    rows = []
    for line in lines:
        code = None
        if source_lines and 1 <= line <= len(source_lines):
            code = source_lines[line - 1]
        rows.append({
            "line": line, "code": code,
            "cells": {tool: [f for f in here.get(tool, []) if f["line"] == line]
                      for tool in TOOLS},
        })

    function_rows, summary = None, None
    functions = load_file_functions(conn, name)
    if functions:
        indexed = list(enumerate(functions))
        counts = {tool: [0] * len(functions) for tool in scans}
        for tool in scans:
            for finding in here[tool]:
                index = find_function(finding, indexed)  # the scorer's own rule
                if index is not None:
                    counts[tool][index] += 1
        function_rows = [{
            "name": fn["function_name"], "start": fn["start_line"],
            "end": fn["end_line"], "cwe": fn["cwe"],
            "flawed": bool(fn["is_vulnerable"]),
            "flags": {tool: counts[tool][i] for tool in scans},
        } for i, fn in enumerate(functions)]
        flawed = [row for row in function_rows if row["flawed"]]
        safe = [row for row in function_rows if not row["flawed"]]
        summary = {tool: {
            "flawed": len(flawed),
            "detected": sum(1 for row in flawed if row["flags"][tool]),
            "safe": len(safe),
            "false_alarms": sum(1 for row in safe if row["flags"][tool]),
        } for tool in scans}

    return {"name": name, "short_name": name.rsplit("/", 1)[-1], "tools": tools,
            "rows": rows, "functions": function_rows, "summary": summary,
            "has_code": source_lines is not None}


def is_inside(path, folder):
    """True if path is the folder or somewhere below it."""
    try:
        Path(path).resolve().relative_to(Path(folder).resolve())
        return True
    except (ValueError, OSError):
        return False


def read_source(name):
    """The lines of a scanned file for display, or None when it is gone or is
    not one of ours. Only uploads and Juliet files are ever read."""
    path = Path(name)
    if not (is_inside(path, config.UPLOAD_DIR) or is_inside(path, config.JULIET_DIR)):
        return None
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace").splitlines()