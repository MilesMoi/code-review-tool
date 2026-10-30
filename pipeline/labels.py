"""Find functions in Juliet C files and label them vulnerable or safe."""

import re
from pathlib import Path

from pipeline.prep import strip_comments


def normalize_path(path):
    """One spelling for a path, so tool output and the answer key match."""
    return str(path).replace("\\", "/").lower()


def find_functions(source):
    """Return [(name, first_line, last_line)] for each top-level function."""
    source = strip_comments(source)  # blank lines replace comments
    functions = []
    depth = 0
    header = ""        # text since the last top-level ; or }
    header_start = None
    name = None
    for number, line in enumerate(source.splitlines(), start=1):
        if depth == 0 and line.lstrip().startswith("#"):
            continue  # preprocessor line
        for ch in line:
            if ch == "{":
                if depth == 0:
                    match = re.search(r"(\w+)\s*\(", header)
                    name = match.group(1) if match else None
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                if depth == 0:
                    if name:
                        functions.append((name, header_start, number))
                    header, header_start, name = "", None, None
            elif depth == 0:
                if ch == ";":
                    header, header_start = "", None
                else:
                    header += ch
                    if header_start is None and not ch.isspace():
                        header_start = number
        if depth == 0:
            header += " "
    return functions


def label_function(name):
    """Return 1 for a flawed function, 0 for a safe one, None for neither."""
    lower = name.lower()
    if "bad" in lower:
        return 1
    if "good" in lower:
        return 0
    return None


def cwe_from_name(filename):
    match = re.match(r"CWE(\d+)_", filename)
    return f"CWE-{int(match.group(1))}" if match else None


def load_juliet(conn, juliet_dir, cwe_prefixes):
    """Fill the ground_truth table from Juliet files. Return rows added."""
    conn.execute("DELETE FROM ground_truth WHERE dataset = 'juliet'")
    rows = 0
    for prefix in cwe_prefixes:
        pattern = f"{prefix}*/**/*.c"
        for path in sorted((Path(juliet_dir) / "testcases").glob(pattern)):
            with open(path, encoding="utf-8", errors="replace") as f:
                source = f.read()
            cwe = cwe_from_name(path.name)
            for name, first, last in find_functions(source):
                flawed = label_function(name)
                if flawed is None:
                    continue
                conn.execute(
                    "INSERT INTO ground_truth (dataset, file, function_name,"
                    " start_line, end_line, cwe, is_vulnerable)"
                    " VALUES ('juliet', ?, ?, ?, ?, ?, ?)",
                    (normalize_path(path), name, first, last, cwe, flawed),
                )
                rows += 1
    return rows