"""Scores findings against the answer key, one labelled function at a time."""


def find_function(finding, functions_in_file):
    """Return the index of the labelled function that contains the finding's
    line, or None. This is the only place the matching rule lives."""
    line = finding["line"]
    if line is None:
        return None
    for index, fn in functions_in_file:
        if fn["start_line"] <= line <= fn["end_line"]:
            return index
    return None


def ratio(top, bottom):
    return top / bottom if bottom else None


def score(findings, functions):
    """Score one tool's findings.

    findings:  [{"file", "line", "cwe"}, ...] with normalized file paths.
    functions: the labelled functions of the files the tool was run on:
               [{"file", "function_name", "start_line", "end_line",
                 "cwe", "is_vulnerable"}, ...]
    """
    by_file = {}
    for index, fn in enumerate(functions):
        by_file.setdefault(fn["file"], []).append((index, fn))

    hits = {}  # function index -> the set of CWEs reported inside it
    unscored = 0
    for finding in findings:
        index = find_function(finding, by_file.get(finding["file"], []))
        if index is None:
            unscored += 1  # outside every labelled function: not scored
        else:
            hits.setdefault(index, set()).add(finding["cwe"])

    flawed = [i for i, fn in enumerate(functions) if fn["is_vulnerable"]]
    safe = [i for i, fn in enumerate(functions) if not fn["is_vulnerable"]]
    detected = [i for i in flawed if i in hits]
    right_cwe = [i for i in detected if functions[i]["cwe"] in hits[i]]
    false_alarms = [i for i in safe if i in hits]

    tp, fp = len(detected), len(false_alarms)
    fn_count = len(flawed) - tp
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, len(flawed))
    if recall is None:
        f1 = None
    elif tp == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "flawed": len(flawed), "safe": len(safe),
        "tp": tp, "fp": fp, "fn": fn_count,
        "right_cwe": len(right_cwe),
        "precision": precision, "recall": recall, "f1": f1,
        "recall_cwe": ratio(len(right_cwe), len(flawed)),
        "fp_rate": ratio(fp, len(safe)),
        "unscored": unscored,
        "detected_keys": {(functions[i]["file"], functions[i]["function_name"])
                          for i in detected},
    }


def score_by_cwe(findings, functions):
    """Return {"ALL": result, "CWE-121": result, ...}."""
    results = {"ALL": score(findings, functions)}
    for cwe in sorted({fn["cwe"] for fn in functions}, key=str):
        subset = [fn for fn in functions if fn["cwe"] == cwe]
        files = {fn["file"] for fn in subset}
        results[cwe] = score([f for f in findings if f["file"] in files], subset)
    return results


def compare_tools(results):
    """results = {tool: score result}. Return (agreement, unique), where
    agreement counts flawed functions found by two or more tools and
    unique[tool] counts those found by that tool alone."""
    found_by = {}
    for tool, result in results.items():
        for key in result["detected_keys"]:
            found_by.setdefault(key, []).append(tool)
    agreement = sum(1 for tools in found_by.values() if len(tools) >= 2)
    unique = {tool: 0 for tool in results}
    for tools in found_by.values():
        if len(tools) == 1:
            unique[tools[0]] += 1
    return agreement, unique


def load_functions(conn, dataset="juliet"):
    """Every labelled function of one dataset, from the ground_truth table."""
    cursor = conn.execute(
        "SELECT file, function_name, start_line, end_line, cwe, is_vulnerable"
        " FROM ground_truth WHERE dataset = ?", (dataset,))
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor]


def latest_scans(conn, tool, prompt_version=None):
    """Return {input_name: scan_id}, the newest scan of a tool for each input."""
    sql = "SELECT id, input_name FROM scans WHERE tool = ?"
    args = [tool]
    if prompt_version:
        sql += " AND prompt_version = ?"
        args.append(prompt_version)
    rows = conn.execute(sql + " ORDER BY id", args)
    return {name: scan_id for scan_id, name in rows}  # a later id replaces an earlier one


def load_findings(conn, scan_ids):
    """The saved findings that belong to the given scans."""
    wanted = set(scan_ids)
    rows = conn.execute("SELECT scan_id, file, line, cwe FROM findings")
    return [{"file": file, "line": line, "cwe": cwe}
            for scan_id, file, line, cwe in rows if scan_id in wanted]