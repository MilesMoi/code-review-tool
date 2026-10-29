"""
Reconciles findings from different sources (cppcheck, flawfinder, llm) and
scores them against ground truth to compute precision/recall/F1.
"""


def is_match(finding_a, finding_b, line_tolerance=3):
    same_file = finding_a["file"] == finding_b["file"]
    close_line = abs(finding_a["line"] - finding_b["line"]) <= line_tolerance
    same_cwe = finding_a.get("cwe") == finding_b.get("cwe")
    return same_file and close_line and same_cwe


def score_against_ground_truth(findings, ground_truth, line_tolerance=3):
    """Returns precision, recall, f1 for a list of findings against labeled
    ground truth rows: [{"file", "line", "cwe", "is_vulnerable"}, ...]
    """
    true_positives = 0
    false_positives = 0

    matched_truth_ids = set()

    for f in findings:
        matched = False
        for i, gt in enumerate(ground_truth):
            if i in matched_truth_ids:
                continue
            if not gt["is_vulnerable"]:
                continue
            same_file = f["file"] == gt["file"]
            close_line = abs(f["line"] - gt["line"]) <= line_tolerance
            same_cwe = f.get("cwe") == gt.get("cwe")
            if same_file and close_line and same_cwe:
                matched = True
                matched_truth_ids.add(i)
                break
        if matched:
            true_positives += 1
        else:
            false_positives += 1

    total_vulnerable = sum(1 for gt in ground_truth if gt["is_vulnerable"])
    false_negatives = total_vulnerable - len(matched_truth_ids)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return {"precision": precision, "recall": recall, "f1": f1}
