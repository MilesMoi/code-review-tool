"""
Wraps Cppcheck and Flawfinder: runs them via subprocess and normalizes
their output into a common schema:

{
    "source_tool": "cppcheck" | "flawfinder",
    "file": str,
    "line": int,
    "cwe": str | None,
    "severity": str,
    "message": str,
}
"""

import subprocess
import xml.etree.ElementTree as ET

# TODO: fill in as checks are mapped to CWE numbers
CPPCHECK_CWE_MAP = {
    # "bufferAccessOutOfBounds": "CWE-119",
}


def run_cppcheck(filepath):
    result = subprocess.run(
        ["cppcheck", "--xml", "--enable=all", filepath],
        capture_output=True, text=True
    )

    findings = []
    root = ET.fromstring(result.stderr)  # cppcheck writes XML to stderr
    for error in root.iter("error"):
        location = error.find("location")
        if location is None:
            continue
        check_id = error.get("id")
        findings.append({
            "source_tool": "cppcheck",
            "file": location.get("file"),
            "line": int(location.get("line")),
            "cwe": CPPCHECK_CWE_MAP.get(check_id),
            "severity": error.get("severity"),
            "message": error.get("msg"),
        })
    return findings


def run_flawfinder(filepath):
    result = subprocess.run(
        ["flawfinder", "--csv", filepath],
        capture_output=True, text=True
    )

    findings = []
    lines = result.stdout.strip().split("\n")
    for line in lines[1:]:  # skip header row
        parts = line.split(",")
        if len(parts) < 7:
            continue
        findings.append({
            "source_tool": "flawfinder",
            "file": parts[0],
            "line": int(parts[1]),
            "cwe": None,  # TODO: map flawfinder risk categories to CWE
            "severity": parts[4],
            "message": parts[6],
        })
    return findings
