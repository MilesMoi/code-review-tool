"""
Wraps Cppcheck and Flawfinder: runs them via subprocess and normalizes
their output into a common schema:

{
    "source_tool": "cppcheck" | "flawfinder",
    "file": str,
    "line": int,
    "cwe": str | None,      # always "CWE-123" style, or None
    "severity": str,
    "message": str,
}
"""

import csv
import logging
import subprocess
import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

TIMEOUT = 60  # seconds before a tool is given up on


def normalize_cwe(value):
    """Turn "121", "CWE-121" or "CWE-120, CWE-20" into "CWE-121" style."""
    if not value:
        return None
    first = str(value).split(",")[0]
    digits = "".join(ch for ch in first if ch.isdigit())
    if not digits or int(digits) == 0:
        return None
    return f"CWE-{int(digits)}"


def _run(command):
    """Run a tool. Return the result, or None if it timed out."""
    try:
        return subprocess.run(
            command, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning("%s timed out", command[0])
        return None


def run_cppcheck(filepath, include_dir=None):
    command = ["cppcheck", "--xml", "--enable=all",
               "--suppress=missingIncludeSystem"]
    if include_dir:
        command += ["-I", str(include_dir)]
    command.append(str(filepath))

    result = _run(command)
    if result is None or not result.stderr.strip():
        return []  # timed out, or Cppcheck printed no XML

    try:
        root = ET.fromstring(result.stderr)  # Cppcheck writes its XML to stderr
    except ET.ParseError:
        log.warning("Cppcheck gave invalid XML for %s", filepath)
        return []

    findings = []
    for error in root.iter("error"):
        if error.get("severity") == "information":
            continue  # setup notices, not code flaws
        location = error.find("location")
        if location is None:
            continue
        findings.append({
            "source_tool": "cppcheck",
            "file": location.get("file"),
            "line": int(location.get("line")),
            "cwe": normalize_cwe(error.get("cwe")),
            "severity": error.get("severity"),
            "message": error.get("msg"),
        })
    return findings


def run_flawfinder(filepath):
    result = _run(["flawfinder", "--csv", str(filepath)])
    if result is None:
        return []

    findings = []
    for row in csv.DictReader(result.stdout.splitlines()):
        try:
            line = int(row["Line"])
        except (KeyError, TypeError, ValueError):
            continue  # not a finding row
        findings.append({
            "source_tool": "flawfinder",
            "file": row["File"],
            "line": line,
            "cwe": normalize_cwe(row.get("CWEs")),
            "severity": row["Level"],
            "message": row["Warning"],
        })
    return findings