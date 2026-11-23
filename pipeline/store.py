"""Saves a tool's findings to SQLite. Model and prompt are recorded automatically."""

import hashlib
from datetime import datetime, timezone

from config import MODEL
from pipeline.labels import normalize_path
from pipeline.llm_client import PROMPT_VERSION, SYSTEM_PROMPT

# The label you set by hand, plus a fingerprint of the real prompt text.
# If you edit the prompt and forget to change PROMPT_VERSION, the
# fingerprint still changes, so two different prompts never look the same.
PROMPT_FINGERPRINT = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:8]


def save_scan(conn, input_name, tool, findings):
    """Save one run of one tool. Return the scan id."""
    is_llm = tool.startswith("llm")  # llm and llm_group
    cursor = conn.execute(
        "INSERT INTO scans (started_at, input_name, tool, model_name, prompt_version)"
        " VALUES (?, ?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            input_name,
            tool,
            MODEL if is_llm else None,
            f"{PROMPT_VERSION}-{PROMPT_FINGERPRINT}" if is_llm else None,
        ),
    )
    scan_id = cursor.lastrowid
    for f in findings:
        conn.execute(
            "INSERT INTO findings"
            " (scan_id, source_tool, file, line, cwe, severity, message, suggested_fix)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, f["source_tool"], normalize_path(f["file"]), f["line"],
             f["cwe"], f["severity"], f["message"], f.get("suggested_fix")),
        )
    conn.commit()
    return scan_id