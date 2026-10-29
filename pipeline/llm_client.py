"""
Sends code chunks to a locally hosted LLM via Ollama and parses the response
into the same normalized finding schema used by analyzer.py.
"""

import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "codellama"  # swap to "phi3" for a lighter model

SYSTEM_PROMPT = """You are a C security reviewer. Identify vulnerabilities in the
given code: buffer overflows, use-after-free, format string bugs, integer
overflows, unchecked input, and similar memory-safety issues.

Respond ONLY with valid JSON in this exact schema, no other text:
{
  "findings": [
    {
      "line": <int>,
      "cwe": "<CWE-XXX>",
      "severity": "<low|medium|high>",
      "explanation": "<short explanation>",
      "suggested_fix": "<short suggested fix>"
    }
  ]
}

If there are no vulnerabilities, respond with {"findings": []}.
"""


def review_chunk(code_text, filepath, start_line=1):
    prompt = f"{SYSTEM_PROMPT}\n\nCode to review:\n{code_text}"

    response = requests.post(OLLAMA_URL, json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    })
    response.raise_for_status()
    raw_output = response.json().get("response", "")

    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError:
        # TODO: add retry/repair logic here - log the raw output for review
        return []

    findings = []
    for f in parsed.get("findings", []):
        findings.append({
            "source_tool": "llm",
            "file": filepath,
            "line": f.get("line", start_line),
            "cwe": f.get("cwe"),
            "severity": f.get("severity"),
            "message": f.get("explanation"),
        })
    return findings
