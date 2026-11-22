"""Runs the tools on one file and saves each result. The web app and the
command line both call run_scan, so there is one way to scan a file."""

import logging

from pipeline.analyzer import run_cppcheck, run_flawfinder
from pipeline.labels import normalize_path
from pipeline.llm_client import review_file
from pipeline.store import save_scan

log = logging.getLogger(__name__)

ALL_TOOLS = ("cppcheck", "flawfinder", "llm")


def run_scan(conn, path, tools=ALL_TOOLS, include_dir=None, hide_answers=False):
    """Scan one file with the chosen tools and save one scan for each.

    Returns a dictionary:
      name    the saved input name, which the report page looks scans up by
      ids     {tool: scan id} for the tools that ran
      counts  {tool: number of findings}
      stats   the model's chunk, retry and parse numbers, or None
      errors  {tool: message} for tools that failed

    A tool that fails is skipped and nothing is saved for it, so an empty
    scan always means "ran and found nothing", never "did not run".
    """
    name = normalize_path(path)
    result = {"name": name, "ids": {}, "counts": {}, "stats": None, "errors": {}}
    for tool in tools:
        try:
            if tool == "cppcheck":
                findings = run_cppcheck(path, include_dir)
            elif tool == "flawfinder":
                findings = run_flawfinder(path)
            elif tool == "llm":
                findings, result["stats"] = review_file(path, hide_answers=hide_answers)
            else:
                raise ValueError(f"unknown tool {tool!r}")
        except Exception as error:  # tool missing, Ollama stopped, bad input
            message = f"{type(error).__name__}: {str(error)[:200]}"
            log.warning("%s failed on %s. %s", tool, path, message)
            result["errors"][tool] = message
            continue
        result["ids"][tool] = save_scan(conn, name, tool, findings)
        result["counts"][tool] = len(findings)
    return result