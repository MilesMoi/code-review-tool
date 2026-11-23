"""The pages: a form, the scan endpoint and the report."""

import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

import config
from pipeline.labels import normalize_path
from pipeline.report import (LABELS, TOOLS, build_repo_summary, build_report,
                             find_reports, read_source)
from pipeline.repo import c_files, clone, parse_github_url
from pipeline.runner import run_scan

bp = Blueprint("routes", __name__)

LIMIT = 30  # most saved reports listed at once


def open_db():
    return sqlite3.connect(config.DB_PATH)


def save_upload(upload):
    """Save an uploaded .c file in a new folder. Return (path, problem)."""
    name = secure_filename(upload.filename or "").lower()
    if not name.endswith(".c"):
        return None, "Upload a file that ends in .c."
    folder = Path(config.UPLOAD_DIR) / uuid4().hex
    folder.mkdir(parents=True)
    path = folder / name
    upload.save(path)
    return path, None


@bp.route("/")
def index():
    return render_template("index.html", tools=[(t, LABELS[t]) for t in TOOLS])


@bp.route("/scan", methods=["POST"])
def scan():
    tools = [tool for tool in TOOLS if request.form.get(tool)]
    if not tools:
        flash("Pick at least one tool.")
        return redirect(url_for("routes.index"))

    upload = request.files.get("source")
    if upload and upload.filename:
        path, problem = save_upload(upload)
    elif request.form.get("repo", "").strip():
        return scan_repo(tools, request.form["repo"])
    else:
        path, problem = None, "Choose a .c file to upload or give a GitHub address."
    if problem:
        flash(problem)
        return redirect(url_for("routes.index"))

    with closing(open_db()) as conn:
        result = run_scan(conn, path, tools)

    for tool, message in result["errors"].items():
        flash(f"{LABELS[tool]} did not run. {message}")
    stats = result["stats"]
    if stats:
        flash(f"Model: {stats['chunks']} chunk(s), {stats['parse_failures']} unreadable "
              f"replies, {stats['retries']} retries, {stats['dropped']} dropped findings.")
    if not result["ids"]:
        return redirect(url_for("routes.index"))
    return redirect(url_for("routes.report", name=result["name"]))


def scan_repo(tools, address):
    """Clone a public GitHub repository and scan its smallest .c files."""
    url = parse_github_url(address)
    if url is None:
        flash("Use an address like https://github.com/owner/name.")
        return redirect(url_for("routes.index"))
    folder = Path(config.UPLOAD_DIR) / uuid4().hex / "repo"
    try:
        clone(url, folder)
    except Exception as error:  # no network, no such repository, a private one
        flash(f"Could not fetch that repository ({type(error).__name__}).")
        return redirect(url_for("routes.index"))
    files = c_files(folder, config.MAX_UPLOAD_BYTES)
    if not files:
        flash("That repository has no .c files within the size limit.")
        return redirect(url_for("routes.index"))

    errors = {}
    with closing(open_db()) as conn:
        for path in files:
            errors.update(run_scan(conn, path, tools)["errors"])
    for tool, message in errors.items():
        flash(f"{LABELS[tool]} did not run. {message}")
    flash(f"Scanned {len(files)} file(s) from {url}.")
    return redirect(url_for("routes.repo", name=normalize_path(folder)))


@bp.route("/repo")
def repo():
    name = request.args.get("name", "")
    with closing(open_db()) as conn:
        files = build_repo_summary(conn, name)
    if not files:
        abort(404)
    return render_template("repo.html", name=name, files=files,
                           tools=[(t, LABELS[t]) for t in TOOLS])


@bp.route("/reports")
def reports():
    text = request.args.get("find", "").strip().lower()
    if len(text) < 3:
        flash("Type at least 3 characters of a file name.")
        return redirect(url_for("routes.index"))
    with closing(open_db()) as conn:
        names = find_reports(conn, text, LIMIT)
    return render_template("reports.html", text=text, names=names, limit=LIMIT)


@bp.route("/report")
def report():
    name = request.args.get("name", "")
    with closing(open_db()) as conn:
        data = build_report(conn, name, read_source(name))
    if data is None:
        abort(404)
    repo_name = None  # set when this file came from a repository scan
    if name.startswith(normalize_path(config.UPLOAD_DIR)) and "/repo/" in name:
        repo_name = name[:name.index("/repo/") + len("/repo")]
    return render_template("report.html", report=data, repo_name=repo_name)