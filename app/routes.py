from flask import Blueprint, render_template_string

bp = Blueprint("routes", __name__)


@bp.route("/")
def index():
    # TODO: replace with a real template and a form for repo URL / dataset selection
    return render_template_string("<h1>AI-Assisted Code Review Tool</h1><p>Frontend coming soon.</p>")


@bp.route("/scan", methods=["POST"])
def run_scan():
    # TODO: accept a GitHub repo URL or dataset selection,
    # call the pipeline modules (chunker -> analyzer + llm_client -> comparison),
    # store results via the db, and return/render the report
    return "Scan endpoint not yet implemented", 501
