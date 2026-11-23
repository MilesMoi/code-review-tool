"""Tests for the web pages, using Flask's test client and fake tools."""

# Run from the repo root: python tests\test_app.py
import io
import logging
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

import config
import pipeline.runner as runner
from app import create_app

logging.disable(logging.CRITICAL)

with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder)
    config.DB_PATH = folder / "test.db"
    config.UPLOAD_DIR = folder / "uploads"
    config.JULIET_DIR = folder / "juliet"
    conn = sqlite3.connect(config.DB_PATH)
    conn.executescript((config.BASE_DIR / "schema.sql").read_text())
    conn.close()

    CODE = b"""int main(void)
{
    char *p = "<script>alert(1)</script>";
    return 0;
}
"""

    def fake_cppcheck(path, include_dir=None):
        return [{"source_tool": "cppcheck", "file": str(path), "line": 3, "cwe": "CWE-121",
                 "severity": "error", "message": "bad <b>thing</b>", "suggested_fix": None}]

    def fake_model(path, hide_answers=False):
        return ([{"source_tool": "llm", "file": str(path), "line": 3, "cwe": "CWE-121",
                  "severity": "high", "message": "overflow", "suggested_fix": "use strncpy"}],
                {"chunks": 1, "parse_failures": 0, "retries": 0, "dropped": 0})

    runner.run_cppcheck = fake_cppcheck
    runner.run_flawfinder = lambda path: []
    runner.review_file = fake_model

    client = create_app().test_client()

    # The home page is the form, not the old placeholder.
    page = client.get("/")
    assert page.status_code == 200 and b'name="source"' in page.data

    # Upload, scan and land on the report.
    response = client.post("/scan", data={
        "source": (io.BytesIO(CODE), "My Test.C"),
        "cppcheck": "1", "flawfinder": "1", "llm": "1"}, follow_redirects=True)
    html = response.get_data(as_text=True)
    assert response.status_code == 200 and "Report: my_test.c" in html
    assert "Suggested fix (not applied):" in html and "use strncpy" in html
    assert "1 chunk(s)" in html                       # the model's numbers are shown
    assert "<script>alert(1)</script>" not in html    # code is escaped, never run
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "bad &lt;b&gt;thing&lt;/b&gt;" in html     # tool messages are escaped too
    assert "Apply" not in html and "<button" not in html   # no button applies a fix

    # The file was saved in its own folder, with a safe lower-case name.
    saved = list(config.UPLOAD_DIR.glob("*/my_test.c"))
    assert len(saved) == 1 and saved[0].read_bytes() == CODE

    # Refusals go back to the form with a message.
    html = client.post("/scan", data={"source": (io.BytesIO(b"x"), "notes.txt"), "cppcheck": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "ends in .c" in html    # A GitHub address: the clone is faked, the rest is real.
    import app.routes as routes
    cloned = []

    def fake_clone(url, target):
        cloned.append(url)
        (target / ".git").mkdir(parents=True)
        (target / ".git" / "hidden.c").write_text("x")
        (target / "src").mkdir()
        (target / "src" / "one.c").write_bytes(CODE)
        (target / "two.c").write_bytes(CODE)
        (target / "big.c").write_bytes(b"a" * (config.MAX_UPLOAD_BYTES + 1))

    runner.review_file = fake_model
    routes.clone = fake_clone
    html = client.post("/scan", data={"repo": "https://github.com/octocat/Hello-World",
                                      "cppcheck": "1", "llm": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert cloned == ["https://github.com/octocat/Hello-World.git"]
    assert "Repository scan" in html and "Scanned 2 file(s)" in html
    assert "src/one.c" in html and "two.c" in html
    assert "hidden.c" not in html and "big.c" not in html
    assert html.count("<td>1</td>") == 4           # one Cppcheck and one model finding per file
    link = html.split('href="/report?name=')[1].split('"')[0]
    assert client.get("/report?name=" + link).status_code == 200

    html = client.post("/scan", data={"repo": "https://example.com/a/b", "cppcheck": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Use an address like" in html and len(cloned) == 1   # nothing was cloned

    def failing_clone(url, target):
        raise OSError("no network")
    routes.clone = failing_clone
    html = client.post("/scan", data={"repo": "https://github.com/a/b", "cppcheck": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Could not fetch that repository (OSError)" in html

    html = client.post("/scan", data={"cppcheck": "1"}, follow_redirects=True).get_data(as_text=True)
    assert "or give a GitHub address" in html
    html = client.post("/scan", data={"source": (io.BytesIO(CODE), "a.c")}, follow_redirects=True).get_data(as_text=True)
    assert "Pick at least one tool" in html

    big = io.BytesIO(b"a" * (config.MAX_UPLOAD_BYTES + 10))
    html = client.post("/scan", data={"source": (big, "big.c"), "cppcheck": "1"},
                       follow_redirects=True, content_type="multipart/form-data").get_data(as_text=True)
    assert "too big" in html

    # The finder lists saved reports by part of a file name, and they open.
    html = client.get("/reports?find=MY_test").get_data(as_text=True)
    assert "/my_test.c" in html and 'href="/report?name=' in html
    assert "No scanned file has that" in client.get("/reports?find=zzzzzz").get_data(as_text=True)
    html = client.get("/reports?find=ab", follow_redirects=True).get_data(as_text=True)
    assert "at least 3 characters" in html

    # A batch-scanned Juliet file opens with its code and the answer key.
    from pipeline.labels import normalize_path
    from pipeline.store import save_scan
    case = config.JULIET_DIR / "testcases" / "cwe121_x" / "cwe121_demo_case_01.c"
    case.parent.mkdir(parents=True)
    case.write_text(CODE.decode())
    key = normalize_path(case)
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("INSERT INTO ground_truth (dataset, file, function_name, start_line, end_line, cwe, is_vulnerable)"
                 " VALUES ('juliet', ?, 'main_bad', 1, 5, 'CWE-121', 1)", (key,))
    conn.commit()
    save_scan(conn, key, "cppcheck", fake_cppcheck(case))
    conn.close()
    html = client.get("/report", query_string={"name": key}).get_data(as_text=True)
    assert "Against the answer key" in html and "main_bad" in html and "1 of 1" in html
    assert "&lt;script&gt;" in html                    # the code column is there, and escaped

    # A model that cannot be reached is named, the other tools still report.
    def down(path, hide_answers=False):
        raise ConnectionError("Ollama is not running")
    runner.review_file = down
    html = client.post("/scan", data={"source": (io.BytesIO(CODE), "b.c"),
                                      "cppcheck": "1", "llm": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Model did not run" in html and "Ollama is not running" in html
    assert "Not run" in html and "Report: b.c" in html

    # A GitHub address: the clone is faked, the rest is real.
    import app.routes as routes
    cloned = []

    def fake_clone(url, target):
        cloned.append(url)
        (target / ".git").mkdir(parents=True)
        (target / ".git" / "hidden.c").write_text("x")
        (target / "src").mkdir()
        (target / "src" / "one.c").write_bytes(CODE)
        (target / "two.c").write_bytes(CODE)
        (target / "big.c").write_bytes(b"a" * (config.MAX_UPLOAD_BYTES + 1))

    runner.review_file = fake_model
    routes.clone = fake_clone
    html = client.post("/scan", data={"repo": "https://github.com/octocat/Hello-World",
                                      "cppcheck": "1", "llm": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert cloned == ["https://github.com/octocat/Hello-World.git"]
    assert "Repository scan" in html and "Scanned 2 file(s)" in html
    assert "src/one.c" in html and "two.c" in html
    assert "hidden.c" not in html and "big.c" not in html
    assert html.count("<td>1</td>") == 4           # one Cppcheck and one model finding per file
    link = html.split('href="/report?name=')[1].split('"')[0]
    assert client.get("/report?name=" + link).status_code == 200

    html = client.post("/scan", data={"repo": "https://example.com/a/b", "cppcheck": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Use an address like" in html and len(cloned) == 1   # nothing was cloned

    def failing_clone(url, target):
        raise OSError("no network")
    routes.clone = failing_clone
    html = client.post("/scan", data={"repo": "https://github.com/a/b", "cppcheck": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Could not fetch that repository (OSError)" in html

    # Unknown reports are a 404, not a crash.
    assert client.get("/report?name=c:/nothing.c").status_code == 404
    assert client.get("/report").status_code == 404
    assert client.get("/repo?name=c:/nothing").status_code == 404

print("All app tests passed")