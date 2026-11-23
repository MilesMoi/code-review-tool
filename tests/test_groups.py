"""Tests for the multi-file helpers: finding cases, the Cppcheck command, shared
renaming and the code the model is shown from the other files."""

# Run from the repo root: python tests\test_groups.py
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

import pipeline.analyzer as analyzer
from pipeline.chunker import build_sibling_context
from pipeline.groups import case_counts, case_id, file_kind, group_key, sample_groups
from pipeline.llm_client import build_prompt
from pipeline.prep import hide_labels

# Names: one file, a part of a case, or something else.
assert file_kind("C:\\J\\CWE121_x_01.c") == "single"
assert file_kind("c:/j/cwe121_x_51a.c") == "multi"
assert file_kind("c:/j/notes.c") == "other"
assert group_key("CWE121_x_51a.c") == group_key("CWE121_x_51b.c") == "cwe121_x_51"
assert group_key("CWE121_x_01.c") is None
assert case_id("C:\\J\\s01\\CWE121_x_51a.c") == case_id("c:/j/s01/cwe121_x_51b.c") == "c:/j/s01/cwe121_x_51"
assert case_id("c:/j/s01/cwe121_x_01.c") is None

# sample_groups: only cases with two or more files, sorted, the same every time.
with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder)
    cases = folder / "testcases" / "CWE121_Stack" / "s01"
    cases.mkdir(parents=True)
    for name in ["CWE121_x_51a.c", "CWE121_x_51b.c", "CWE121_x_52a.c", "CWE121_x_52b.c",
                 "CWE121_x_52c.c", "CWE121_x_01.c", "CWE121_x_61a.c"]:
        (cases / name).write_text("int x;\n")
    (folder / "testcases" / "CWE190_Int").mkdir()
    (folder / "testcases" / "CWE190_Int" / "CWE190_y_51a.c").write_text("int y;\n")
    (folder / "testcases" / "CWE190_Int" / "CWE190_y_51b.c").write_text("int y;\n")

    everything = sample_groups(folder, ["CWE121", "CWE190"], per_cwe=10)
    shape = [[p.name for p in case] for case in everything]
    assert sorted(shape) == [["CWE121_x_51a.c", "CWE121_x_51b.c"],
                             ["CWE121_x_52a.c", "CWE121_x_52b.c", "CWE121_x_52c.c"],
                             ["CWE190_y_51a.c", "CWE190_y_51b.c"]]   # no _01, no lone 61a
    assert sample_groups(folder, ["CWE121", "CWE190"], per_cwe=10) == everything
    assert len(sample_groups(folder, ["CWE121", "CWE190"], per_cwe=1)) == 2  # one per CWE

# case_counts: a case is caught when any of its flawed functions is detected.
def fn(file, name, flawed):
    return {"file": file, "function_name": name, "is_vulnerable": flawed}

FUNCTIONS = [
    fn("c:/j/x_51a.c", "x_51_bad", 1), fn("c:/j/x_51b.c", "x_51b_badSink", 1),
    fn("c:/j/x_51b.c", "x_51b_goodSink", 0),
    fn("c:/j/x_52a.c", "x_52_bad", 1), fn("c:/j/x_52b.c", "x_52b_badSink", 1),
    fn("c:/j/x_01.c", "x_01_bad", 1),                      # a single file: not a case
]
assert case_counts(FUNCTIONS, {("c:/j/x_51b.c", "x_51b_badSink")}) == (1, 2)
assert case_counts(FUNCTIONS, {("c:/j/x_51b.c", "x_51b_goodSink")}) == (0, 2)  # a safe one does not count
assert case_counts(FUNCTIONS, {("c:/j/x_01.c", "x_01_bad")}) == (0, 2)
assert case_counts(FUNCTIONS, set()) == (0, 2)

# Cppcheck gets every path in one command when given a list.
commands = []
analyzer._run = lambda command: commands.append(command)   # records and returns None
analyzer.run_cppcheck(["a.c", "b.c"], "inc")
analyzer.run_cppcheck("single.c")
assert commands[0][-2:] == ["a.c", "b.c"] and "inc" in commands[0]
assert commands[1][-1] == "single.c" and commands[1].count("single.c") == 1

# One shared names dictionary keeps a renamed function the same in every file.
call_file = "void CWE1_51_bad() { CWE1_51b_badSink(1); }"
sink_file = "void CWE1_51b_badSink(int d) { }"
names = {}
renamed = [hide_labels(call_file, names), hide_labels(sink_file, names)]
sink_name = renamed[1].split("(")[0].split()[-1]
assert sink_name in renamed[0] and "bad" not in renamed[0] + renamed[1].lower()
alone = [hide_labels(call_file), hide_labels(sink_file)]
assert "func_2(1)" in alone[0] and "void func_1(" in alone[1]   # separate dictionaries disagree

# What the model is shown from the other files.
B = """#include "std_testcase.h"
static int limit = 10;
void sink_b(int data)
{
    sink_c(data);
}
void unrelated(int x)
{
    x = 1;
}
"""
C = """void sink_c(int data)
{
    int buffer[10];
    buffer[data] = 1;
}
"""
chunk = "void start()\n{\n    sink_b(5);\n}\n"
shown = build_sibling_context(chunk, [B, C])
assert len(shown) == 2                                     # one text for each file used
assert "static int limit = 10;" in shown[0] and "sink_b" in shown[0]
assert "unrelated" not in shown[0] and "#include" not in shown[0]
assert "buffer[data] = 1;" in shown[1]                     # found two hops away
assert not any(line[:1].isdigit() for text in shown for line in text.splitlines())  # no line numbers
assert build_sibling_context("void f() { nothing(); }", [B, C]) == []
LONG = "void sink_b(int data)\n{\n" + "    data = data + 1;\n" * 20 + "}\n"
tight = build_sibling_context(chunk, [LONG], budget=30)    # room for the header only
assert tight == ["void sink_b(int data)\n{ /* body not shown */"]
assert build_sibling_context(chunk, []) == []

# The prompt only changes when there is other-file code to show.
assert build_prompt("1: x") == "\n".join(
    ["Review the code between the CODE markers.",
     "=====BEGIN CODE=====", "1: x", "=====END CODE====="])
prompt = build_prompt("1: x", "", ["void sink() {}"])
assert "OTHER FILE come from other files" in prompt
assert prompt.index("BEGIN OTHER FILE 1") < prompt.index("BEGIN CODE")

# review_file with a sibling: the prompt carries the other file's code, with the
# answers hidden and the function names matching across the two files.
import pipeline.llm_client as llm_client

prompts = []
llm_client.ask_model = lambda prompt: prompts.append(prompt) or '{"findings": []}'
with tempfile.TemporaryDirectory() as folder:
    first, second = Path(folder) / "case_51a.c", Path(folder) / "case_51b.c"
    first.write_text("void CWE1_51_bad()\n{\n    CWE1_51b_badSink(100);\n}\n")
    second.write_text("/* FLAW: bad */\nvoid CWE1_51b_badSink(int data)\n{\n    int b[10];\n    b[data] = 1;\n}\n")
    llm_client.review_file(first, hide_answers=True, siblings=[second])
    llm_client.review_file(first, hide_answers=True)
assert len(prompts) == 2
together, alone = prompts
assert "b[data] = 1;" in together and "OTHER FILE" not in alone
assert "bad" not in together.lower() and "flaw" not in together.lower()
sink = together.split("BEGIN OTHER FILE 1=====\n")[1].split("(")[0].split()[-1]
assert f"{sink}(100)" in together.split("BEGIN CODE")[1]   # the call and the definition agree

print("All group tests passed")