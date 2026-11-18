"""Tests for the function-based chunker."""

# Run from the repo root: python tests\test_chunker.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

from pipeline.chunker import chunk_text


def function(name, total_lines):
    body = "".join(f"    x = {i};\n" for i in range(total_lines - 3))
    return f"void {name}(void)\n{{\n{body}}}\n"


def starts(chunks):
    return [start for start, _ in chunks]


# Line 1 is an include. Four functions of 10 lines follow: lines 2-11, 12-21,
# 22-31 and 32-41.
source = ("#include <stdio.h>\n" + function("a", 10) + function("b", 10)
          + function("c", 10) + function("d", 10))

# Room for 25 lines: a and b fit together (lines 1-21), c and d fit together.
chunks = chunk_text(source, max_lines=25)
assert starts(chunks) == [1, 22]
assert "".join(text for _, text in chunks) == source   # nothing lost or repeated
for _, text in chunks:
    assert text.count("{") == text.count("}")          # no function cut in half

# A short file stays in one piece.
assert chunk_text(source, max_lines=200) == [(1, source)]

# One function longer than max_lines is cut by lines, as a last resort.
big = function("big", 30)
assert starts(chunk_text(big, max_lines=25)) == [1, 26]

# Text with no functions is cut by lines too.
assert starts(chunk_text("int x;\n" * 60, max_lines=25)) == [1, 26, 51]

assert chunk_text("") == []

print("All chunker tests passed")