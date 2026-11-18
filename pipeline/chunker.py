"""
Splits C source into chunks to send to the LLM.

A chunk is cut between functions, never inside one. Each chunk holds as many
whole functions as fit in max_lines. Most Juliet files are shorter than
max_lines, so they go to the model whole.
"""

from pipeline.labels import find_functions


def chunk_lines(text, max_lines=200, first_line=1):
    """Plain fixed-size blocks. Used only where there is no function boundary
    to cut at. Returns [(start_line, chunk_text)]."""
    lines = text.splitlines(keepends=True)
    return [(first_line + i, "".join(lines[i:i + max_lines]))
            for i in range(0, len(lines), max_lines)]


def chunk_text(text, max_lines=200):
    """Split text into chunks that end at a function boundary.

    Returns [(start_line, chunk_text)]. start_line is the real line number of
    the chunk's first line, so the numbers the model reads stay correct.
    """
    lines = text.splitlines(keepends=True)
    chunks = []
    start = 1     # first line of the chunk being built
    cut = None    # last line of the newest function that still fits in it
    for _, _, last in find_functions(text):
        if last - start + 1 > max_lines:  # this function would overflow the chunk
            if cut is not None:
                chunks.append((start, "".join(lines[start - 1:cut])))
                start, cut = cut + 1, None
            if last - start + 1 > max_lines:  # it is too long even alone
                chunks += chunk_lines("".join(lines[start - 1:last]), max_lines, start)
                start, cut = last + 1, None
                continue
        cut = last
    if cut is not None and len(lines) - start + 1 > max_lines:
        chunks.append((start, "".join(lines[start - 1:cut])))
        start = cut + 1
    if start <= len(lines):  # what is left, such as trailing lines
        chunks += chunk_lines("".join(lines[start - 1:]), max_lines, start)
    return chunks


def chunk_file(filepath, max_lines=200):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return chunk_text(f.read(), max_lines)