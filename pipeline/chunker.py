"""
Splits a C source file into chunks to send to the LLM.

v1 (now): fixed-line-count chunking. Most Juliet files are shorter than
          max_lines, so they go to the model whole.
v2 (later): chunk by function so each chunk is a complete function.
"""


def chunk_text(text, max_lines=200):
    """Split text into blocks of max_lines lines.
    Returns a list of (start_line, chunk_text) tuples.
    """
    lines = text.splitlines(keepends=True)
    chunks = []
    for i in range(0, len(lines), max_lines):
        block = lines[i:i + max_lines]
        chunks.append((i + 1, "".join(block)))
    return chunks


def chunk_file(filepath, max_lines=200):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return chunk_text(f.read(), max_lines)