"""
Splits a C source file into chunks to send to the LLM.

v1 (now): naive whole-file or fixed-line-count chunking.
v2 (later): AST-based chunking by function using pycparser or libclang,
            so each chunk sent to the LLM is a complete function.
"""


def chunk_file(filepath, max_lines=200):
    """Naive chunking: splits a file into blocks of max_lines lines each.
    Returns a list of (start_line, chunk_text) tuples.
    """
    with open(filepath, "r") as f:
        lines = f.readlines()

    chunks = []
    for i in range(0, len(lines), max_lines):
        block = lines[i:i + max_lines]
        start_line = i + 1
        chunks.append((start_line, "".join(block)))

    return chunks
