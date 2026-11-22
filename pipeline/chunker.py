"""
Splits C source into chunks to send to the LLM, and finds the code each chunk
depends on.

A chunk is cut between functions, never inside one. Each chunk holds as many
whole functions as fit in max_lines. Most Juliet files are shorter than
max_lines, so they go to the model whole.

Each chunk can also come with read-only context: the declarations at the top
of the file, and the functions in the same file that the chunk calls.
"""

import re

from pipeline.labels import find_functions
from pipeline.prep import strip_comments

CONTEXT_TOKENS = 1500    # the most tokens of context added to one chunk
DECLARATION_LINES = 40   # the most top-of-file lines kept as context
CALL = re.compile(r"\b(\w+)\s*\(")  # a name followed by an opening bracket


def estimate_tokens(text):
    """A rough count. C code averages about three characters per token."""
    return len(text) // 3 + 1


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


def signature_end(lines, first, last):
    """The line where a function's header ends: the first line with a {."""
    for number in range(first, min(last, first + 4) + 1):
        if "{" in lines[number - 1]:
            return number
    return first


def build_context(text, start, end, budget=CONTEXT_TOKENS):
    """Return [(line_number, line_text)] for the code outside lines start-end
    that helps in reading them: declarations first, then called functions."""
    lines = text.splitlines()
    clean = strip_comments(text).splitlines()  # comments blanked, same numbers
    functions = find_functions(text)

    inside = set()  # every line that belongs to a function
    for _, first, last in functions:
        inside.update(range(first, last + 1))
    outside = {name: (first, last) for name, first, last in functions
               if last < start or first > end}  # a repeated name keeps its last copy

    context, used = {}, 0

    # Declarations: macros, types and globals above the chunk, nearest first.
    # Blank lines and #if / #endif lines say nothing about the code, so skip them.
    skip = ("#if", "#else", "#elif", "#endif")
    declarations = [n for n in range(1, start)
                    if n not in inside and clean[n - 1].strip()
                    and not clean[n - 1].lstrip().startswith(skip)]
    for number in declarations[-DECLARATION_LINES:]:
        context[number] = lines[number - 1]
    used += estimate_tokens("\n".join(context.values()))

    # Functions the chunk calls, then the functions those call: two levels.
    chunk_code = "\n".join(clean[start - 1:end])
    wanted, seen, order = set(CALL.findall(chunk_code)), set(), []
    for _ in range(2):
        found = sorted((n for n in wanted if n in outside and n not in seen),
                       key=lambda n: outside[n][0])
        wanted = set()
        for name in found:
            seen.add(name)
            order.append(name)
            first, last = outside[name]
            wanted |= set(CALL.findall("\n".join(clean[first - 1:last])))

    for name in order:
        first, last = outside[name]
        body = {n: lines[n - 1] for n in range(first, last + 1)}
        cost = estimate_tokens("\n".join(body.values()))
        if used + cost > budget:  # too long: keep only the header
            head = signature_end(lines, first, last)
            body = {n: lines[n - 1] for n in range(first, head + 1)}
            body[head] = body[head].rstrip() + " /* body not shown */"
            cost = estimate_tokens("\n".join(body.values()))
            if used + cost > budget:
                continue
        context.update(body)
        used += cost
    return sorted(context.items())


def chunk_with_context(text, max_lines=200, budget=CONTEXT_TOKENS):
    """Like chunk_text, but returns [(start_line, chunk_text, context)]."""
    result = []
    for start, chunk in chunk_text(text, max_lines):
        end = start + len(chunk.splitlines()) - 1
        result.append((start, chunk, build_context(text, start, end, budget)))
    return result