"""Helpers that hide the answers in Juliet files before the model sees them."""

import re


def strip_comments(source):
    # Replace each comment with blank lines so line numbers do not move.
    def blank(match):
        return "\n" * match.group(0).count("\n")
    return re.sub(r"/\*.*?\*/|//[^\n]*", blank, source, flags=re.DOTALL)


def hide_labels(source):
    # Give every labelled name a neutral one: func_1, func_2, ...
    names = {}
    def rename(match):
        word = match.group(0)
        if word not in names:
            names[word] = f"func_{len(names) + 1}"
        return names[word]
    return re.sub(r"\b(?:CWE\d+\w*|good\w*|bad\w*|OMIT(?:BAD|GOOD))\b", rename, source)