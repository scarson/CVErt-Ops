"""Reporting helpers, called per report-export request.

Contains planted performance issues (see expected-findings.md).
"""

import re


def total_revenue(rows):
    """Sum revenue across rows.

    PLANTED ISSUE #3 (Lane 2 — memory/allocation): materializes a full list of
    every line's revenue just to sum it once. A generator expression avoids
    building the throwaway list. With large `rows` this allocates needlessly.
    """
    line_revenues = [row["qty"] * row["price"] for row in rows]   # full list, used once
    return sum(line_revenues)


def render_csv(rows):
    """Render rows to a CSV string.

    PLANTED ISSUE #4 (Lane 2/1 — allocation in hot loop): builds the output by
    repeated string concatenation (`out += ...`), which reallocates the growing
    string on every iteration. ''.join(...) over a list/generator is the idiom.
    """
    out = ""
    for row in rows:
        out += f"{row['id']},{row['name']},{row['price']}\n"   # quadratic string growth
    return out


def extract_codes(lines):
    """Pull product codes out of free-text lines.

    PLANTED ISSUE #5 (Lane 1 — recomputed work in loop): re.compile() is called
    on every iteration. The compiled pattern is loop-invariant and should be
    hoisted (or module-level). Reached per line of potentially large input.
    """
    codes = []
    for line in lines:
        pattern = re.compile(r"[A-Z]{3}-\d{4}")   # recompiled every iteration
        m = pattern.search(line)
        if m:
            codes.append(m.group(0))
    return codes
