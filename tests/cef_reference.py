"""A reference CEF parser written from the escaping rules, for tests and the fuzz targets.

It is deliberately independent of :mod:`agentsec.middleware.cef`: if the formatter and this
parser ever disagree about where a field ends, a value has escaped its field.
"""

from __future__ import annotations

import re

# Every extension key ``format_cef`` can emit. A parsed line containing any other key means a
# value forged one.
ALLOWED_EXTENSION_KEYS = {
    "rt",
    "externalId",
    "suser",
    "deviceExternalId",
    "act",
    "cs1",
    "cs1Label",
    "cs2",
    "cs2Label",
    "cs3",
    "cs3Label",
    "cs4",
    "cs4Label",
    "cs5",
    "cs5Label",
    "msg",
}


def unescape(raw: str) -> str:
    out, i = [], 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append({"n": "\n", "r": "\r"}.get(nxt, nxt))
            i += 2
        else:
            out.append(raw[i])
            i += 1
    return "".join(out)


def parse_cef(line: str) -> tuple[list[str], dict[str, str]]:
    """Header fields (unescaped) and extension key/values, per the CEF escaping rules."""
    assert "\n" not in line and "\r" not in line, "a CEF event must be one line"
    fields: list[str] = []
    cur: list[str] = []
    i = 0
    while len(fields) < 7:
        ch = line[i]
        if ch == "\\":
            cur.append(line[i + 1])
            i += 2
        elif ch == "|":
            fields.append("".join(cur))
            cur = []
            i += 1
        else:
            cur.append(ch)
            i += 1
    extension = line[i:]
    keys = list(re.finditer(r"(?:^| )([A-Za-z][A-Za-z0-9_]*)=", extension))
    values: dict[str, str] = {}
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(extension)
        values[m.group(1)] = unescape(extension[m.end() : end])
    return fields, values
