"""Holdback streaming: release model text only once it is checked and far enough behind.

Text is released when it is more than ``hold`` characters behind the newest text, and only if
the output guard finds nothing in the window around it (the released tail plus everything
not yet released). Everything after an unclosed ``[``, ``![``, ``<`` or code fence is held,
so a link or a fenced block is checked whole.

Once the window is not clean, or the held text grows past ``8 * hold``, nothing more is
released: the rest goes out after the final check of the full text, as in buffer mode. A
secret longer than the window, or a rule that needs the whole text, can still only be caught
by that final check; the gateway then ends the stream with an error (see app.py).
"""

from __future__ import annotations

import re

from agentsec.middleware.validators import OutputGuard

FENCE = "```"
_SPACES = re.compile(r"\s+")


def unclosed(text: str, fence_open: bool) -> int:
    """Index in ``text`` of the earliest construct still open; ``len(text)`` if none."""
    cut = len(text)
    fences = text.count(FENCE)
    if fences % 2 != fence_open:  # odd overall: the last fence opened a block
        cut = text.rfind(FENCE) if fences else 0
    i = text.find("<")
    while i != -1 and i < cut:
        if _tag_end(text, i) == -1:
            cut = i
            break
        i = text.find("<", i + 1)
    i = text.find("[")
    while i != -1 and i < cut:
        close = text.find("]", i)
        link = close != -1 and text.startswith("(", close + 1)
        image = i > 0 and text[i - 1] == "!"
        if (
            close == -1
            or close + 1 == len(text)
            or (link and text.find(")", close) == -1)
            # A reference image (![a] or ![a][b]) fetches a URL defined anywhere in the
            # answer, before or after it, which no window can see: held to the final check.
            or (image and not link)
        ):
            cut = i - 1 if image else i
            break
        i = text.find("[", i + 1)
    return cut


def _tag_end(text: str, start: int) -> int:
    """The ``>`` that ends the tag opened at ``start``, skipping quoted attribute values."""
    quote = ""
    for j in range(start + 1, len(text)):
        ch = text[j]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return j
    return -1


def _behind(text: str, hold: int) -> int:
    """The index in ``text`` with ``hold`` non-whitespace characters after it.

    Counted without whitespace because ProtectedStringValidator ignores it: "A" and "B"
    100 spaces apart still match "AB", so spaces must not push "A" out of the window.
    """
    seen = 0
    for j in range(len(text) - 1, -1, -1):
        if not text[j].isspace():
            seen += 1
            if seen > hold:
                return j + 1
    return 0


class Holdback:
    def __init__(self, guard: OutputGuard, hold: int) -> None:
        self._guard = guard
        self._hold = hold
        self._cap = 8 * hold
        self._sent: list[str] = []
        self._tail = ""  # the end of the released text: context for the window check
        self._pending = ""  # received, not released, bounded by the cap
        self._overflow: list[str] = []  # once buffering: everything else, unjoined
        self._fence_open = False  # whether the released text ends inside a code fence
        self.buffering = False

    def feed(self, piece: str) -> str:
        """Add model text; return what may be released now (possibly empty)."""
        if self.buffering:
            self._overflow.append(piece)
            return ""
        self._pending += piece
        if len(self._pending) > self._cap:
            self.buffering = True
            return ""
        limit = min(_behind(self._pending, self._hold), unclosed(self._pending, self._fence_open))
        while limit > 0 and self._pending[limit - 1] == "`":
            limit -= 1  # never split a fence, so fence parity stays countable
        if limit <= 0:
            return ""
        window = self._tail + self._pending
        checked = self._guard.process(window)
        if not checked.allowed or checked.violations or checked.text != window:
            self.buffering = True  # something to redact or block: the final check decides
            return ""
        out, self._pending = self._pending[:limit], self._pending[limit:]
        self._sent.append(out)
        # Whitespace runs collapsed: 2 * hold characters then hold at least hold non-space ones.
        self._tail = _SPACES.sub(" ", self._tail + out)[-2 * self._hold :]
        self._fence_open ^= out.count(FENCE) % 2 == 1
        return out

    @property
    def released(self) -> str:
        return "".join(self._sent)

    @property
    def text(self) -> str:
        return self.released + self._pending + "".join(self._overflow)
