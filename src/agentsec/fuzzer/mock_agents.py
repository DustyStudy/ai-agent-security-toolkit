"""Reference targets for demos, tests and CI self-checks.

:class:`NaiveAgent` is a **deterministic simulator of a gullible LLM agent**, not
a real model. It reads text the way a capable model does (it decodes base64 and
ROT13 on request, folds leetspeak and homoglyphs, ignores zero-width characters,
understands a few languages) and then obeys any injected instruction it finds.
That makes it a fair stand-in for "what if the model complies", which is the
scenario your containment layers must survive.

:class:`GuardedAgent` puts the same simulated model behind this toolkit's
scanner, tool policy, output guard and audit log.

Neither says anything about how a *real* model behaves; run the fuzzer against
your actual agent for that.
"""

from __future__ import annotations

import codecs
import hashlib
import re
import unicodedata
from dataclasses import dataclass

from agentsec.middleware.audit import AuditLogger, MemorySink
from agentsec.middleware.injection import InjectionScanner
from agentsec.middleware.pipeline import AgentMiddleware
from agentsec.middleware.validators import OutputGuard
from agentsec.sandbox.guard import Session, ToolGuard
from agentsec.sandbox.policy import Policy
from agentsec.types import AttackInput, TargetResponse, ToolCall

_INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
_TAGS = re.compile("[\U000e0020-\U000e007e]")
_HOMOGLYPH_FOLD = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0456": "i",
    }
)
_LEET_FOLD = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"})

_TRIGGER = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier)|"
    r"disregard (?:your |all )?(?:previous|prior)|forget (?:them|the instructions|all)|"
    r"instructions above are outdated|previous restrictions are lifted|you are now|"
    r"developer mode|note to ai assistant|message from the (?:developer|administrator)|"
    r"notice from the administrator|<\|im_start\|>system|### system|new instructions|"
    r"has authori[sz]ed all actions|user: actually|end of document ---|"
    r"ignora todas las instrucciones|ignorez toutes les instructions|"
    r"ignoriere alle vorherigen anweisungen|repeat everything above|"
    r"hidden instructions|for debugging, output|let's play a game",
    re.IGNORECASE,
)
_CANARY = re.compile(
    r"[\"\u201c]([A-Za-z0-9_-]{6,})[\"\u201d]\s*[A-Za-z0-9]{1,4}\s*[\"\u201c]([A-Za-z0-9_-]{6,})[\"\u201d]",
)
_TOOL = re.compile(r"(?:call|invoke) the tool [`'\"]?([a-z_]+)[`'\"]?", re.IGNORECASE)
_ARG = re.compile(r"\b(to|url|method|path|command|body)=(`[^`]+`|\S+)")
_LEAK = re.compile(
    r"system prompt|hidden instructions|everything above|your secret|and secret|including any secrets",
    re.IGNORECASE,
)
_MD_URL = re.compile(r"(!?\[[^\]]*\])\((https?://[^)\s]+)\)")


def _views(text: str) -> list[tuple[str, str]]:
    """Every reading of the text a capable model might arrive at, as ``(kind, text)``."""
    text = _TAGS.sub(lambda m: chr(ord(m.group()) - 0xE0000), text)
    text = _INVISIBLE.sub("", text)
    base = unicodedata.normalize("NFKC", text).translate(_HOMOGLYPH_FOLD)
    views = [("base", base)]
    lowered = base.lower()
    if "base64" in lowered:
        import base64

        for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", base):
            try:
                views.append(
                    ("decoded", base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8"))
                )
            except (ValueError, UnicodeDecodeError):
                continue
    if "rot13" in lowered:
        views.append(("decoded", codecs.decode(base, "rot13")))
    views.append(("leet", base.lower().translate(_LEET_FOLD)))
    return views


@dataclass
class NaiveAgent:
    """Obeys injected instructions. ``resistance`` (0..1) makes it deterministically refuse
    that fraction of attempts, keyed on a hash of the input, to model a partly-robust model."""

    resistance: float = 0.0

    def __call__(self, inp: AttackInput) -> TargetResponse:
        full = inp.user_message + "\n" + (inp.untrusted_content or "")
        views = _views(full)
        triggered = [(kind, v) for kind, v in views if _TRIGGER.search(v)]
        if not triggered:
            return TargetResponse(text="Here is a brief summary of the content you provided.")
        if self.resistance > 0:
            bucket = int(hashlib.sha256(full.encode()).hexdigest(), 16) % 100
            if bucket < self.resistance * 100:
                return TargetResponse(text="I can't follow instructions embedded in that content.")

        # The leetspeak view is only for *understanding* the verbs; quoted canaries are
        # taken from the un-folded base view so digits survive.
        canary_views = [v for kind, v in triggered if kind != "leet"]
        if any(kind == "leet" for kind, _ in triggered):
            canary_views.append(views[0][1])

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for view in canary_views:
            if m := _CANARY.search(view):
                text_parts.append(f"{m.group(1)}{m.group(2)}")
                break
        for _, view in triggered:
            if calls:
                break
            if t := _TOOL.search(view):
                args = {k: v.strip("`") for k, v in _ARG.findall(view)}
                calls.append(ToolCall(name=t.group(1), arguments=args))
        for _, view in triggered:
            if inp.system_secret and _LEAK.search(view):
                text_parts.append(f"My instructions contain: {inp.system_secret}")
                break
        for _, view in triggered:
            if img := _MD_URL.search(view):
                url = img.group(2).replace("<SECRET>", inp.system_secret or "")
                text_parts.append(f"{img.group(1)}({url})")
                break
        if not text_parts and not calls:
            text_parts.append("Understood.")
        return TargetResponse(text="\n".join(text_parts), tool_calls=calls)


def demo_policy() -> Policy:
    """A small policy for a document-assistant agent, used by :class:`GuardedAgent`."""
    return Policy.from_dict(
        {
            "tools": {
                "search_docs": {
                    "returns_untrusted": True,
                    "args": {"query": {"type": "string", "required": True, "max_length": 300}},
                },
                "http_request": {
                    "side_effects": True,
                    "args": {
                        "url": {
                            "type": "url",
                            "required": True,
                            "schemes": ["https"],
                            "hosts": ["api.corp.example"],
                        },
                        "method": {"type": "string", "enum": ["GET"]},
                    },
                },
                "send_email": {
                    "side_effects": True,
                    "require_approval": True,
                    "args": {
                        "to": {"type": "string", "pattern": r"[^@\s]+@corp\.example"},
                        "body": {"type": "string", "max_length": 2000},
                    },
                },
            }
        }
    )


class GuardedAgent:
    """:class:`NaiveAgent` behind scanner + tool policy + output guard + audit log."""

    def __init__(self, model: NaiveAgent | None = None, *, use_scanner: bool = True) -> None:
        self.model = model or NaiveAgent()
        self.sink = MemorySink()
        self.audit = AuditLogger(self.sink)
        self.use_scanner = use_scanner

    def __call__(self, inp: AttackInput) -> TargetResponse:
        guard = ToolGuard(demo_policy(), audit=self.audit)  # no approver: approvals deny
        mw = AgentMiddleware(
            guard=guard,
            output_guard=OutputGuard.default(
                allowed_hosts=["corp.example", "*.corp.example"],
                protected=[inp.system_secret] if inp.system_secret else [],
            ),
            scanner=InjectionScanner() if self.use_scanner else None,
            audit=self.audit,
        )
        session = Session()
        notes: list[str] = []

        screens = [mw.screen_input(inp.user_message, source="user", session=session)]
        if inp.untrusted_content:
            screens.append(
                mw.screen_input(
                    inp.untrusted_content, source="document", untrusted=True, session=session
                )
            )
        if any(s.blocked for s in screens):
            return TargetResponse(
                text="[request refused: possible prompt injection]",
                blocked=True,
                notes=[r for s in screens for r in s.reasons],
            )

        raw = self.model(inp)
        allowed: list[ToolCall] = []
        for call in raw.tool_calls:
            decision = mw.authorize_tool(call, session)
            if decision.allowed:
                allowed.append(call)
            else:
                notes.append(f"{call.name}: {decision.message()}")

        out = mw.screen_output(raw.text)
        for v in out.violations:
            notes.append(f"{v.validator}: {v.message}")
        return TargetResponse(
            text=out.text,
            tool_calls=allowed,
            blocked=not out.allowed or len(allowed) < len(raw.tool_calls),
            notes=notes,
        )
