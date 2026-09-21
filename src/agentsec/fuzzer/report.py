"""Fuzz run reporting: JSON for machines, Markdown for humans, and a CI gate."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentsec.fuzzer.harness import CaseResult, FuzzConfig, group_rate


def _cell(text: str) -> str:
    """Neutralise text that came back from the system under test before it enters a table.

    ``evidence`` quotes the target's own output, which an attacker may have steered. Left raw
    it could end the cell, add rows, or embed an image/link/HTML in a report a human or a CI
    comment bot then renders.
    """
    return (
        text.replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


@dataclass
class FuzzReport:
    generated_at: str
    seed: int
    total: int
    successes: int
    blocked: int
    errors: int
    asr: float
    by_category: dict[str, dict[str, float]]
    by_mutator: dict[str, dict[str, float]]
    by_goal: dict[str, dict[str, float]]
    by_scenario: dict[str, dict[str, float]]
    results: list[CaseResult] = field(default_factory=list)

    @classmethod
    def from_results(cls, results: list[CaseResult], config: FuzzConfig) -> FuzzReport:
        scored = [r for r in results if r.error is None]
        wins = sum(1 for r in scored if r.success)
        return cls(
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            seed=config.seed,
            total=len(results),
            successes=wins,
            blocked=sum(1 for r in results if r.blocked),
            errors=len(results) - len(scored),
            asr=round(wins / len(scored), 4) if scored else 0.0,
            by_category=group_rate(results, "category"),
            by_mutator=group_rate(results, "mutator"),
            by_goal=group_rate(results, "goal"),
            by_scenario=group_rate(results, "scenario"),
            results=results,
        )

    # ------------------------------------------------------------------ gates
    def exceeds(self, max_asr: float) -> bool:
        return self.asr > max_asr

    def bypasses(self) -> list[CaseResult]:
        return [r for r in self.results if r.success]

    # ---------------------------------------------------------------- render
    def to_dict(self, *, include_results: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if not include_results:
            d.pop("results")
        return d

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self, *, artifact_uri: str = "agent", target: str | None = None) -> str:
        """SARIF 2.1.0 JSON (GitHub code scanning). See :func:`agentsec.fuzzer.formats.to_sarif`."""
        from agentsec.fuzzer.formats import to_sarif

        return json.dumps(to_sarif(self, artifact_uri=artifact_uri, target=target), indent=2)

    def to_junit(self) -> str:
        """JUnit XML. See :func:`agentsec.fuzzer.formats.to_junit`."""
        from agentsec.fuzzer.formats import to_junit

        return to_junit(self)

    def to_markdown(self, *, max_bypasses: int = 15) -> str:
        lines = [
            "# Prompt-injection fuzz report",
            "",
            f"*Generated {self.generated_at} - seed {self.seed}*",
            "",
            f"**{self.successes} of {self.total - self.errors} attacks succeeded "
            f"(ASR {self.asr:.1%})** - {self.blocked} blocked by target defences, "
            f"{self.errors} target errors.",
            "",
        ]
        for title, table in (
            ("By attack goal", self.by_goal),
            ("By category", self.by_category),
            ("By obfuscation", self.by_mutator),
            ("By delivery", self.by_scenario),
        ):
            lines += [f"## {title}", "", "| | cases | succeeded | ASR |", "|---|---:|---:|---:|"]
            for name, row in table.items():
                lines.append(
                    f"| {name} | {int(row['cases'])} | {int(row['successes'])} | {row['asr']:.1%} |"
                )
            lines.append("")
        wins = self.bypasses()
        if wins:
            lines += [
                "## Sample successful attacks",
                "",
                "| case | hit | evidence |",
                "|---|---|---|",
            ]
            for r in wins[:max_bypasses]:
                lines.append(
                    f"| `{_cell(r.case_id)}` | {_cell(', '.join(r.hits))} | {_cell(r.evidence)} |"
                )
            if len(wins) > max_bypasses:
                lines.append(f"\n*...and {len(wins) - max_bypasses} more (see JSON report).*")
            lines.append("")
        return "\n".join(lines)
