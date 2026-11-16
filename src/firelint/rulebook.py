"""Generate docs/rules.md from the registry.

A hand-edited rule table is wrong within two commits; this is the single
source the docs contract test compares against.
"""

from __future__ import annotations

from .rules import REGISTRY


def full_markdown() -> str:
    table = sorted(REGISTRY, key=lambda item: item.id)
    counts: dict[str, int] = {}
    for item in table:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    names = ("critical", "high", "medium", "low", "note")
    breakdown = ", ".join(f"{counts[name]} {name}" for name in names if name in counts)

    out = [
        "# firelint rules",
        "",
        f"{len(table)} rules ({breakdown}), in three passes: `lines` reads one rule at a time,",
        "`chains` reads chain defaults and ordering, `relations` reads the gaps between files and families.",
        "",
    ]
    for item in table:
        out += [
            f"## {item.id}",
            "",
            f"**{item.title}**",
            "",
            f"- severity: {item.severity} (score {item.score}/10)",
            f"- pass: {item.stage}",
            "",
            item.why,
            "",
            f"**Fix:** {item.fix}",
            "",
        ]
    return "\n".join(out)
