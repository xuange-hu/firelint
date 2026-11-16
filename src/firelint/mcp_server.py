"""MCP server: expose firelint to Claude Code / Cursor / Cline.

The `mcp` package is imported lazily so the core stays importable (and the
zero-dependency claim testable) without the optional extra installed.
"""

from __future__ import annotations

import json


def tool_manifest() -> list[dict]:
    return [
        {
            "name": "firelint_scan",
            "description": (
                "Scan firewall ruleset files (iptables-save, nft list ruleset, ufw status verbose) "
                "and return findings with line-level evidence."
            ),
            "args": "paths (list[str]), fail_on (str, default 'none')",
        },
        {
            "name": "firelint_demo",
            "description": (
                "Run the embedded demo corpus (a deliberately careless firewall) "
                "and return the findings summary."
            ),
            "args": "none",
        },
        {
            "name": "firelint_rules",
            "description": "Return the full rulebook: id, title, severity, pass, why and fix for all rules.",
            "args": "none",
        },
        {
            "name": "firelint_explain",
            "description": "Explain one rule by id (e.g. FWL102) including why it matters and how to fix it.",
            "args": "rule_id (str)",
        },
        {
            "name": "firelint_parse",
            "description": (
                "Parse one ruleset file and return its normalized chains and rules "
                "(verdicts, ports, sources) without running rules."
            ),
            "args": "path (str)",
        },
        {
            "name": "firelint_defaults",
            "description": (
                "Summarize what a ruleset allows: chain default policies and every rule "
                "that accepts traffic from anywhere."
            ),
            "args": "path (str)",
        },
    ]


def _summary(report) -> str:
    payload = {
        "source": report.source,
        "counts": report.counts,
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(payload, indent=2)


def build_server():
    from mcp.server.fastmcp import FastMCP

    from .demo import run_demo
    from .parsers import parse
    from .rules import RULES_BY_ID
    from .scanner import scan_paths

    mcp = FastMCP("firelint")

    @mcp.tool(name="firelint_scan")
    def firelint_scan(paths: list[str], fail_on: str = "none") -> str:
        """Scan ruleset files or directories; returns findings with evidence."""
        report = scan_paths(paths)
        return _summary(report)

    @mcp.tool(name="firelint_demo")
    def firelint_demo() -> str:
        """Run the embedded demo corpus and return its findings."""
        return _summary(run_demo())

    @mcp.tool(name="firelint_rules")
    def firelint_rules() -> str:
        """Return the full rulebook as JSON."""
        return json.dumps([item.__dict__ for item in sorted(RULES_BY_ID.values(), key=lambda i: i.id)], indent=2)

    @mcp.tool(name="firelint_explain")
    def firelint_explain(rule_id: str) -> str:
        """Explain one rule by id."""
        item = RULES_BY_ID.get(rule_id.upper())
        if item is None:
            return json.dumps({"error": f"unknown rule {rule_id!r}"})
        return json.dumps(item.__dict__, indent=2)

    @mcp.tool(name="firelint_parse")
    def firelint_parse(path: str) -> str:
        """Parse one ruleset file and return its normalized rules."""
        with open(path, encoding="utf-8", errors="replace") as handle:
            target = parse(handle.read(), path)
        return json.dumps(
            {
                "source": target.source,
                "format": target.fmt,
                "chains": [
                    {
                        "name": c.name,
                        "table": c.table,
                        "policy": c.policy,
                        "policy_stated": c.policy_stated,
                        "hooked": c.hooked,
                        "rules": [r.to_dict() for r in c.rules],
                    }
                    for c in target.chains
                ],
                "warnings": [{"line": line, "offset": offset, "raw": raw} for line, offset, raw in target.warnings],
            },
            indent=2,
        )

    @mcp.tool(name="firelint_defaults")
    def firelint_defaults(path: str) -> str:
        """Summarize chain default policies and world-open allows."""
        with open(path, encoding="utf-8", errors="replace") as handle:
            target = parse(handle.read(), path)
        from .model import is_any

        opens = [
            r.to_dict()
            for r in target.rules
            if r.action == "ACCEPT" and is_any(r.src) and r.inbound
        ]
        return json.dumps(
            {
                "source": target.source,
                "format": target.fmt,
                "policies": {c.name: (c.policy or "UNSTATED") for c in target.chains},
                "open_from_anywhere": opens,
            },
            indent=2,
        )

    return mcp


def main() -> None:
    mcp = build_server()
    mcp.run()


if __name__ == "__main__":
    main()
