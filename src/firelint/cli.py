"""Command line interface: scan, rules, demo, explain."""

from __future__ import annotations

import argparse
import sys

from .__about__ import __version__
from .demo import run_demo
from .render import render
from .rules import REGISTRY, RULES_BY_ID
from .scanner import scan_paths

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "note", "none")


def _emit(report, args) -> int:
    fmt = getattr(args, "format", "text")
    quiet = getattr(args, "quiet", False)
    sys.stdout.write(render(report, fmt=fmt, quiet=quiet) + "\n")
    return 1 if report.should_fail(getattr(args, "fail_on", "none")) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firelint",
        description="Zero-dependency firewall ruleset auditor (iptables, nftables, ufw).",
    )
    parser.add_argument("--version", action="version", version=f"firelint {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan ruleset files or directories")
    scan.add_argument("paths", nargs="+", help="ruleset file(s) or directory(ies)")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="none",
        help="exit 1 when a finding at or above this severity exists",
    )
    scan.add_argument("--quiet", action="store_true", help="hide fix hints")

    rules = sub.add_parser("rules", help="print the rulebook")
    rules.add_argument("--rule", default="", help="only this rule id")
    rules.add_argument("--format", choices=("text", "json"), default="text")

    demo = sub.add_parser("demo", help="run the embedded demo corpus (no arguments needed)")
    demo.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    demo.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="none")
    demo.add_argument("--quiet", action="store_true")

    explain = sub.add_parser("explain", help="explain one rule")
    explain.add_argument("rule_id", help="e.g. FWL102")
    return parser


def _print_rule(item) -> None:
    sys.stdout.write(f"{item.id}  {item.title}\n")
    sys.stdout.write(f"  severity: {item.severity} (score {item.score}/10)  pass: {item.stage}\n")
    sys.stdout.write(f"  why: {item.why}\n")
    sys.stdout.write(f"  fix: {item.fix}\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _emit(scan_paths(args.paths), args)
    if args.command == "demo":
        return _emit(run_demo(), args)
    if args.command == "rules":
        if args.format == "json":
            import json

            wanted = [RULES_BY_ID[args.rule]] if args.rule else REGISTRY
            sys.stdout.write(json.dumps([item.__dict__ for item in wanted], indent=2) + "\n")
            return 0
        if args.rule:
            item = RULES_BY_ID.get(args.rule.upper())
            if item is None:
                sys.stderr.write(f"firelint: unknown rule {args.rule!r}\n")
                return 2
            _print_rule(item)
            return 0
        for item in sorted(REGISTRY, key=lambda i: i.id):
            sys.stdout.write(f"{item.id}  [{item.severity}] {item.title}\n")
        return 0
    if args.command == "explain":
        item = RULES_BY_ID.get(args.rule_id.upper())
        if item is None:
            sys.stderr.write(f"firelint: unknown rule {args.rule_id!r}\n")
            return 2
        _print_rule(item)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
