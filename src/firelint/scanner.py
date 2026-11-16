"""Scan orchestration: collect files, parse them, run the rule engine."""

from __future__ import annotations

import os

from .model import Report, Target
from .parsers import detect_format, parse
from .rules import REGISTRY, evaluate

MAX_FILE_BYTES = 5 * 1024 * 1024


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read(MAX_FILE_BYTES)


def collect(paths: list[str]) -> tuple[list[str], list[str]]:
    """Return (explicit files, discovered files). Directories are walked."""
    explicit: list[str] = []
    discovered: list[str] = []
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, names in os.walk(path):
                for name in sorted(names):
                    candidate = os.path.join(root, name)
                    if os.path.getsize(candidate) > MAX_FILE_BYTES:
                        continue
                    try:
                        text = _read(candidate)
                    except OSError:
                        continue
                    if detect_format(text, candidate):
                        discovered.append(candidate)
        else:
            explicit.append(path)
    return explicit, discovered


def scan_paths(paths: list[str] | str) -> Report:
    if isinstance(paths, str):
        paths = [paths]
    explicit, discovered = collect(list(paths))
    targets: list[Target] = []
    for path in explicit + discovered:
        if not os.path.isfile(path):
            target = Target(source=path, fmt="missing")
            target.warnings.append((1, 0, f"no such file: {path}"))
            targets.append(target)
            continue
        targets.append(parse(_read(path), path))

    findings = evaluate(targets)
    return Report(
        source=", ".join(paths),
        targets=targets,
        findings=findings,
        rules_run=len(REGISTRY),
        rule_ids=sorted(item.id for item in REGISTRY),
    )
