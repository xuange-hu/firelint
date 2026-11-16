"""Packaging contract: what the wheel promises must stay true.

The zero-dependency claim is about what `pip install firelint` pulls in, and
the console scripts must stay importable with no extras installed.
"""

import ast
import importlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Modules that would break the zero-dependency claim if imported at module
# scope by a console-script entry point.
THIRD_PARTY = {"mcp", "yaml", "click", "rich", "requests", "pytest"}


def _pyproject() -> str:
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        return handle.read()


def _module_source(name: str) -> str:
    path = os.path.join(ROOT, "src", "firelint", name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def test_version_matches_pyproject():
    import firelint

    match = re.search(r'(?m)^version = "([^"]+)"', _pyproject())
    assert match and match.group(1) == firelint.__version__


def test_console_scripts_resolve():
    for module_name, attr in (("cli", "main"), ("mcp_server", "main")):
        module = importlib.import_module(f"firelint.{module_name}")
        assert callable(getattr(module, attr))


def test_base_dependencies_are_empty():
    assert re.search(r"(?m)^dependencies = \[\]", _pyproject())


def test_mcp_extra_pinned_below_2():
    assert 'mcp = ["mcp>=1.2,<2"]' in _pyproject()


def test_no_module_scope_third_party_imports():
    for name in ("cli.py", "mcp_server.py", "scanner.py", "parsers.py", "rules.py", "render.py", "demo.py"):
        tree = ast.parse(_module_source(name))
        for node in tree.body:
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots = {node.module.split(".")[0]}
            else:
                continue
            assert not (roots & THIRD_PARTY), f"{name} imports {roots & THIRD_PARTY} at module scope"


def test_pypi_name_matches_project():
    assert re.search(r'(?m)^name = "firelint"', _pyproject())
