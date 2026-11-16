"""MCP server tests (skipped when the optional mcp extra is absent)."""

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from firelint.mcp_server import build_server, tool_manifest  # noqa: E402


def _call(name: str, arguments: dict):
    mcp = build_server()
    result = asyncio.run(mcp.call_tool(name, arguments))
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


def test_manifest_matches_registered_tools():
    tools = asyncio.run(build_server().list_tools())
    assert {t.name for t in tools} == {entry["name"] for entry in tool_manifest()}


def test_six_tools_with_descriptions():
    manifest = tool_manifest()
    assert len(manifest) == 6
    assert all(entry["description"] for entry in manifest)


def test_call_demo_tool():
    payload = _call("firelint_demo", {})
    assert payload["counts"]["critical"] >= 2
    assert payload["findings"]


def test_call_rules_tool():
    payload = _call("firelint_rules", {})
    assert len(payload) == 20
    assert payload[0]["id"] == "FWL101"


def test_call_explain_tool():
    payload = _call("firelint_explain", {"rule_id": "FWL102"})
    assert payload["severity"] == "critical"
    assert _call("firelint_explain", {"rule_id": "FWL999"})["error"]


def test_call_defaults_tool(tmp_path):
    path = tmp_path / "host.rules"
    path.write_text("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n", encoding="utf-8")
    payload = _call("firelint_defaults", {"path": str(path)})
    assert payload["policies"]["INPUT"] == "ACCEPT"
    assert payload["open_from_anywhere"]
