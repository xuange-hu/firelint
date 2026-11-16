"""CLI tests: exit codes, output formats and the rulebook commands."""

import json

import pytest

from firelint.cli import build_parser, main

CLEAN_NFT = """\
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state invalid drop
		ct state established,related accept
		ip saddr 10.0.0.0/8 tcp dport 22 accept
	}
}
"""

BAD_IPTABLES = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
"""


@pytest.fixture()
def clean(tmp_path):
    path = tmp_path / "clean.ruleset"
    path.write_text(CLEAN_NFT, encoding="utf-8")
    return str(path)


@pytest.fixture()
def bad(tmp_path):
    path = tmp_path / "bad.rules"
    path.write_text(BAD_IPTABLES, encoding="utf-8")
    return str(path)


def test_scan_clean_exits_zero_at_high(clean, capsys):
    assert main(["scan", clean, "--fail-on", "high"]) == 0
    out = capsys.readouterr().out
    assert "FWL206" in out and "1 finding(s)" in out


def test_scan_clean_fails_at_low(clean, capsys):
    assert main(["scan", clean, "--fail-on", "low"]) == 1
    capsys.readouterr()


def test_scan_bad_fails_at_high(bad, capsys):
    assert main(["scan", bad, "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "FWL101" in out and "FWL201" in out


def test_scan_bad_exits_zero_without_gate(bad, capsys):
    assert main(["scan", bad, "--fail-on", "none"]) == 0
    capsys.readouterr()


def test_scan_json_output(clean, capsys):
    assert main(["scan", clean, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["low"] == 1
    assert payload["rules_run"] == 20
    assert payload["findings"][0]["rule"] == "FWL206"


def test_scan_sarif_output(bad, capsys):
    assert main(["scan", bad, "--format", "sarif"]) == 0
    payload = json.loads(capsys.readouterr().out)
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "firelint"
    assert any(result["level"] == "error" for result in run["results"])


def test_scan_missing_file_warns(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.rules"), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(f["rule"] == "FWL109" for f in payload["findings"])


def test_scan_directory_discovers_rulesets(tmp_path, capsys):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "host.rules").write_text(BAD_IPTABLES, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("just prose\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--fail-on", "none", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"], "directory scan should discover the nested ruleset"


def test_demo_runs(capsys):
    assert main(["demo", "--fail-on", "none"]) == 0
    out = capsys.readouterr().out
    assert "FWL102" in out and "finding(s)" in out


def test_rules_lists_registry(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule_id in ("FWL101", "FWL201", "FWL301"):
        assert rule_id in out


def test_rules_json(capsys):
    assert main(["rules", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 20


def test_rules_single(capsys):
    assert main(["rules", "--rule", "FWL102"]) == 0
    assert "Management port" in capsys.readouterr().out


def test_explain_rule(capsys):
    assert main(["explain", "fwl201"]) == 0
    out = capsys.readouterr().out
    assert "INPUT default policy ACCEPT" in out


def test_explain_unknown_rule(capsys):
    assert main(["explain", "FWL999"]) == 2


def test_no_command_shows_help(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_version_flag():
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["--version"])
    assert excinfo.value.code == 0
