"""Rule tests: every rule fires on its trigger and stays quiet otherwise."""

from firelint.model import Finding  # noqa: F401 (documents the type under test)
from firelint.parsers import parse
from firelint.rules import REGISTRY, RULES_BY_ID, evaluate


def findings(text: str, source: str = "rules.test") -> list:
    return evaluate([parse(text, source)])


def ids(text: str) -> set[str]:
    return {f.rule for f in findings(text)}


def wrap(body: str) -> str:
    return f"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n{body}\nCOMMIT\n"


# FWL101 ---------------------------------------------------------------

def test_fwl101_fires_on_bare_accept():
    assert "FWL101" in ids(wrap("-A INPUT -j ACCEPT"))


def test_fwl101_fires_on_proto_all():
    assert "FWL101" in ids(wrap("-A INPUT -p all -j ACCEPT"))


def test_fwl101_silent_on_state_accept():
    assert "FWL101" not in ids(wrap("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"))


def test_fwl101_silent_on_scoped_accept():
    assert "FWL101" not in ids(wrap("-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"))


# FWL102 ---------------------------------------------------------------

def test_fwl102_fires_on_ssh_open():
    assert "FWL102" in ids(wrap("-A INPUT -p tcp --dport 22 -j ACCEPT"))


def test_fwl102_fires_when_range_covers_rdp():
    assert "FWL102" in ids(wrap("-A INPUT -p tcp --dport 3300:3400 -j ACCEPT"))


def test_fwl102_silent_when_range_misses_mgmt_ports():
    assert "FWL102" not in ids(wrap("-A INPUT -p tcp --dport 3000:3300 -j ACCEPT"))


def test_fwl102_silent_on_scoped_source():
    assert "FWL102" not in ids(wrap("-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"))


# FWL103 ---------------------------------------------------------------

def test_fwl103_fires_on_service_port():
    assert "FWL103" in ids(wrap("-A INPUT -p tcp --dport 8080 -j ACCEPT"))


def test_fwl103_silent_on_scoped_source():
    assert "FWL103" not in ids(wrap("-A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT"))


# FWL104 ---------------------------------------------------------------

def test_fwl104_fires_on_wide_range():
    assert "FWL104" in ids(wrap("-A INPUT -p tcp --dport 1024:65535 -j ACCEPT"))


def test_fwl104_silent_on_small_range():
    assert "FWL104" not in ids(wrap("-A INPUT -p tcp --dport 8000:8010 -j ACCEPT"))


# FWL105 ---------------------------------------------------------------

def test_fwl105_fires_on_stateless_allow():
    assert "FWL105" in ids(wrap("-A INPUT -p tcp --dport 8080 -j ACCEPT"))


def test_fwl105_silent_on_state_match():
    assert "FWL105" not in ids(wrap("-A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW -j ACCEPT"))


# FWL106 ---------------------------------------------------------------

def test_fwl106_fires_on_sport_only():
    assert "FWL106" in ids(wrap("-A INPUT -p tcp --sport 1024:65535 -j ACCEPT"))


def test_fwl106_silent_when_dport_present():
    assert "FWL106" not in ids(wrap("-A INPUT -p tcp --sport 53 --dport 80 -j ACCEPT"))


# FWL107 ---------------------------------------------------------------

def _nat(body: str) -> str:
    return f"*nat\n:PREROUTING ACCEPT [0:0]\n{body}\nCOMMIT\n"


def test_fwl107_fires_on_open_dnat():
    assert "FWL107" in ids(_nat("-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.5:8080"))


def test_fwl107_silent_on_scoped_dnat():
    body = "-A PREROUTING -p tcp --dport 80 -s 10.0.0.0/8 -j DNAT --to-destination 10.0.0.5:8080"
    assert "FWL107" not in ids(_nat(body))


# FWL108 ---------------------------------------------------------------

def test_fwl108_fires_on_udp_any_ports():
    assert "FWL108" in ids(wrap("-A INPUT -p udp -j ACCEPT"))


def test_fwl108_silent_on_named_port():
    assert "FWL108" not in ids(wrap("-A INPUT -p udp --dport 53 -j ACCEPT"))


def test_fwl108_silent_on_state_match():
    assert "FWL108" not in ids(wrap("-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT"))


# FWL109 ---------------------------------------------------------------

def test_fwl109_fires_on_malformed():
    assert "FWL109" in ids(wrap("-A INPUT --dport"))


def test_fwl109_silent_on_valid_rules():
    assert "FWL109" not in ids(wrap("-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"))


# FWL201 / FWL202 --------------------------------------------------------

def test_fwl201_fires_on_input_accept_policy():
    assert "FWL201" in ids("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n")


def test_fwl201_silent_on_drop_policy():
    assert "FWL201" not in ids("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n")


def test_fwl202_fires_on_forward_accept_policy():
    assert "FWL202" in ids("*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n")


def test_fwl202_silent_on_drop_policy():
    assert "FWL202" not in ids("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n")


# FWL203 ---------------------------------------------------------------

def test_fwl203_fires_on_rules_after_unconditional_drop():
    text = wrap("-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -j DROP\n-A INPUT -p tcp --dport 8080 -j ACCEPT")
    assert "FWL203" in ids(text)


def test_fwl203_silent_without_unconditional_verdict():
    text = wrap("-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -p tcp --dport 8080 -j DROP")
    assert "FWL203" not in ids(text)


# FWL204 ---------------------------------------------------------------

def test_fwl204_fires_on_hook_without_policy():
    text = "table ip filter {\n\tchain input {\n\t\ttype filter hook input priority 0;\n\t}\n}\n"
    assert "FWL204" in ids(text)


def test_fwl204_silent_when_policy_stated():
    text = "table ip filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n"
    assert "FWL204" not in ids(text)


# FWL205 ---------------------------------------------------------------

def test_fwl205_fires_without_invalid_drop():
    text = (
        "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n"
        "\t\ttcp dport 22 accept\n\t}\n}\n"
    )
    assert "FWL205" in ids(text)


def test_fwl205_silent_with_invalid_drop():
    text = (
        "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n"
        "\t\tct state invalid drop\n\t\ttcp dport 22 accept\n\t}\n}\n"
    )
    assert "FWL205" not in ids(text)


# FWL206 ---------------------------------------------------------------

def test_fwl206_fires_without_logging():
    assert "FWL206" in ids(wrap("-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"))


def test_fwl206_silent_with_log_rule():
    assert "FWL206" not in ids(wrap("-A INPUT -p tcp --dport 25 -j LOG --log-prefix \"smtp \""))


def test_fwl206_silent_when_ufw_logging_on():
    text = "Status: active\n\nLogging: on\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
    assert "FWL206" not in ids(text)


# FWL207 ---------------------------------------------------------------

def test_fwl207_fires_on_log_without_drop():
    text = (
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 25 -j LOG --log-prefix \"smtp \"\nCOMMIT\n"
    )
    assert "FWL207" in ids(text)


def test_fwl207_silent_when_drop_follows():
    text = (
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 25 -j LOG --log-prefix \"smtp \"\n-A INPUT -p tcp --dport 25 -j DROP\nCOMMIT\n"
    )
    assert "FWL207" not in ids(text)


# registry invariants -----------------------------------------------------

def test_registry_ids_unique():
    all_ids = [item.id for item in REGISTRY]
    assert len(all_ids) == len(set(all_ids))


def test_findings_severity_matches_registry():
    text = wrap("-A INPUT -j ACCEPT\n-A INPUT --dport")
    for finding in findings(text):
        assert finding.severity == RULES_BY_ID[finding.rule].severity
        assert finding.saw and finding.where and finding.fix


def test_findings_sorted_by_severity():
    text = wrap("-A INPUT -j ACCEPT\n-A INPUT --dport\n-A INPUT -p tcp --dport 8080 -j ACCEPT")
    result = findings(text)
    severities = [f.severity for f in result]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
    assert severities == sorted(severities, key=lambda s: order[s])
