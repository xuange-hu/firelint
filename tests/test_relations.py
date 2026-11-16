"""Relation-pass tests: the conclusions that only exist between files."""

from firelint.parsers import parse
from firelint.rules import evaluate

IPTABLES_V4 = (
    "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
    "-A INPUT -p tcp --dport 80 -j ACCEPT\nCOMMIT\n"
)

NFT_IP = (
    "table ip filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n"
    "\t\ttcp dport 80 accept\n\t}\n}\n"
)

NFT_INET = (
    "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n"
    "\t\ttcp dport 80 accept\n\t}\n}\n"
)

UFW_ON = (
    "Status: active\n\nLogging: off\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n"
    "To Action From\n-- ------ ----\n80/tcp ALLOW IN Anywhere\n"
)

UFW_OFF = (
    "Status: inactive\n\nLogging: off\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n"
    "To Action From\n-- ------ ----\n80/tcp ALLOW IN Anywhere\n"
)


def ids_of(targets) -> set[str]:
    return {f.rule for f in evaluate(targets)}


def test_fwl301_fires_when_ipv6_uncovered():
    assert "FWL301" in ids_of([parse(IPTABLES_V4, "v4.rules"), parse(NFT_IP, "nft-ip.ruleset")])


def test_fwl301_silent_with_inet_table():
    assert "FWL301" not in ids_of([parse(IPTABLES_V4, "v4.rules"), parse(NFT_INET, "nft-inet.ruleset")])


def test_fwl301_silent_with_ufw_v6_rows():
    text = UFW_ON.replace("80/tcp ALLOW IN Anywhere", "80/tcp ALLOW IN Anywhere (v6)")
    assert "FWL301" not in ids_of([parse(text, "ufw.txt")])


def test_fwl301_silent_with_ip6tables_name():
    assert "FWL301" not in ids_of([parse(IPTABLES_V4, "ip6tables.rules")])


def test_fwl302_fires_on_ufw_plus_raw_iptables():
    assert "FWL302" in ids_of([parse(UFW_ON, "ufw.txt"), parse(IPTABLES_V4, "v4.rules")])


def test_fwl302_silent_on_ufw_alone():
    assert "FWL302" not in ids_of([parse(UFW_ON, "ufw.txt")])


def test_fwl303_fires_on_mixed_stacks():
    assert "FWL303" in ids_of([parse(IPTABLES_V4, "v4.rules"), parse(NFT_IP, "nft-ip.ruleset")])


def test_fwl303_silent_on_single_stack():
    assert "FWL303" not in ids_of([parse(NFT_IP, "nft-ip.ruleset"), parse(NFT_INET, "nft-inet.ruleset")])


def test_fwl304_fires_on_inactive_ufw_with_rules():
    assert "FWL304" in ids_of([parse(UFW_OFF, "ufw.txt")])


def test_fwl304_silent_on_active_ufw():
    assert "FWL304" not in ids_of([parse(UFW_ON, "ufw.txt")])


def test_relations_findings_point_at_real_lines():
    result = evaluate([parse(UFW_OFF, "ufw.txt")])
    rel = next(f for f in result if f.rule == "FWL304")
    assert rel.line > 0 and rel.saw.startswith("80/tcp")
