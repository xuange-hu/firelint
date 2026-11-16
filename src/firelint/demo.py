"""Embedded demo corpus: one careless firewall, four dumps.

The corpus is embedded in the package (not shipped as files) so `firelint demo`
works from a wheel on any machine, and so the demo can never drift out of the
test suite: ``tests/test_demo.py`` asserts that this corpus exercises every
rule in the registry.
"""

from __future__ import annotations

from .model import Report, Target
from .parsers import parse
from .rules import REGISTRY, evaluate

IPTABLES = """\
# Careless host firewall, captured with `iptables-save`.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3306 -s 0.0.0.0/0 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 1024:65535 -j ACCEPT
-A INPUT -p tcp -m tcp --sport 1024:65535 -j ACCEPT
-A INPUT -p udp -j ACCEPT
-A INPUT -j ACCEPT
-A INPUT -j DROP
-A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT
-A INPUT --dport
-A OUTPUT -p tcp -m tcp --dport 25 -j LOG --log-prefix "smtp-out "
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.5:8080
COMMIT
"""

NFT = """\
# nft list ruleset on a second host (table ip only -- IPv6 was never configured)
table ip filter {
	chain input {
		type filter hook input priority filter;
		iif "lo" accept
		ct state established,related accept
		tcp dport 8080 accept
	}
}
"""

UFW_ACTIVE = """\
Status: active

Logging: off
Default: allow (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
3389/tcp                   ALLOW IN    Anywhere
22/tcp                     ALLOW IN    Anywhere
8080/tcp                   ALLOW IN    10.0.0.0/8
"""

UFW_STALE = """\
Status: inactive

Logging: off
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
8080/tcp                   ALLOW IN    Anywhere
"""

DEMO_FILES: dict[str, str] = {
    "demo-iptables.rules": IPTABLES,
    "demo-nft.ruleset": NFT,
    "demo-ufw.txt": UFW_ACTIVE,
    "demo-ufw-stale.txt": UFW_STALE,
}


def demo_targets() -> list[Target]:
    return [parse(text, name) for name, text in DEMO_FILES.items()]


def run_demo() -> Report:
    targets = demo_targets()
    findings = evaluate(targets)
    return Report(
        source="firelint demo (embedded corpus)",
        targets=targets,
        findings=findings,
        rules_run=len(REGISTRY),
        rule_ids=sorted(item.id for item in REGISTRY),
    )
