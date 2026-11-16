"""The rule engine: 20 rules in three passes.

``lines``     one rule at a time — what does *this* line expose?
``chains``    chain defaults and ordering — policy, dead rules, logging.
``relations`` between files and families — IPv6 gaps, mixed firewall stacks.

Rules may co-fire on the same line by design: an exposed management port is
both an exposure (FWL102) and a stateless allow (FWL105).  Each conclusion
names the rule that produced it so the two concerns can be tracked separately.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import (
    MGMT_PORTS,
    Finding,
    Rule,
    Target,
    is_any,
)


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    severity: str
    stage: str  # lines | chains | relations
    score: int
    why: str
    fix: str


REGISTRY: list[RuleInfo] = [
    RuleInfo(
        id="FWL101",
        title="Unconditional allow from anywhere",
        severity="critical",
        stage="lines",
        score=10,
        why=(
            "An inbound ACCEPT with no match expression (or protocol `all`) matches every packet from every "
            "source on every port. Whatever the chain's other rules say, this line alone turns the firewall off "
            "for that chain."
        ),
        fix="Delete the rule, or narrow it to the protocol, port and source that actually need the traffic.",
    ),
    RuleInfo(
        id="FWL102",
        title="Management port exposed to anywhere",
        severity="critical",
        stage="lines",
        score=10,
        why=(
            "SSH, RDP, VNC, database and container-runtime ports are management planes, not services. "
            "An ACCEPT from `any` on one of these ports puts credentials directly on the internet; "
            "the scanning noise on port 22 alone starts within minutes of exposure."
        ),
        fix="Restrict the source to a jump host / VPN / allowlist CIDR, or move access behind a bastion.",
    ),
    RuleInfo(
        id="FWL103",
        title="Service port exposed to anywhere",
        severity="medium",
        stage="lines",
        score=5,
        why=(
            "A service port open to `any` is only safe if the service behind it is meant to face the whole "
            "internet and is patched like it. Most such rules are leftovers from a quick test."
        ),
        fix="Confirm the service is intentionally public; otherwise restrict the source or close the port.",
    ),
    RuleInfo(
        id="FWL104",
        title="Wide destination-port range from anywhere",
        severity="medium",
        stage="lines",
        score=5,
        why=(
            "A destination-port range wider than 1024 ports is not a service allowlist, it is a hole with a "
            "label. It hides real services inside noise and expands any future service compromise to the "
            "whole range."
        ),
        fix="Enumerate the actual ports. If the range is for passive FTP or RPC, pin the range to the smallest that works.",
    ),
    RuleInfo(
        id="FWL105",
        title="Stateless inbound allow",
        severity="medium",
        stage="lines",
        score=5,
        why=(
            "An inbound ACCEPT with no connection-state match (`-m state/--ctstate`, `ct state`) lets forged "
            "packets in through the same door as legitimate sessions. Stateless allows also break INVALID-drop "
            "discipline, which is what keeps spoofed scans out."
        ),
        fix="Add `-m conntrack --ctstate NEW` (or `ct state new`) on the allow and keep an ESTABLISHED accept plus an INVALID drop in the chain.",
    ),
    RuleInfo(
        id="FWL106",
        title="Allow filtered only by source port",
        severity="low",
        stage="lines",
        score=2,
        why=(
            "Source ports are chosen freely by any client stack; a filter that only constrains `--sport` "
            "matches effectively everything. It reads like a rule but enforces almost nothing."
        ),
        fix="Filter on destination port instead; drop the source-port condition unless it is paired with a state match.",
    ),
    RuleInfo(
        id="FWL107",
        title="DNAT/redirect from anywhere",
        severity="high",
        stage="lines",
        score=8,
        why=(
            "A DNAT or redirect with no source restriction forwards *all* traffic for that port into an "
            "internal host. The internal service inherits the exposure of the router, usually without its "
            "own hardening or monitoring."
        ),
        fix="Pin the DNAT source to the intended client networks, and filter the forwarded traffic in the forward chain as well.",
    ),
    RuleInfo(
        id="FWL108",
        title="Protocol-wide allow from anywhere",
        severity="medium",
        stage="lines",
        score=5,
        why=(
            "An ACCEPT for all TCP or all UDP ports from `any` is a full protocol exposure. On UDP it is "
            "worse: connectionless transports are the raw material for reflection and amplification abuse."
        ),
        fix="Name the ports the service actually listens on; for UDP, restrict sources wherever possible.",
    ),
    RuleInfo(
        id="FWL109",
        title="Rule the auditor could not parse",
        severity="low",
        stage="lines",
        score=2,
        why=(
            "A line that no parser understands is a line no audit covers. It is usually a truncated edit or a "
            "hand-merged ruleset — exactly the state where a silent open port lives."
        ),
        fix="Re-render the ruleset with the native tool (iptables-save / nft list ruleset) and diff against the stored copy.",
    ),
    RuleInfo(
        id="FWL201",
        title="INPUT default policy ACCEPT",
        severity="critical",
        stage="chains",
        score=10,
        why=(
            "A chain default of ACCEPT means every packet not matched by a later rule is allowed. One deleted "
            "rule, one failed reload, one new interface — and the host is open. Deny-by-default is the single "
            "cheapest property a host firewall has."
        ),
        fix="Set the INPUT policy to DROP and allow explicitly: `iptables -P INPUT DROP` / `policy drop;` / `ufw default deny incoming`.",
    ),
    RuleInfo(
        id="FWL202",
        title="FORWARD default policy ACCEPT",
        severity="critical",
        stage="chains",
        score=10,
        why=(
            "FORWARD ACCEPT turns every host with routing enabled into an open router. On cloud instances and "
            "lab machines with two interfaces this is a classic pivot path — and container bridges make every "
            "container a routed neighbour."
        ),
        fix="Set the FORWARD policy to DROP and allow only the flows that must transit (`iptables -P FORWARD DROP`).",
    ),
    RuleInfo(
        id="FWL203",
        title="Unreachable rules after an unconditional verdict",
        severity="medium",
        stage="chains",
        score=5,
        why=(
            "Once a rule with no match expression jumps to ACCEPT/DROP/REJECT, nothing below it in the chain "
            "can ever fire. The dead rules are usually the intended policy — the live line above them is the "
            "mistake."
        ),
        fix="Move the unconditional verdict to the end of the chain, or delete the lines that can never match.",
    ),
    RuleInfo(
        id="FWL204",
        title="Attached chain with no explicit policy",
        severity="high",
        stage="chains",
        score=8,
        why=(
            "An nftables chain attached to a hook without a `policy` statement defaults to ACCEPT — silently. "
            "The ruleset looks like a filter but the default is allow; the same file with one word added "
            "behaves completely differently."
        ),
        fix="State the policy explicitly on every hooked chain: `type filter hook input priority 0; policy drop;`.",
    ),
    RuleInfo(
        id="FWL205",
        title="No INVALID-state drop",
        severity="medium",
        stage="chains",
        score=5,
        why=(
            "Packets in the INVALID conntrack state are exactly what forged scans and out-of-state probes look "
            "like. A chain that allows traffic but never drops INVALID hands that reconnaissance channel to "
            "anyone who asks."
        ),
        fix="Add early in the chain: `-m conntrack --ctstate INVALID -j DROP` (or `ct state invalid drop`).",
    ),
    RuleInfo(
        id="FWL206",
        title="No logging in the ruleset",
        severity="low",
        stage="chains",
        score=2,
        why=(
            "A firewall without logging can neither be tuned nor investigated. When the inevitable 'why is "
            "this blocked' call comes, there is no evidence either way."
        ),
        fix="Log dropped traffic at least: a LOG rule before the final DROP (rate-limited), or `ufw logging on`.",
    ),
    RuleInfo(
        id="FWL207",
        title="Logging without a drop",
        severity="low",
        stage="chains",
        score=2,
        why=(
            "Log rules in a chain that ends in ACCEPT (and has no DROP) record traffic that is then allowed "
            "anyway. The log looks like a filter and bills like a filter; it is only a witness."
        ),
        fix="Pair each LOG rule with the DROP/REJECT it is meant to document, or set the chain policy to DROP.",
    ),
    RuleInfo(
        id="FWL301",
        title="IPv4 rules with no IPv6 coverage",
        severity="high",
        stage="relations",
        score=8,
        why=(
            "IPv6 is enabled on every modern host and is not covered by a single iptables rule. A service "
            "locked down for IPv4 is reachable over IPv6 with the default allow policy — the firewall is not "
            "wrong, it is simply looking at the wrong family."
        ),
        fix="Mirror the policy for IPv6 (ip6tables / `table ip6` / `table inet`), or disable IPv6 explicitly if it is unused.",
    ),
    RuleInfo(
        id="FWL302",
        title="ufw and raw iptables rulesets coexist",
        severity="medium",
        stage="relations",
        score=5,
        why=(
            "ufw is a front-end that generates iptables rules. Hand-written iptables rules live in the same "
            "tables and are wiped or reordered by the next `ufw reload`. Two writers, one ruleset: the "
            "surviving order is whatever ran last."
        ),
        fix="Pick one owner. If ufw owns the host, move custom rules into ufw's before/after rules files (`/etc/ufw/before.rules`).",
    ),
    RuleInfo(
        id="FWL303",
        title="iptables and nftables rulesets coexist",
        severity="medium",
        stage="relations",
        score=5,
        why=(
            "On hosts with both stacks, packet verdicts depend on hook priorities across two subsystems. "
            "iptables-nft translation layers and legacy `iptables` binaries make the effective order "
            "impossible to read from either file alone — the classic source of 'the rule is there but does "
            "nothing'."
        ),
        fix="Standardise on one stack (nftables with the iptables-nft compatibility layer, or pure iptables-legacy) and delete the other's ruleset.",
    ),
    RuleInfo(
        id="FWL304",
        title="ufw inactive but rules are listed",
        severity="low",
        stage="relations",
        score=2,
        why=(
            "When ufw reports `Status: inactive`, none of the listed rules is enforced. The file reads like "
            "protection; the kernel enforces nothing. This is the gap that survives audits, because the "
            "documentation and the enforcement are reviewed by different people."
        ),
        fix="`ufw enable` if the rules are the intended policy, or delete them so the file cannot lie.",
    ),
]

RULES_BY_ID: dict[str, RuleInfo] = {item.id: item for item in REGISTRY}


def _finding(info: RuleInfo, where: str, line: int, offset: int, saw: str, message: str) -> Finding:
    return Finding(
        rule=info.id,
        severity=info.severity,
        message=message,
        line=line,
        offset=offset,
        length=len(saw),
        saw=saw,
        fix=info.fix,
        where=where,
        score=info.score,
    )


def _rule_logged(rule: Rule) -> bool:
    if rule.action == "LOG":
        return True
    raw = rule.raw.lower()
    return "--log-prefix" in raw or (rule.fmt == "nft" and " log " in f" {raw} ")


# ------------------------------------------------------------------ pass 1 ---


def pass_lines(target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for chain in target.chains:
        for rule in chain.rules:
            exposed = is_any(rule.src)
            findings.extend(_lines_one(target, rule, exposed))
    for line, offset, raw in target.warnings:
        findings.append(_finding(RULES_BY_ID["FWL109"], target.source, line, offset, " ".join(raw.split())[:160], "line could not be parsed as a firewall rule; this fragment of the ruleset is unaudited"))
    return findings


def _lines_one(target: Target, rule: Rule, exposed: bool) -> list[Finding]:
    out: list[Finding] = []
    accept = rule.action == "ACCEPT"

    if (
        accept
        and rule.inbound
        and exposed
        and not rule.dport
        and not rule.sport
        and not rule.dst
        and not rule.in_if
        and not rule.out_if
        and not rule.stateful
        and rule.proto in ("", "all")
    ):
        out.append(_finding(RULES_BY_ID["FWL101"], target.source, rule.line, rule.offset, rule.saw, "unconditional ACCEPT: every protocol and port from anywhere is allowed"))

    if accept and rule.inbound and exposed and rule.dport:
        hit_mgmt = sorted({port for port in MGMT_PORTS if rule.dport_matches(port)})
        wide = rule.dport_span > 1024
        if hit_mgmt:
            out.append(_finding(RULES_BY_ID["FWL102"], target.source, rule.line, rule.offset, rule.saw, f"management port(s) {', '.join(hit_mgmt)} accepted from anywhere"))
        if wide:
            out.append(_finding(RULES_BY_ID["FWL104"], target.source, rule.line, rule.offset, rule.saw, f"destination-port span {rule.dport} covers {rule.dport_span} ports for any source"))
        elif not hit_mgmt:
            out.append(_finding(RULES_BY_ID["FWL103"], target.source, rule.line, rule.offset, rule.saw, f"service port {rule.dport} accepted from anywhere"))
        if not rule.stateful:
            out.append(_finding(RULES_BY_ID["FWL105"], target.source, rule.line, rule.offset, rule.saw, "inbound ACCEPT from anywhere with no connection-state match"))

    if accept and rule.inbound and exposed and rule.port_wide and not rule.stateful:
        family = "UDP" if rule.proto == "udp" else "TCP"
        out.append(_finding(RULES_BY_ID["FWL108"], target.source, rule.line, rule.offset, rule.saw, f"all {family} ports accepted from anywhere"))

    if accept and rule.sport and not rule.dport:
        out.append(_finding(RULES_BY_ID["FWL106"], target.source, rule.line, rule.offset, rule.saw, "allow rule filtered only by source port; source ports are client-chosen"))

    if rule.action in ("DNAT", "REDIRECT") and exposed:
        out.append(_finding(RULES_BY_ID["FWL107"], target.source, rule.line, rule.offset, rule.saw, f"{rule.action} with no source restriction forwards outside traffic to {rule.nat_to or 'an internal host'}"))

    return out


# ------------------------------------------------------------------ pass 2 ---


def pass_chains(target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for chain in target.chains:
        head = (chain.header_line, chain.header_offset, chain.header_raw or f"<chain {chain.name}>")

        if chain.name == "INPUT" and chain.hooked and chain.policy == "ACCEPT":
            findings.append(_finding(RULES_BY_ID["FWL201"], target.source, head[0], head[1], " ".join(head[2].split())[:160], "INPUT default policy is ACCEPT: unmatched packets are allowed"))
        if chain.name == "FORWARD" and chain.hooked and chain.policy == "ACCEPT":
            findings.append(_finding(RULES_BY_ID["FWL202"], target.source, head[0], head[1], " ".join(head[2].split())[:160], "FORWARD default policy is ACCEPT: transit traffic is routed by default"))
        if chain.hooked and not chain.policy_stated:
            findings.append(_finding(RULES_BY_ID["FWL204"], target.source, head[0], head[1], " ".join(head[2].split())[:160], f"chain {chain.name} is attached to a hook with no explicit policy (defaults to ACCEPT)"))

        dead_at = None
        for index, rule in enumerate(chain.rules):
            if rule.unconstrained and rule.action in ("ACCEPT", "DROP", "REJECT"):
                dead_at = index + 1
                break
        if dead_at is not None and dead_at < len(chain.rules):
            first = chain.rules[dead_at]
            count = len(chain.rules) - dead_at
            findings.append(_finding(RULES_BY_ID["FWL203"], target.source, first.line, first.offset, first.saw, f"{count} rule(s) after an unconditional {chain.rules[dead_at - 1].action} can never match"))

        if chain.name in ("INPUT", "FORWARD"):
            allows = any(rule.action == "ACCEPT" for rule in chain.rules)
            drops_invalid = any("invalid" in rule.raw.lower() and rule.action in ("DROP", "REJECT") for rule in chain.rules)
            if allows and not drops_invalid:
                findings.append(_finding(RULES_BY_ID["FWL205"], target.source, head[0], head[1], " ".join(head[2].split())[:160], f"{chain.name} allows traffic but never drops INVALID-state packets"))

        logged_rules = [rule for rule in chain.rules if _rule_logged(rule)]
        if logged_rules and chain.policy == "ACCEPT" and not any(rule.action in ("DROP", "REJECT") for rule in chain.rules):
            first = logged_rules[0]
            findings.append(_finding(RULES_BY_ID["FWL207"], target.source, first.line, first.offset, first.saw, f"chain {chain.name} logs traffic but its policy ACCEPTs that traffic afterwards"))

    has_log = any(_rule_logged(rule) for rule in target.rules) or (target.fmt == "ufw" and target.meta.get("logging") == "on")
    if target.rules and not has_log:
        findings.append(_finding(RULES_BY_ID["FWL206"], target.source, 1, 0, f"<{target.source}>", "ruleset contains no logging at all: drops are invisible"))
    return findings


# ------------------------------------------------------------------ pass 3 ---


def pass_relations(targets: list[Target]) -> list[Finding]:
    findings: list[Finding] = []
    with_rules = [target for target in targets if target.rules]
    if not with_rules:
        return findings

    def evidence(target: Target) -> tuple[str, int, int, str]:
        first = target.rules[0]
        return target.source, first.line, first.offset, first.saw

    if not any(target.meta.get("covers_ipv6") for target in with_rules):
        where, line, offset, saw = evidence(with_rules[0])
        findings.append(_finding(RULES_BY_ID["FWL301"], where, line, offset, saw, "every rule in scope is IPv4; nothing constrains IPv6, which the kernel still accepts by default"))

    by_fmt = {fmt: [t for t in with_rules if t.fmt == fmt] for fmt in ("iptables", "nft", "ufw")}

    if by_fmt["ufw"] and by_fmt["iptables"]:
        where, line, offset, saw = evidence(by_fmt["iptables"][0])
        findings.append(_finding(RULES_BY_ID["FWL302"], where, line, offset, saw, "raw iptables rules coexist with a ufw-managed ruleset; ufw reloads can silently reorder or wipe the raw rules"))

    if by_fmt["iptables"] and by_fmt["nft"]:
        where, line, offset, saw = evidence(by_fmt["nft"][0])
        findings.append(_finding(RULES_BY_ID["FWL303"], where, line, offset, saw, "iptables and nftables rulesets both present; effective verdicts depend on hook priorities across two stacks"))

    for target in by_fmt["ufw"]:
        if target.meta.get("status") == "inactive" and any(rule.action == "ACCEPT" for rule in target.rules):
            first = next(rule for rule in target.rules if rule.action == "ACCEPT")
            findings.append(_finding(RULES_BY_ID["FWL304"], target.source, first.line, first.offset, first.saw, "ufw is inactive while listing allow rules: none of them is enforced"))
    return findings


def evaluate(targets: list[Target]) -> list[Finding]:
    """Run all three passes and return findings in severity order."""
    findings: list[Finding] = []
    for target in targets:
        findings.extend(pass_lines(target))
        findings.extend(pass_chains(target))
    findings.extend(pass_relations(targets))
    findings.sort(key=lambda f: f.sort_key())
    return findings
