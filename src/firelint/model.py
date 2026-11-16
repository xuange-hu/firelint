"""Object model: normalized rules, chains, targets and the report.

Three input dialects (iptables-save, ``nft list ruleset``, ``ufw status
verbose``) are flattened into one :class:`Rule` shape so the rule engine never
has to branch on syntax.  Every rule keeps its line number, character offset
and raw text, because the only useful firewall finding is the one that points
at the exact line an operator must look at.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}

IPTABLES = "iptables"
NFT = "nft"
UFW = "ufw"

# Chains that carry traffic arriving from outside the host.  OUTPUT is
# deliberately excluded: an OUTPUT allow is not an inbound exposure.
INBOUND_CHAINS = {"INPUT", "FORWARD", "PREROUTING"}

# Destinations that are management planes, not services.  Exposing any of
# these to `anywhere` is a critical finding regardless of the machine's role.
MGMT_PORTS = {
    "22",
    "23",
    "3389",
    "5900",
    "5901",
    "2375",
    "2376",
    "3306",
    "5432",
    "6379",
    "27017",
    "9200",
    "11211",
}

ANY_VALUES = {"", "any", "anywhere", "0.0.0.0/0", "::/0", "0.0.0.0", "::"}


def is_any(addr: str) -> bool:
    """True when an address matcher is the unrestricted `any`."""
    return addr.strip().lower() in ANY_VALUES


@dataclass
class Rule:
    """One normalized firewall rule."""

    raw: str
    line: int
    offset: int
    fmt: str = IPTABLES
    table: str = "filter"
    chain: str = ""
    action: str = ""  # ACCEPT / DROP / REJECT / LOG / DNAT / MASQUERADE / ...
    proto: str = ""
    src: str = ""
    dst: str = ""
    sport: str = ""
    dport: str = ""
    in_if: str = ""
    out_if: str = ""
    stateful: bool = False
    nat_to: str = ""
    comment: str = ""
    ipv6: bool = False

    @property
    def saw(self) -> str:
        return " ".join(self.raw.split())[:160]

    @property
    def inbound(self) -> bool:
        return self.chain.upper() in INBOUND_CHAINS

    @property
    def unconstrained(self) -> bool:
        """No match expression at all: the rule matches every packet."""
        return not (
            self.proto
            or self.src
            or self.dst
            or self.sport
            or self.dport
            or self.in_if
            or self.out_if
            or self.stateful
            or self.nat_to
        )

    @property
    def port_wide(self) -> bool:
        """tcp/udp rule with no port constraint: every port matches."""
        return self.proto in ("tcp", "udp") and not self.dport

    @property
    def dport_span(self) -> int:
        """Width of the destination-port range (single port = 1)."""
        text = self.dport.strip()
        if not text:
            return 0
        if ":" in text or "-" in text:
            lo, _, hi = text.replace("-", ":").partition(":")
            try:
                return max(1, int(hi) - int(lo) + 1)
            except ValueError:
                return 1
        if "," in text:
            return len([p for p in text.split(",") if p.strip()])
        return 1

    def dport_matches(self, port: str) -> bool:
        if not self.dport:
            return True  # no constraint
        parts = self.dport.replace("-", ":").replace("{", "").replace("}", "").split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                lo, _, hi = part.partition(":")
                try:
                    if int(lo) <= int(port) <= int(hi):
                        return True
                except ValueError:
                    continue
            elif part == port:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "line": self.line,
            "offset": self.offset,
            "format": self.fmt,
            "table": self.table,
            "chain": self.chain,
            "action": self.action,
            "proto": self.proto,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "stateful": self.stateful,
            "nat_to": self.nat_to,
            "ipv6": self.ipv6,
        }


@dataclass
class Chain:
    """One chain: its default policy and the ordered rules inside it."""

    name: str
    table: str = "filter"
    fmt: str = IPTABLES
    policy: str = ""  # ACCEPT / DROP / REJECT / "" (unknown or unstated)
    policy_stated: bool = True
    hooked: bool = False  # attached to a netfilter hook (built-in or nft hook)
    rules: list[Rule] = field(default_factory=list)
    header_line: int = 1
    header_offset: int = 0
    header_raw: str = ""


@dataclass
class Target:
    """One parsed file: its chains, parse warnings and format metadata."""

    source: str
    fmt: str
    chains: list[Chain] = field(default_factory=list)
    warnings: list[tuple[int, int, str]] = field(default_factory=list)  # line, offset, raw
    meta: dict = field(default_factory=dict)

    @property
    def rules(self) -> list[Rule]:
        out: list[Rule] = []
        for chain in self.chains:
            out.extend(chain.rules)
        return out

    @property
    def text(self) -> str:
        return "\n".join(rule.raw for rule in self.rules)


@dataclass
class Finding:
    """One rule conclusion, with the evidence that produced it."""

    rule: str
    severity: str
    message: str
    line: int
    offset: int
    length: int
    saw: str
    fix: str
    where: str
    score: int = 0

    def sort_key(self) -> tuple[int, str, int]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.rule, self.offset)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "where": self.where,
            "line": self.line,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "length": self.length,
            "saw": self.saw,
            "fix": self.fix,
        }


@dataclass
class Report:
    source: str
    targets: list[Target] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rule_ids: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def should_fail(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        limit = SEVERITY_ORDER[threshold]
        return any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts,
            "rules_run": self.rules_run,
        }
