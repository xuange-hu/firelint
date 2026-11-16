"""Parsers for the three firewall dialects: iptables-save, nft, ufw.

Everything is flattened into :class:`~firelint.model.Target` objects.  The
parsers are deliberately conservative: a line they cannot understand becomes a
*warning* (surfaced by rule FWL109) instead of being silently dropped, because
"the auditor ignored half my ruleset" is worse than "the auditor is confused
by one line".
"""

from __future__ import annotations

import os
import re
import shlex

from .model import IPTABLES, NFT, UFW, Chain, Rule, Target

_SET_RE = re.compile(r"\{[^}]*\}")
_L4_RE = re.compile(r"\b(?:meta l4proto|meta protocol|ip protocol|ip6 nexthdr)\s+(\w+)")
_DPORT_RE = re.compile(r"\bdport\s+(\{[^}]*\}|\S+)")
_SPORT_RE = re.compile(r"\bsport\s+(\{[^}]*\}|\S+)")
_SADDR_RE = re.compile(r"\b(?:ip6?\s+)?saddr\s+(\{[^}]*\}|\S+)")
_DADDR_RE = re.compile(r"\b(?:ip6?\s+)?daddr\s+(\{[^}]*\}|\S+)")
_IIF_RE = re.compile(r"\biif(?:name)?\s+\"?([^\"\s};]+)\"?")
_OIF_RE = re.compile(r"\boif(?:name)?\s+\"?([^\"\s};]+)\"?")
_NFT_VERBS = {"tcp", "udp", "icmp", "icmpv6", "esp", "ah"}


def _norm_addr(value: str) -> str:
    value = value.strip().strip('"').lower()
    if value in ("0.0.0.0/0", "::/0", "anywhere", "any"):
        return "any"
    return value


def _norm_ports(value: str) -> str:
    value = value.strip().strip('"')
    value = _SET_RE.sub(lambda m: m.group(0)[1:-1].replace(" ", ""), value)
    return value.replace("-", ":")


def detect_format(text: str, source: str = "") -> str | None:
    """Best-effort dialect detection from content (filename is a hint only)."""
    if re.search(r"(?mi)^\s*status:\s*(active|inactive)\b", text):
        return UFW
    if re.search(r"(?m)^\s*table\s+\w+\s+\w+\s*\{", text) or re.search(r"(?m)^\s*chain\s+\w+\s*\{", text):
        return NFT
    if re.search(r"(?m)^\*\w+", text) or re.search(r"(?m)^:\S+\s", text) or re.search(r"(?m)^-A\s", text):
        return IPTABLES
    if "ip6tables" in os.path.basename(source).lower():
        return IPTABLES
    return None


def _line_iter(text: str):
    offset = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        yield number, offset, raw
        offset += len(raw) + 1


# ---------------------------------------------------------------- iptables ---

def _parse_iptables_args(tokens: list[str]) -> dict:
    """Parse the match/target part of one iptables rule, or raise ValueError."""
    fields: dict = {}
    i = 0

    def need() -> str:
        nonlocal i
        if i + 1 >= len(tokens):
            raise ValueError("dangling flag")
        i += 1
        return tokens[i]

    while i < len(tokens):
        token = tokens[i]
        if token in ("!",):
            i += 1
            continue
        if token in ("-p", "--protocol"):
            fields["proto"] = need().lower()
        elif token in ("-s", "--source"):
            fields["src"] = _norm_addr(need())
        elif token in ("-d", "--destination"):
            fields["dst"] = _norm_addr(need())
        elif token in ("--sport", "--source-port", "--sports"):
            fields["sport"] = _norm_ports(need())
        elif token in ("--dport", "--destination-port", "--dports"):
            fields["dport"] = _norm_ports(need())
        elif token in ("-i", "--in-interface"):
            fields["in_if"] = need()
        elif token in ("-o", "--out-interface"):
            fields["out_if"] = need()
        elif token in ("-m", "--match"):
            module = need().lower()
            if module in ("state", "conntrack"):
                fields["stateful"] = True
        elif token in ("--state", "--ctstate"):
            fields["stateful"] = True
            need()
        elif token in ("-j", "--jump"):
            fields["action"] = need().upper()
        elif token in ("-g", "--goto"):
            fields["action"] = "GOTO"
            need()
        elif token in ("--to-destination", "--to-ports", "--to-source"):
            fields["nat_to"] = need()
        elif token in ("--log-prefix", "--log-level"):
            fields["logged"] = True
            need()
        elif token in ("--src-range",):
            fields["src"] = need()
        elif token in ("--dst-range",):
            fields["dst"] = need()
        elif token in ("--comment",):
            fields["comment"] = need()
        elif token in ("-c", "--set-counters"):
            need()
            need()
        elif token.startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            # Unknown flag: consume one value when one is plausible so a
            # following real flag is not swallowed as that value.
            i += 1
        i += 1

    if not fields.get("action"):
        raise ValueError("rule has no verdict target")
    return fields


def parse_iptables(text: str, source: str = "") -> Target:
    target = Target(source=source, fmt=IPTABLES)
    chains: dict[tuple[str, str], Chain] = {}
    table = "filter"

    def chain_for(name: str) -> Chain:
        key = (table, name)
        if key not in chains:
            chains[key] = Chain(
                name=name,
                table=table,
                fmt=IPTABLES,
                hooked=name in ("INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"),
            )
        return chains[key]

    for number, offset, raw in _line_iter(text):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("*"):
            table = stripped[1:].strip() or "filter"
            continue
        if stripped == "COMMIT":
            table = "filter"
            continue
        if stripped.startswith(":"):
            body = stripped[1:].split()
            name = body[0]
            policy = body[1].upper() if len(body) > 1 else ""
            chain = chain_for(name)
            if policy and policy != "-":
                chain.policy = policy
                chain.policy_stated = True
                chain.header_raw = stripped
                chain.header_line = number
                chain.header_offset = offset
            else:
                chain.policy_stated = False
                chain.header_raw = stripped
                chain.header_line = number
                chain.header_offset = offset
            continue
        if stripped.startswith("-N "):
            chain_for(stripped.split()[1])
            continue
        if stripped.startswith("-P "):
            body = stripped.split()
            chain = chain_for(body[1])
            chain.policy = body[2].upper()
            chain.header_raw = stripped
            chain.header_line = number
            chain.header_offset = offset
            continue
        if stripped.startswith("-A ") or stripped.startswith("-I ") or stripped.startswith("-C "):
            try:
                tokens = shlex.split(stripped)
                chain_name = tokens[1]
                fields = _parse_iptables_args(tokens[2:])
            except (ValueError, IndexError):
                target.warnings.append((number, offset, raw))
                continue
            chain_for(chain_name).rules.append(
                Rule(
                    raw=raw,
                    line=number,
                    offset=offset,
                    fmt=IPTABLES,
                    table=table,
                    chain=chain_name,
                    action=fields.get("action", ""),
                    proto=fields.get("proto", ""),
                    src=fields.get("src", ""),
                    dst=fields.get("dst", ""),
                    sport=fields.get("sport", ""),
                    dport=fields.get("dport", ""),
                    in_if=fields.get("in_if", ""),
                    out_if=fields.get("out_if", ""),
                    stateful=fields.get("stateful", False),
                    nat_to=fields.get("nat_to", ""),
                    comment=fields.get("comment", ""),
                    ipv6="ip6tables" in os.path.basename(source).lower(),
                )
            )
            continue
        target.warnings.append((number, offset, raw))

    target.chains = list(chains.values())
    target.meta["covers_ipv6"] = "ip6tables" in os.path.basename(source).lower()
    return target


# --------------------------------------------------------------------- nft ---

def _parse_nft_statement(statement: str, family: str) -> dict:
    fields: dict = {}
    stmt = statement.strip().rstrip(";").strip()
    if not stmt:
        return fields
    lowered = stmt.lower()

    if lowered.startswith("type ") and " hook " in lowered:
        fields["hook"] = lowered.split(" hook ", 1)[1].split()[0]
        match = re.search(r"\bpolicy\s+(\w+)", lowered)
        if match:
            fields["policy"] = match.group(1).upper()
        return fields
    if lowered.startswith("policy "):
        fields["policy"] = lowered.split(None, 1)[1].split()[0].upper()
        return fields

    if re.search(r"\blog\b", lowered):
        fields["logged"] = True

    match = _L4_RE.search(lowered)
    if match:
        fields["proto"] = match.group(1).lower()
    else:
        first = lowered.split()[0]
        if first in _NFT_VERBS:
            fields["proto"] = first

    for regex, key in ((_DPORT_RE, "dport"), (_SPORT_RE, "sport"), (_SADDR_RE, "src"), (_DADDR_RE, "dst")):
        found = regex.search(lowered)
        if found:
            value = _norm_ports(found.group(1)) if key in ("dport", "sport") else _norm_addr(found.group(1))
            fields[key] = value

    match = _IIF_RE.search(lowered)
    if match:
        fields["in_if"] = match.group(1)
    match = _OIF_RE.search(lowered)
    if match:
        fields["out_if"] = match.group(1)
    if re.search(r"\bct\s+state\b", lowered):
        fields["stateful"] = True

    for verdict in ("accept", "drop", "reject", "return"):
        if re.search(rf"\b{verdict}\s*$", lowered):
            fields["action"] = verdict.upper()
            break
    else:
        match = re.search(r"\b(dnat|snat|redirect)\s+to\s+(\S+)", lowered)
        if match:
            fields["action"] = match.group(1).upper()
            fields["nat_to"] = match.group(2).rstrip(",;")
        elif re.search(r"\bmasquerade\b", lowered):
            fields["action"] = "MASQUERADE"
        elif re.search(r"\bjump\s+\S+", lowered):
            fields["action"] = "JUMP"
        elif re.search(r"\bgoto\s+\S+", lowered):
            fields["action"] = "GOTO"

    if family == "ip6" or re.search(r"\bip6\b", lowered):
        fields["ipv6"] = True
    return fields


def parse_nft(text: str, source: str = "") -> Target:
    target = Target(source=source, fmt=NFT)
    chains: dict[tuple[str, str], Chain] = {}
    families: set[str] = set()
    table_name = ""
    family = ""
    current: Chain | None = None

    for number, offset, raw in _line_iter(text):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        table_match = re.match(r"table\s+(\w+)\s+(\w+)\s*\{", stripped)
        if table_match:
            family, table_name = table_match.group(1), table_match.group(2)
            families.add(family)
            current = None
            continue
        chain_match = re.match(r"chain\s+([\w-]+)\s*\{", stripped)
        if chain_match:
            label = chain_match.group(1)
            current = Chain(
                name=label.upper(),
                table=table_name or "filter",
                fmt=NFT,
                policy_stated=False,
                header_raw=stripped,
                header_line=number,
                header_offset=offset,
            )
            chains[(table_name, label)] = current
            continue
        if stripped.startswith("}"):
            current = None
            continue
        if current is None:
            continue

        for statement in filter(None, (part.strip() for part in stripped.split(";"))):
            fields = _parse_nft_statement(statement, family)
            if "hook" in fields:
                current.hooked = True
                hook = fields["hook"].upper()
                if hook in ("INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"):
                    current.name = hook
                if "policy" in fields:
                    current.policy = fields["policy"]
                    current.policy_stated = True
                current.header_raw = stripped
                current.header_line = number
                current.header_offset = offset
                continue
            if "policy" in fields and "action" not in fields:
                current.policy = fields["policy"]
                current.policy_stated = True
                continue
            if not fields.get("action") and not fields.get("logged") and not statement.lower().startswith("counter"):
                target.warnings.append((number, offset, raw))
                continue
            current.rules.append(
                Rule(
                    raw=raw,
                    line=number,
                    offset=offset,
                    fmt=NFT,
                    table=current.table,
                    chain=current.name,
                    action=fields.get("action", ""),
                    proto=fields.get("proto", ""),
                    src=fields.get("src", ""),
                    dst=fields.get("dst", ""),
                    sport=fields.get("sport", ""),
                    dport=fields.get("dport", ""),
                    in_if=fields.get("in_if", ""),
                    out_if=fields.get("out_if", ""),
                    stateful=fields.get("stateful", False),
                    nat_to=fields.get("nat_to", ""),
                    ipv6=fields.get("ipv6", False),
                )
            )

    target.chains = list(chains.values())
    target.meta["families"] = sorted(families)
    target.meta["covers_ipv6"] = bool(families & {"ip6", "inet"})
    return target


# --------------------------------------------------------------------- ufw ---

_UFW_CHAIN = {"IN": "INPUT", "OUT": "OUTPUT", "FWD": "FORWARD"}
_UFW_POLICY = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT", "disabled": "DROP"}


def parse_ufw(text: str, source: str = "") -> Target:
    target = Target(source=source, fmt=UFW)
    policies: dict[str, str] = {}
    defaults_raw = ""
    in_table = False

    for number, offset, raw in _line_iter(text):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("status:"):
            target.meta["status"] = stripped.split(":", 1)[1].strip().lower()
            continue
        if stripped.lower().startswith("logging:"):
            target.meta["logging"] = stripped.split(":", 1)[1].strip().lower().split()[0]
            continue
        if stripped.lower().startswith("default:"):
            defaults_raw = stripped
            for value, scope in re.findall(r"(\w+)\s*\((\w+)\)", stripped):
                chain = {"incoming": "INPUT", "outgoing": "OUTPUT", "routed": "FORWARD"}.get(scope.lower())
                if chain:
                    policies[chain] = _UFW_POLICY.get(value.lower(), "")
            continue
        if stripped.startswith("To") and "Action" in stripped:
            in_table = True
            continue
        if set(stripped) <= {"-", " "}:
            continue
        if not in_table:
            continue

        cells = re.split(r"\s{2,}", stripped)
        if len(cells) < 3:
            # Pasted `ufw status` output sometimes collapses the wide columns;
            # fall back to the fixed "VERB DIRECTION source" action shape.
            match = re.match(r"^(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(\S.*)$", stripped, re.I)
            if match:
                cells = [match.group(1), f"{match.group(2)} {match.group(3)}", match.group(4)]
            else:
                target.warnings.append((number, offset, raw))
                continue
        to_cell, action_cell, from_cell = cells[0].strip(), cells[1].strip(), cells[2].strip()

        ipv6 = "(v6)" in to_cell.lower() or "(v6)" in from_cell.lower()
        to_cell = re.sub(r"\s*\(v6\)", "", to_cell, flags=re.I).strip()
        from_cell = re.sub(r"\s*\(v6\)", "", from_cell, flags=re.I).strip()

        proto = ""
        dport = "" if to_cell.lower().startswith("anywhere") else to_cell
        if "/" in dport:
            dport, _, proto = dport.partition("/")
            proto = proto.lower()
        src = "any" if from_cell.lower().startswith("anywhere") else from_cell

        action_parts = action_cell.upper().split()
        action = action_parts[0] if action_parts else ""
        direction = action_parts[1] if len(action_parts) > 1 else "IN"
        chain_name = _UFW_CHAIN.get(direction, "INPUT")

        current = None
        for chain in target.chains:
            if chain.name == chain_name:
                current = chain
                break
        if current is None:
            current = Chain(name=chain_name, fmt=UFW, hooked=True, header_raw=defaults_raw)
            target.chains.append(current)

        current.rules.append(
            Rule(
                raw=raw,
                line=number,
                offset=offset,
                fmt=UFW,
                table="filter",
                chain=chain_name,
                action="ACCEPT" if action in ("ALLOW", "LIMIT") else ("DROP" if action == "DENY" else action),
                proto=proto,
                src=src,
                dport=_norm_ports(dport),
                ipv6=ipv6,
            )
        )

    for name in ("INPUT", "FORWARD", "OUTPUT"):
        chain = next((c for c in target.chains if c.name == name), None)
        if chain is None:
            chain = Chain(name=name, fmt=UFW, hooked=True, header_raw=defaults_raw)
            target.chains.append(chain)
        chain.policy = policies.get(name, "")
        chain.policy_stated = name in policies
        if not chain.header_raw:
            chain.header_raw = defaults_raw

    target.meta["covers_ipv6"] = any(rule.ipv6 for rule in target.rules)
    return target


# ------------------------------------------------------------------ public ---

def parse(text: str, source: str = "") -> Target:
    """Parse one file's text into a normalized Target."""
    fmt = detect_format(text, source)
    if fmt == UFW:
        return parse_ufw(text, source)
    if fmt == NFT:
        return parse_nft(text, source)
    if fmt == IPTABLES:
        return parse_iptables(text, source)
    target = Target(source=source, fmt="unknown")
    for number, offset, raw in _line_iter(text):
        if raw.strip():
            target.warnings.append((number, offset, raw))
    return target
