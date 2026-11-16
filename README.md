# firelint

[![tests](https://img.shields.io/badge/tests-109-brightgreen)](https://github.com/xuange-hu/firelint/actions)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/xuange-hu/firelint/blob/main/pyproject.toml)

**Zero-dependency firewall ruleset auditor for iptables, nftables and ufw.**
Three passes — rules, chains, relations — and every conclusion points at the
exact line that produced it.

```console
$ firelint scan rules.v4
CRITICAL FWL201  INPUT default policy is ACCEPT: unmatched packets are allowed
         at rules.v4:2 (offset 22, len 24)
         saw: :INPUT ACCEPT [0:0]
         fix: Set the INPUT policy to DROP and allow explicitly: `iptables -P INPUT DROP` / `policy drop;` / `ufw default deny incoming`.
...
42 finding(s) across 4 ruleset(s): 9 critical, 3 high, 23 medium, 7 low
```

## Why another firewall tool?

Because the existing ones fall into three camps and none of them is this one:

| | what it is | why it is not enough |
|---|---|---|
| `iptables -L -n` | the live state | says *what* the rules are, never whether they are wrong |
| firewall UIs / cloud consoles | per-rule editing | no cross-rule reasoning: shadowing, defaults, IPv6 gaps |
| heavyweight audit suites | agent + server + dashboard | you cannot run them on the box you just inherited |

firelint is a single Python package with **zero runtime dependencies**. It
reads a ruleset dump — the thing every machine can produce, including ones
where `apt` is a fond memory — and reasons about it offline. It runs in CI, on
a bastion, in an incident-response shell, and inside your editor's agent.

## Quickstart

```console
# 1. get it (no dependencies to resolve)
pip install git+https://github.com/xuange-hu/firelint

# 2. dump a ruleset on the target host (any one of these)
iptables-save > rules.v4
nft list ruleset > ruleset.nft
ufw status verbose > ufw.txt

# 3. audit it
firelint scan rules.v4 ruleset.nft ufw.txt
```

Nothing to configure. No daemon. No network calls.

## The three passes

**`lines` — one rule at a time.** What does *this* line expose?
World-open management ports (FWL102), stateless allows (FWL105), DNAT from
anywhere (FWL107), source-port-only filters (FWL106).

**`chains` — defaults and ordering.** `INPUT` policy ACCEPT (FWL201), rules
that can never fire because an unconditional verdict sits above them
(FWL203), hooked chains with no stated policy (FWL204 — nftables defaults
those to ACCEPT), traffic that is logged and then allowed anyway (FWL207).

**`relations` — between files and families.** IPv4 rules with zero IPv6
coverage (FWL301: the firewall is not wrong, it is looking at the wrong
family), ufw fighting raw iptables in the same tables (FWL302), iptables and
nftables stacked on the same host (FWL303), `ufw inactive` while listing
allow rules (FWL304).

20 rules, each with why-it-matters prose and a concrete fix:
[`docs/rules.md`](docs/rules.md). Rule overlap is deliberate — an exposed
port can be both an exposure and a stateless allow, and both concerns deserve
their own tracking.

## What it reads

| format | how to produce it | notes |
|---|---|---|
| iptables-save | `iptables-save` / `ip6tables-save` | all tables: filter, nat, mangle, raw |
| nftables | `nft list ruleset` | families `ip`, `ip6`, `inet`; inline sets; `dnat to` |
| ufw | `ufw status verbose` | status, logging, defaults, allow/deny rows, `(v6)` rows |

A line no parser understands becomes an **FWL109 finding**, never a silent
skip — "the auditor ignored half my ruleset" is worse than "the auditor is
confused by one line".

## Evidence first

Every finding carries the file, line, offset, length and the raw text it
judged:

```console
HIGH     FWL301  every rule in scope is IPv4; nothing constrains IPv6, which the kernel still accepts by default
         at rules.v4:6 (offset 78, len 44)
         saw: -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
         fix: Mirror the policy for IPv6 (ip6tables / `table ip6` / `table inet`), or disable IPv6 explicitly if it is unused.
```

Conclusions are meant to be re-checked by hand in ten seconds, not trusted.

## CI integration

```console
firelint scan rules.v4 --fail-on high          # exit 1 on high/critical
firelint scan rules.v4 --format sarif > firelint.sarif
```

Exit codes: `0` clean (or below `--fail-on`), `1` gate tripped, `2` usage
error. `--fail-on none` always exits 0 — use it for `--format json` calls that
only collect output.

## MCP server (Claude Code / Cursor / Cline)

Six tools — `firelint_scan`, `firelint_demo`, `firelint_rules`,
`firelint_explain`, `firelint_parse`, `firelint_defaults`:

```console
uvx --from "git+https://github.com/xuange-hu/firelint" --with "mcp>=1.2,<2" firelint-mcp
```

Register in your MCP client config:

```json
{
  "mcpServers": {
    "firelint": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/firelint", "--with", "mcp>=1.2,<2", "firelint-mcp"]
    }
  }
}
```

The server pins `mcp>=1.2,<2` on purpose: mcp 2.x renamed `FastMCP` and moved
its import path.

## Demo

```console
$ firelint demo
```

Runs a built-in corpus — one careless firewall, four dumps — that triggers
all 20 rules (42 findings: 9 critical, 3 high, 23 medium, 7 low). The corpus
is embedded in the package and pinned by the test suite, so the demo can
never drift from the rules.

## Design notes

- **Zero dependencies is a feature, not a flex.** The audit has to run on the
  machine being audited. `pip install firelint` pulls in nothing.
- **Normalized model.** Three dialects parse into one rule shape (verdict,
  proto, addresses, ports, state, interfaces); the rule engine never branches
  on syntax.
- **Deterministic.** Same input, same output, byte for byte. No LLM, no
  network, no clock.
- **exit-code contract is tested**, both directions, with real files.

## License

MIT — see [LICENSE](LICENSE).
