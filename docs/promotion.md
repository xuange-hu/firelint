# Promotion copy (drafts — pending maintainer approval before posting)

## Show HN

**Title:** Show HN: firelint – zero-dependency firewall ruleset auditor (iptables/nftables/ufw)

**Body:**

Hi HN — I built firelint because every time I inherited a Linux box I wanted
to answer one question ("is this firewall actually protecting anything?")
and every existing answer required either a live system, a GUI, or an agent.

firelint is a single zero-dependency Python package. You feed it a ruleset
dump (`iptables-save`, `nft list ruleset`, `ufw status verbose`) and it
reasons about it in three passes:

- rule level: world-open management ports, stateless allows, DNAT from anywhere
- chain level: INPUT/FORWARD policy ACCEPT, rules that can never fire after an
  unconditional verdict, nftables hooked chains with no stated policy (they
  default to ACCEPT silently)
- relations: IPv4 rules with zero IPv6 coverage (the classic bypass), ufw and
  raw iptables fighting over the same tables, inactive ufw with live-looking rules

Everything is evidence-first: each finding carries file, line, offset and the
raw text it judged, so you can re-verify by hand in seconds. There's an
embedded demo corpus that triggers all 20 rules, and an MCP server so your
editor agent can audit rulesets too.

It runs in CI with `--fail-on high` and SARIF output. No daemon, no network
calls, no config.

Curious what I'm missing — especially if you've fought nftables hook
priorities in production.

## Reddit r/netsec

**Title:** firelint: zero-dependency static auditor for iptables/nftables/ufw rulesets (20 rules, evidence-first, SARIF + MCP)

**Body:**

Wrote a small tool for a recurring IR/hardening pain: auditing a firewall
ruleset you can only see as text. Parses iptables-save, `nft list ruleset`
and `ufw status verbose` into one normalized model, then runs 20 rules in
three passes (per-rule exposure / chain defaults and ordering / cross-family
relations like missing IPv6 coverage).

Design choices that might interest the sub:

- unparseable lines become findings (FWL109), never silent skips
- findings carry byte offsets and the raw line — built to be re-checked, not trusted
- zero runtime dependencies on purpose: it has to run on the box you just inherited
- the exit-code gate is tested in both directions with real files
- `--format sarif` for CI, plus an MCP server (6 tools) for agent workflows

MIT, Python 3.10+. Feedback on rule quality welcome — especially false
positive patterns you've seen with Docker-managed iptables chains.

## X (thread)

1/ New open-source tool: firelint — a zero-dependency auditor for firewall
rulesets (iptables / nftables / ufw). Feed it a dump, get evidence-first
findings with line numbers. 20 rules, 3 passes, 109 tests. MIT.

2/ The three passes: rules (world-open ports, stateless allows, open DNAT) →
chains (policy ACCEPT defaults, unreachable rules, nft chains that silently
default to accept) → relations (IPv6 gaps, ufw vs raw iptables conflicts).

3/ Design rule I care about most: a line the parser can't understand becomes
a finding, not a silent skip. Half-audited rulesets are how "the firewall was
fine" incidents happen.

4/ Ships with an embedded demo corpus that triggers all 20 rules, SARIF for
CI, `--fail-on` gates, and an MCP server so Claude Code / Cursor can audit
rulesets directly.

github.com/xuange-hu/firelint
