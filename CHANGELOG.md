# Changelog

## 0.1.0 — 2026-11-17

First release.

- Three parsers into one normalized rule model: iptables-save (all tables),
  `nft list ruleset` (ip/ip6/inet families, inline sets, dnat/snat/redirect),
  `ufw status verbose` (status, logging, defaults, rows including `(v6)`).
- 20 rules in three passes: `lines` (FWL101–FWL109), `chains` (FWL201–FWL207),
  `relations` (FWL301–FWL304). Evidence-first findings with file, line,
  offset, length and raw text.
- Unparseable lines surface as FWL109 instead of being dropped.
- CLI: `firelint scan|rules|demo|explain`, text/json/sarif output,
  `--fail-on` exit-code gate (both directions tested with real files).
- MCP server (`firelint-mcp`) with 6 tools for Claude Code / Cursor / Cline,
  pinned to `mcp>=1.2,<2`.
- Embedded demo corpus that triggers all 20 rules (42 findings), pinned by
  the test suite.
- Zero runtime dependencies, Python 3.10+.
