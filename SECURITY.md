# Security policy

## Reporting a vulnerability

Open a private security advisory on GitHub (Security → Advisories → Report a
vulnerability), or email the maintainer through the address on the GitHub
profile. Please include:

- the version (or commit) you tested,
- a minimal ruleset that reproduces the problem,
- what firelint concluded and what the correct conclusion should be.

You will get an acknowledgement within 72 hours.

## What counts as a security issue

firelint reads firewall rulesets and prints conclusions. The security-relevant
failure modes are:

- **False negatives on dangerous rulesets** — a configuration that is clearly
  world-open but produces no finding. This is the top priority class.
- **Crashes on hostile input** — ruleset files are attacker-influenced in
  incident-response scenarios; a crafted file must not execute code or read
  outside the file given.
- **Dependency confusion** — the package must stay dependency-free; any
  runtime dependency addition is treated as a security-relevant change.

False positives and rule-prose issues are regular bugs (open an issue).

## Scope

firelint is an offline static auditor. It never touches live firewall state,
never needs root, and makes no network calls. It is meant for defensive audit
of systems you are authorised to assess.
