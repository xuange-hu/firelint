# firelint rules

20 rules (4 critical, 3 high, 8 medium, 5 low), in three passes: `lines` reads one rule at a time,
`chains` reads chain defaults and ordering, `relations` reads the gaps between files and families.

## FWL101

**Unconditional allow from anywhere**

- severity: critical (score 10/10)
- pass: lines

An inbound ACCEPT with no match expression (or protocol `all`) matches every packet from every source on every port. Whatever the chain's other rules say, this line alone turns the firewall off for that chain.

**Fix:** Delete the rule, or narrow it to the protocol, port and source that actually need the traffic.

## FWL102

**Management port exposed to anywhere**

- severity: critical (score 10/10)
- pass: lines

SSH, RDP, VNC, database and container-runtime ports are management planes, not services. An ACCEPT from `any` on one of these ports puts credentials directly on the internet; the scanning noise on port 22 alone starts within minutes of exposure.

**Fix:** Restrict the source to a jump host / VPN / allowlist CIDR, or move access behind a bastion.

## FWL103

**Service port exposed to anywhere**

- severity: medium (score 5/10)
- pass: lines

A service port open to `any` is only safe if the service behind it is meant to face the whole internet and is patched like it. Most such rules are leftovers from a quick test.

**Fix:** Confirm the service is intentionally public; otherwise restrict the source or close the port.

## FWL104

**Wide destination-port range from anywhere**

- severity: medium (score 5/10)
- pass: lines

A destination-port range wider than 1024 ports is not a service allowlist, it is a hole with a label. It hides real services inside noise and expands any future service compromise to the whole range.

**Fix:** Enumerate the actual ports. If the range is for passive FTP or RPC, pin the range to the smallest that works.

## FWL105

**Stateless inbound allow**

- severity: medium (score 5/10)
- pass: lines

An inbound ACCEPT with no connection-state match (`-m state/--ctstate`, `ct state`) lets forged packets in through the same door as legitimate sessions. Stateless allows also break INVALID-drop discipline, which is what keeps spoofed scans out.

**Fix:** Add `-m conntrack --ctstate NEW` (or `ct state new`) on the allow and keep an ESTABLISHED accept plus an INVALID drop in the chain.

## FWL106

**Allow filtered only by source port**

- severity: low (score 2/10)
- pass: lines

Source ports are chosen freely by any client stack; a filter that only constrains `--sport` matches effectively everything. It reads like a rule but enforces almost nothing.

**Fix:** Filter on destination port instead; drop the source-port condition unless it is paired with a state match.

## FWL107

**DNAT/redirect from anywhere**

- severity: high (score 8/10)
- pass: lines

A DNAT or redirect with no source restriction forwards *all* traffic for that port into an internal host. The internal service inherits the exposure of the router, usually without its own hardening or monitoring.

**Fix:** Pin the DNAT source to the intended client networks, and filter the forwarded traffic in the forward chain as well.

## FWL108

**Protocol-wide allow from anywhere**

- severity: medium (score 5/10)
- pass: lines

An ACCEPT for all TCP or all UDP ports from `any` is a full protocol exposure. On UDP it is worse: connectionless transports are the raw material for reflection and amplification abuse.

**Fix:** Name the ports the service actually listens on; for UDP, restrict sources wherever possible.

## FWL109

**Rule the auditor could not parse**

- severity: low (score 2/10)
- pass: lines

A line that no parser understands is a line no audit covers. It is usually a truncated edit or a hand-merged ruleset — exactly the state where a silent open port lives.

**Fix:** Re-render the ruleset with the native tool (iptables-save / nft list ruleset) and diff against the stored copy.

## FWL201

**INPUT default policy ACCEPT**

- severity: critical (score 10/10)
- pass: chains

A chain default of ACCEPT means every packet not matched by a later rule is allowed. One deleted rule, one failed reload, one new interface — and the host is open. Deny-by-default is the single cheapest property a host firewall has.

**Fix:** Set the INPUT policy to DROP and allow explicitly: `iptables -P INPUT DROP` / `policy drop;` / `ufw default deny incoming`.

## FWL202

**FORWARD default policy ACCEPT**

- severity: critical (score 10/10)
- pass: chains

FORWARD ACCEPT turns every host with routing enabled into an open router. On cloud instances and lab machines with two interfaces this is a classic pivot path — and container bridges make every container a routed neighbour.

**Fix:** Set the FORWARD policy to DROP and allow only the flows that must transit (`iptables -P FORWARD DROP`).

## FWL203

**Unreachable rules after an unconditional verdict**

- severity: medium (score 5/10)
- pass: chains

Once a rule with no match expression jumps to ACCEPT/DROP/REJECT, nothing below it in the chain can ever fire. The dead rules are usually the intended policy — the live line above them is the mistake.

**Fix:** Move the unconditional verdict to the end of the chain, or delete the lines that can never match.

## FWL204

**Attached chain with no explicit policy**

- severity: high (score 8/10)
- pass: chains

An nftables chain attached to a hook without a `policy` statement defaults to ACCEPT — silently. The ruleset looks like a filter but the default is allow; the same file with one word added behaves completely differently.

**Fix:** State the policy explicitly on every hooked chain: `type filter hook input priority 0; policy drop;`.

## FWL205

**No INVALID-state drop**

- severity: medium (score 5/10)
- pass: chains

Packets in the INVALID conntrack state are exactly what forged scans and out-of-state probes look like. A chain that allows traffic but never drops INVALID hands that reconnaissance channel to anyone who asks.

**Fix:** Add early in the chain: `-m conntrack --ctstate INVALID -j DROP` (or `ct state invalid drop`).

## FWL206

**No logging in the ruleset**

- severity: low (score 2/10)
- pass: chains

A firewall without logging can neither be tuned nor investigated. When the inevitable 'why is this blocked' call comes, there is no evidence either way.

**Fix:** Log dropped traffic at least: a LOG rule before the final DROP (rate-limited), or `ufw logging on`.

## FWL207

**Logging without a drop**

- severity: low (score 2/10)
- pass: chains

Log rules in a chain that ends in ACCEPT (and has no DROP) record traffic that is then allowed anyway. The log looks like a filter and bills like a filter; it is only a witness.

**Fix:** Pair each LOG rule with the DROP/REJECT it is meant to document, or set the chain policy to DROP.

## FWL301

**IPv4 rules with no IPv6 coverage**

- severity: high (score 8/10)
- pass: relations

IPv6 is enabled on every modern host and is not covered by a single iptables rule. A service locked down for IPv4 is reachable over IPv6 with the default allow policy — the firewall is not wrong, it is simply looking at the wrong family.

**Fix:** Mirror the policy for IPv6 (ip6tables / `table ip6` / `table inet`), or disable IPv6 explicitly if it is unused.

## FWL302

**ufw and raw iptables rulesets coexist**

- severity: medium (score 5/10)
- pass: relations

ufw is a front-end that generates iptables rules. Hand-written iptables rules live in the same tables and are wiped or reordered by the next `ufw reload`. Two writers, one ruleset: the surviving order is whatever ran last.

**Fix:** Pick one owner. If ufw owns the host, move custom rules into ufw's before/after rules files (`/etc/ufw/before.rules`).

## FWL303

**iptables and nftables rulesets coexist**

- severity: medium (score 5/10)
- pass: relations

On hosts with both stacks, packet verdicts depend on hook priorities across two subsystems. iptables-nft translation layers and legacy `iptables` binaries make the effective order impossible to read from either file alone — the classic source of 'the rule is there but does nothing'.

**Fix:** Standardise on one stack (nftables with the iptables-nft compatibility layer, or pure iptables-legacy) and delete the other's ruleset.

## FWL304

**ufw inactive but rules are listed**

- severity: low (score 2/10)
- pass: relations

When ufw reports `Status: inactive`, none of the listed rules is enforced. The file reads like protection; the kernel enforces nothing. This is the gap that survives audits, because the documentation and the enforcement are reviewed by different people.

**Fix:** `ufw enable` if the rules are the intended policy, or delete them so the file cannot lie.
