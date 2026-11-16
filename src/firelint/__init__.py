"""firelint — zero-dependency firewall ruleset auditor.

Parses iptables-save, ``nft list ruleset`` and ``ufw status verbose`` output
into one normalized rule model, then reasons about it in three passes:

* ``lines``     — one rule at a time (world-open ports, stateless allows)
* ``chains``    — chain defaults and ordering (policy accept, dead rules)
* ``relations`` — between files and families (IPv6 gaps, mixed firewall stacks)
"""

from .__about__ import __version__

__all__ = ["__version__"]
