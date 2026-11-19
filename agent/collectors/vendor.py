"""Route a collected running-config to the vendor parser whose grammar it matches.

The agent reads a device's config once and normalises it per control. Which parser normalises it is
decided by the config's own grammar, not by a caller-declared vendor, so a mislabelled device cannot
be parsed by the wrong grammar. Each vendor parser returns the same executable-control fields.
"""

from __future__ import annotations

from agent.collectors import arista, frr

# A marker only that vendor's running-config carries. FRR stamps `frr version` at the top; Arista EOS
# is the default when no more specific grammar matches.
_FRR_MARKER = "frr version "


def collect_control_fields(running_config: str, control_id: str) -> dict[str, object] | None:
    """Normalise ``control_id``'s fields from ``running_config`` using the matching vendor parser."""
    if _FRR_MARKER in running_config:
        return frr.collect_control_fields(running_config, control_id)
    return arista.collect_control_fields(running_config, control_id)
