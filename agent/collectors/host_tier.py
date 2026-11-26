"""Route a credentialed host control to the host collector that owns it.

A collect job carries a mix of control ids and the control plane does not tag them by family: the
agent decides, by prefix, which collector reads each one. The device tier (``vendor``) handles
``net.*`` from a running-config; this host tier handles everything read from a host's own config over
SSH, and there is now more than one host family (``server.*`` hardening in :mod:`linux_host`,
``storage.nfs.*`` in :mod:`storage_host`, ...). This module is the single seam :mod:`agent.main`
routes the host tier through, so adding a host family is one import here plus its module, never a
change to the collect partition.

Each host collector exposes the same small interface (``serves`` / ``source_for`` /
``collect_control_fields`` and a ``SOURCE_READERS`` map), so aggregating them is mechanical: a control
is owned by exactly one module (prefixes do not overlap), and the evidence sources are globally unique
so the merged reader map never clobbers.
"""

from __future__ import annotations

from types import ModuleType

from agent.collectors import database_host, linux_host, storage_host

# Every host collector family. A control_id is served by at most one of these (prefixes are disjoint),
# so the iteration order is only a never-triggered tie-break.
_HOST_COLLECTORS: tuple[ModuleType, ...] = (linux_host, storage_host, database_host)

# The merged evidence-source -> ssh_collect reader-function-name map across every host family. Source
# keys are globally unique, so the merge is loss-free; main.py reads each needed source once through
# this map.
SOURCE_READERS: dict[str, str] = {
    source: reader
    for module in _HOST_COLLECTORS
    for source, reader in module.SOURCE_READERS.items()
}


def _module_for(control_id: str) -> ModuleType | None:
    """The one host collector that serves ``control_id``, or ``None`` when no host family does (so the
    control falls through to the device tier)."""
    for module in _HOST_COLLECTORS:
        if module.serves(control_id):
            return module
    return None


def serves(control_id: str) -> bool:
    """Whether any host collector reads ``control_id`` (so the dispatcher routes it to the host tier
    rather than the device running-config)."""
    return _module_for(control_id) is not None


def source_for(control_id: str) -> str | None:
    """The single evidence source ``control_id`` is read from across the host families, or ``None`` if
    no host collector serves it."""
    module = _module_for(control_id)
    return module.source_for(control_id) if module else None


def sources_for(control_ids: list[str]) -> set[str]:
    """The distinct evidence sources needed to collect the host controls among ``control_ids``, so the
    agent runs each host command at most once."""
    return {src for cid in control_ids if (src := source_for(cid)) is not None}


def collect_control_fields(sources: dict[str, str], control_id: str) -> dict[str, object] | None:
    """The typed field values for ``control_id`` from the collected evidence, delegated to the host
    collector that owns it, or ``None`` if no host family serves it."""
    module = _module_for(control_id)
    return module.collect_control_fields(sources, control_id) if module else None
