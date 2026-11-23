"""Best-effort packet capture of the agent's OWN assessment traffic for one job.

Runs a bounded ``tcpdump`` scoped by a BPF host/net filter built from the VERIFIED job's target, for
the duration of the active probe, so the evidence is an agent-origin capture of the agent's own
traffic, never third-party sniffing. The bytes become a ``packet_capture`` artifact
(``assessment_artifact``) the control plane verifies and stores.

Two invariants make this safe to wire into the lab-proven collector:
  - OPT-IN: capture only runs when ``ARES_ASSESSMENT_PCAP`` is set, so the default agent is unchanged.
  - FAIL-SOFT: disabled, tcpdump missing, no capability, or any error returns ``None``; the assessment
    runs and reports exactly as before, and simply produces no artifact.

Needs ``CAP_NET_RAW`` in the container (the Dockerfile grants it; the rest of the posture stays
non-root). Without the capability tcpdump exits non-zero and ``stop`` returns ``None``, which is the
fail-soft path, not an error.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_ENV_FLAG = "ARES_ASSESSMENT_PCAP"
_TCPDUMP = "tcpdump"
_MAX_PCAP_BYTES = 32 * 1024 * 1024  # a job's own traffic is small; bound a runaway capture
_MAX_PACKETS = 50_000
_START_GRACE_S = 0.5  # let tcpdump bind before the probe opens its first socket
_STOP_TIMEOUT_S = 5.0


def is_enabled() -> bool:
    """Capture is strictly opt-in, so the default agent behaviour (and the accuracy lab's proven
    collector) is unchanged unless an operator turns it on."""
    return os.environ.get(_ENV_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


def bpf_for_targets(targets: list[str]) -> str | None:
    """A BPF host/net filter over the job's targets, or ``None`` if none are valid. Each target is
    validated with :mod:`ipaddress` so a malformed scope cannot build a bad filter, and the filter is
    passed to tcpdump as a single argv element (never a shell string), so there is no injection seam."""
    terms: list[str] = []
    for raw in targets:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            terms.append(f"host {net.network_address}")
        else:
            terms.append(f"net {net.with_prefixlen}")
    return " or ".join(terms) if terms else None


class Capture:
    """A running capture. ``stop`` terminates tcpdump and returns the pcap bytes, or ``None``."""

    def __init__(self, proc: asyncio.subprocess.Process, path: str) -> None:
        self._proc = proc
        self._path = path

    async def stop(self) -> bytes | None:
        with contextlib.suppress(ProcessLookupError):
            self._proc.terminate()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=_STOP_TIMEOUT_S)
        except (TimeoutError, asyncio.TimeoutError):
            with contextlib.suppress(ProcessLookupError):
                self._proc.kill()
        try:
            data = Path(self._path).read_bytes()
        except OSError:
            data = b""
        finally:
            with contextlib.suppress(OSError):
                os.unlink(self._path)
        # A capture with only the pcap global header (24 bytes) and no packets is not evidence; and an
        # oversize file is dropped rather than uploaded.
        if len(data) <= 24 or len(data) > _MAX_PCAP_BYTES:
            return None
        return data


async def start(targets: list[str]) -> Capture | None:
    """Start a bounded tcpdump scoped to ``targets``, or ``None`` when capture is disabled, the scope
    is empty, or tcpdump cannot be launched. Fail-soft: never raises."""
    if not is_enabled():
        return None
    bpf = bpf_for_targets(targets)
    if bpf is None:
        return None
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="ares-assessment-")
    os.close(fd)
    args = [_TCPDUMP, "-i", "any", "-w", path, "-c", str(_MAX_PACKETS), "-U", "-n", bpf]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError) as exc:
        logger.info("pcap capture unavailable (%s); continuing without it", type(exc).__name__)
        with contextlib.suppress(OSError):
            os.unlink(path)
        return None
    await asyncio.sleep(_START_GRACE_S)
    return Capture(proc, path)
