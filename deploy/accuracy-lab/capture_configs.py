"""Capture each lab node's running-config, for the credentialed accuracy score. Runs ON the lab host.

The host reaches the cEOS/FRR containers directly, so this shells out to each node's read-only config
command (`Cli -p 15 -c 'show running-config'` for Arista EOS, `vtysh -c 'show running-config'` for
FRR) and prints {node: running_config} as JSON on stdout. Host Python is 3.9 and this uses only the
stdlib, so it runs there; `score_credentialed.py` then parses the captured configs locally under 3.12
with the real agent collectors. Read-only: no config command here changes device state.
"""
from __future__ import annotations

import json
import subprocess

_PREFIX = "clab-ares-netassess-ceos-"
_NODES = {
    "frr-access": ["vtysh", "-c", "show running-config"],
    "frr-edge": ["vtysh", "-c", "show running-config"],
    "core-switch": ["Cli", "-p", "15", "-c", "show running-config"],
    "access-switch": ["Cli", "-p", "15", "-c", "show running-config"],
    "edge-router": ["Cli", "-p", "15", "-c", "show running-config"],
}


def main() -> int:
    out: dict[str, str] = {}
    for node, command in _NODES.items():
        result = subprocess.run(
            ["docker", "exec", f"{_PREFIX}{node}", *command],
            capture_output=True,
            text=True,
            timeout=30,
        )
        out[node] = (
            result.stdout
            if result.returncode == 0
            else f"__ERROR__ rc={result.returncode} {result.stderr[:200]}"
        )
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
