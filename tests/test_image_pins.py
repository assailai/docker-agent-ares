"""The updater image's pins and its cosign checksum.

Neither breaks anything visible when it goes wrong: a drifted pin still installs, and a missing
checksum still downloads. So these tests are the only place either fails.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==(\S+)")
# a sha256 digest as cosign_checksums.txt writes it: 64 lowercase hex characters
_SHA256 = "[0-9a-f]{64}"


def _pins(name: str) -> dict[str, str]:
    """Package name (normalised, extras dropped) to pinned version, for one requirements file."""
    lines = (ROOT / name).read_text().splitlines()
    matches = [_PIN.match(line.strip()) for line in lines]
    return {m.group(1).lower().replace("_", "-"): m.group(2) for m in matches if m}


def test_updater_pins_match_what_the_agent_tests_run_against() -> None:
    # given the two requirements files
    agent = _pins("requirements.txt")
    updater = _pins("requirements-updater.txt")

    # when the updater's pins are compared to the agent's
    drifted = {pkg: (ver, agent.get(pkg)) for pkg, ver in updater.items() if agent.get(pkg) != ver}

    # then every updater pin is the version the test suite ran
    assert updater, "requirements-updater.txt pins nothing"
    assert not drifted, f"updater pins differ from requirements.txt (updater, agent): {drifted}"


def test_every_pip_install_in_the_updater_image_reads_the_pinned_file() -> None:
    # given the updater Dockerfile
    dockerfile = (ROOT / "Dockerfile.updater").read_text()

    # when its pip installs are collected
    installs = re.findall(r"pip install([^\n]*)", dockerfile)
    unpinned = [args for args in installs if "-r /tmp/requirements-updater.txt" not in args]

    # then each one installs from the pinned file, never a bare package list
    assert installs, "Dockerfile.updater installs no Python packages"
    assert not unpinned, f"pip install without the pinned file: {unpinned}"


def test_cosign_is_checksum_verified_for_every_architecture_the_image_is_built_for() -> None:
    # given the architectures docker-build.yml builds
    dockerfile = (ROOT / "Dockerfile.updater").read_text()
    workflow = (ROOT / ".github/workflows/docker-build.yml").read_text()
    built = set(re.findall(r"linux/(\w+)", workflow))

    # when the Dockerfile is searched for a pinned checksum per architecture
    missing = [
        arch
        for arch in sorted(built)
        if not re.search(
            pattern=rf"^ARG COSIGN_SHA256_{arch.upper()}={_SHA256}$", string=dockerfile, flags=re.M
        )
    ]

    # then each has one, and the build actually checks it
    assert built, "could not read the build platforms from docker-build.yml"
    assert not missing, f"no pinned sha256 for cosign-linux-{missing}"
    assert "sha256sum -c -" in dockerfile
