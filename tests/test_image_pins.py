"""What the two images install, held to what the test suite actually exercises.

The updater used to `pip install httpx pydantic-settings` unpinned, so it shipped whatever PyPI
served on the day of the build while the tests ran against requirements.txt. And its cosign, the
binary that decides what may run next to the Docker socket, was downloaded with no checksum. Both
are leak-on-forget: nothing fails when a pin drifts or a checksum goes missing, so these do.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==(\S+)")


def _pins(name: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (ROOT / name).read_text().splitlines():
        m = _PIN.match(line.strip())
        if m:
            pins[m.group(1).lower().replace("_", "-")] = m.group(2)
    return pins


def test_every_updater_dependency_is_pinned_to_the_version_the_agent_tests_run() -> None:
    agent = _pins("requirements.txt")
    updater = _pins("requirements-updater.txt")

    assert updater, "requirements-updater.txt pins nothing"
    drifted = {pkg: (ver, agent.get(pkg)) for pkg, ver in updater.items() if agent.get(pkg) != ver}
    assert not drifted, f"updater pins differ from requirements.txt (updater, agent): {drifted}"


def test_the_updater_installs_from_its_pinned_file_not_a_bare_package_list() -> None:
    dockerfile = (ROOT / "Dockerfile.updater").read_text()

    assert "pip install --no-cache-dir -r /tmp/requirements-updater.txt" in dockerfile
    assert not re.search(r"pip install[^\n]*\bhttpx\b", dockerfile)


def test_cosign_is_checksum_verified_for_every_architecture_the_image_is_built_for() -> None:
    dockerfile = (ROOT / "Dockerfile.updater").read_text()
    workflow = (ROOT / ".github/workflows/docker-build.yml").read_text()
    built = set(re.findall(r"linux/(\w+)", workflow))

    assert built, "could not read the build platforms from docker-build.yml"
    for arch in built:
        m = re.search(rf"^ARG COSIGN_SHA256_{arch.upper()}=([0-9a-f]+)$", dockerfile, re.M)
        assert m and len(m.group(1)) == 64, f"no pinned sha256 for cosign-linux-{arch}"
    assert "sha256sum -c -" in dockerfile
