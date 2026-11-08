"""The images' pins, and what the updater's cosign build is anchored to.

Nothing visible breaks when one of these goes wrong (a drifted pin still installs, a forgotten
override still builds), so these tests are the only place it fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==(\S+)")
_SHA256 = "[0-9a-f]{64}"
_GIT_SHA = "[0-9a-f]{40}"
_SEMVER = r"v\d+\.\d+\.\d+"


def _pins(name: str) -> dict[str, str]:
    """Package name (normalised, extras dropped) to pinned version, for one requirements file."""
    lines = (ROOT / name).read_text().splitlines()
    matches = [_PIN.match(line.strip()) for line in lines]
    return {m.group(1).lower().replace("_", "-"): m.group(2) for m in matches if m}


def _updater_dockerfile() -> str:
    return (ROOT / "Dockerfile.updater").read_text()


def _runtime_stage(dockerfile: str) -> str:
    """The stage the image ships: everything after the last FROM."""
    return dockerfile[dockerfile.rindex("\nFROM ") :]


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


def test_cosign_is_built_from_the_commit_its_tag_pointed_at() -> None:
    # given the updater Dockerfile, which builds cosign from source (ARES-2046)
    dockerfile = _updater_dockerfile()

    # when the tag's commit pin is read
    commit = re.search(pattern=rf"^ARG COSIGN_COMMIT=({_GIT_SHA})$", string=dockerfile, flags=re.M)

    # then it is a full commit id and the clone is refused anywhere else: this is what stands in
    # for the release checksum the download used to be checked against
    assert commit, "no full commit id pinned for the cosign tag"
    assert re.search(r'actual="\$\(git -C /src rev-parse HEAD\)"', dockerfile)
    assert '"${actual}" != "${COSIGN_COMMIT}"' in dockerfile


def test_the_cosign_toolchain_is_pinned_and_cannot_fetch_another() -> None:
    # given the builder stage's base image
    dockerfile = _updater_dockerfile()
    builder = re.search(
        pattern=r"^FROM --platform=\$BUILDPLATFORM (\S+) AS cosign$", string=dockerfile, flags=re.M
    )

    # when it and the go environment are checked, then the image is pinned by digest and go may not
    # download the newer toolchain a go.mod could ask for
    assert builder, "no cosign builder stage"
    assert re.search(rf"@sha256:{_SHA256}$", builder.group(1)), builder.group(1)
    assert "GOTOOLCHAIN=local" in dockerfile


def test_the_compress_override_only_runs_while_upstream_ships_the_vulnerable_version() -> None:
    # given the override's two versions and where the guard and the `go get` sit
    dockerfile = _updater_dockerfile()
    upstream = re.search(
        pattern=rf"^ARG COSIGN_COMPRESS_UPSTREAM=({_SEMVER})$", string=dockerfile, flags=re.M
    )
    override = re.search(
        pattern=rf"^ARG COSIGN_COMPRESS_OVERRIDE=({_SEMVER})$", string=dockerfile, flags=re.M
    )
    guard_at = dockerfile.find('"${upstream}" != "${COSIGN_COMPRESS_UPSTREAM}"')
    override_at = dockerfile.find(
        'go get "github.com/klauspost/compress@${COSIGN_COMPRESS_OVERRIDE}"'
    )

    # then upstream's version is checked before it is raised: a cosign that already ships something
    # else must fail the build, or a later COSIGN_VERSION bump keeps the override (and may
    # downgrade compress)
    assert upstream and override, "the compress override's versions are not pinned"
    assert 0 <= guard_at < override_at, "the override is not guarded, or the guard runs after it"


def test_the_image_runs_the_cosign_it_built() -> None:
    # given the updater Dockerfile
    dockerfile = _updater_dockerfile()

    # then cosign comes from the builder stage, and no step downloads a release over it
    assert "COPY --from=cosign /out/cosign /usr/local/bin/cosign" in dockerfile
    assert "releases/download" not in dockerfile


def test_the_updater_image_knows_its_own_release_from_the_one_version_source() -> None:
    # given the updater Dockerfile
    dockerfile = _updater_dockerfile()

    # then it writes updater/RELEASE from agent/__version__.py, which main._is_backwards reads to
    # keep the updater from moving itself backwards; never from an ENV, which a successor would
    # inherit from the older updater that started it
    assert "COPY agent/__version__.py /tmp/release.py" in dockerfile
    assert "> updater/RELEASE" in dockerfile
    assert "test -s updater/RELEASE" in dockerfile
    assert "ARES_UPDATE_RELEASE" not in dockerfile


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.updater"])
def test_every_shipped_image_takes_alpines_current_packages(name: str) -> None:
    # given an image whose base, python:3.12-alpine, is rebuilt on its own schedule: on 2026-11-07
    # Alpine had zlib 1.4-r0 (CVE-2026-4738) while the base still had 1.3.2-r1 (ARES-2046)
    stage = _runtime_stage((ROOT / name).read_text())

    # when the runtime stage's first RUN is read, continuation lines included
    first = re.findall(pattern=r"^RUN ((?:.*\\\n)*.*)$", string=stage, flags=re.M)[0]

    # then it upgrades Alpine's packages, and does not end in a bare `|| true` (the agent's install
    # RUN used to, which hid a failed apk add)
    assert first.startswith("apk upgrade --no-cache"), f"{name}: first RUN is not apk upgrade"
    assert not re.search(pattern=r"\|\| true\s*$", string=first), f"{name}: a failure is masked"
