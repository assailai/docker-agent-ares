"""The updater image's pins and the anchors of its cosign build.

None of them breaks anything visible when it goes wrong: a drifted pin still installs, a moved tag
still clones, and a forgotten override still builds. So these tests are the only place any fails.
"""

from __future__ import annotations

import re
from pathlib import Path

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


def _updater_dockerfile() -> str:
    return (ROOT / "Dockerfile.updater").read_text()


def test_cosign_is_built_from_the_commit_its_tag_pointed_at() -> None:
    # given the updater Dockerfile, which builds cosign from source (ARES-2046)
    dockerfile = _updater_dockerfile()

    # when its source pin is read
    commit = re.search(pattern=rf"^ARG COSIGN_COMMIT=({_GIT_SHA})$", string=dockerfile, flags=re.M)

    # then the tag is pinned to a full commit id and the clone is refused unless it lands there,
    # which is what stands in for the release checksum a download was checked against
    assert commit, "no full commit id pinned for the cosign tag"
    assert re.search(r'actual="\$\(git -C /src rev-parse HEAD\)"', dockerfile)
    assert '"${actual}" != "${COSIGN_COMMIT}"' in dockerfile


def test_the_cosign_toolchain_is_pinned_and_cannot_fetch_another() -> None:
    # given the updater Dockerfile
    dockerfile = _updater_dockerfile()

    # when the builder stage's base image is read
    builder = re.search(
        pattern=r"^FROM --platform=\$BUILDPLATFORM (\S+) AS cosign$", string=dockerfile, flags=re.M
    )

    # then it is pinned by digest, and go may not swap in a toolchain a go.mod asks for
    assert builder, "no cosign builder stage"
    assert re.search(rf"@sha256:{_SHA256}$", builder.group(1)), builder.group(1)
    assert "GOTOOLCHAIN=local" in dockerfile


def test_the_compress_override_only_runs_while_upstream_ships_the_vulnerable_version() -> None:
    # given the updater Dockerfile
    dockerfile = _updater_dockerfile()

    # when the override and its guard are located
    upstream = re.search(
        pattern=rf"^ARG COSIGN_COMPRESS_UPSTREAM=({_SEMVER})$", string=dockerfile, flags=re.M
    )
    raised = re.search(
        pattern=rf"^ARG COMPRESS_VERSION=({_SEMVER})$", string=dockerfile, flags=re.M
    )
    guard = dockerfile.find('"${upstream}" != "${COSIGN_COMPRESS_UPSTREAM}"')
    override = dockerfile.find('go get "github.com/klauspost/compress@${COMPRESS_VERSION}"')

    # then the build checks upstream's version before raising it, so a cosign that already ships
    # something else fails the build instead of keeping (or downgrading through) a stale override
    assert upstream and raised, "the compress override's versions are not pinned"
    assert 0 <= guard < override, "the compress override is not guarded, or the guard runs after it"


def test_the_image_runs_the_cosign_it_built() -> None:
    # given the updater Dockerfile
    dockerfile = _updater_dockerfile()

    # then the binary on PATH is the builder stage's, and nothing downloads another
    assert "COPY --from=cosign /out/cosign /usr/local/bin/cosign" in dockerfile
    assert "releases/download" not in dockerfile
