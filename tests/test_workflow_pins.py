"""What the release workflows are allowed to run, and with what rights.

Nothing visible breaks when one of these goes wrong, which is the whole problem: a workflow that
loads a third-party action by a tag the upstream can move keeps working perfectly right up to the
moment someone else decides what it runs. The signing job holds the Docker Hub token and
`id-token: write`, so code that lands in it can push and cosign-sign under the identity every
deployed updater trusts. That is the 2025 tj-actions/changed-files shape, and these tests are the
only place it fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parent.parent / ".github/workflows").glob("*.yml"))
# `uses:` with its ref, as a step or a reusable-workflow call. Local `./...` calls have no ref.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s+(?P<ref>\S+)", re.M)
_SHA_PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")


def _uses(workflow: Path) -> list[str]:
    return _USES.findall(workflow.read_text())


def test_there_are_workflows_to_check() -> None:
    # the glob silently passing is the one way every test below becomes a no-op
    assert WORKFLOWS, "no workflows found"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_third_party_action_is_pinned_to_a_commit(workflow: Path) -> None:
    # given every action this workflow loads
    refs = _uses(workflow)

    # when the ones from outside this repository are picked out (a ./ reference is this repo's own
    # file at this repo's own commit, so there is nothing for an upstream to move)
    external = [ref for ref in refs if not ref.startswith("./")]

    # then each resolves to a full commit id, never a tag. The version lives in a trailing comment
    # so Dependabot can still propose the bump, as a reviewable change rather than a silent one.
    unpinned = [ref for ref in external if not _SHA_PINNED.match(ref)]
    assert not unpinned, f"{workflow.name}: tag-pinned action(s): {unpinned}"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_pinned_action_records_the_version_it_is(workflow: Path) -> None:
    # given the lines that pin an action by commit
    lines = [
        line
        for line in workflow.read_text().splitlines()
        if re.search(r"uses:\s+[^.\s][^\s]*@[0-9a-f]{40}", line)
    ]

    # then each carries the version as a comment: a bare 40-hex id tells a reviewer nothing, and
    # Dependabot reads that comment to know what it is bumping from
    missing = [line.strip() for line in lines if not re.search(r"#\s*v?\d+\.\d+", line)]
    assert not missing, f"{workflow.name}: pinned without a version comment: {missing}"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_declares_its_permissions(workflow: Path) -> None:
    # given the workflow source
    text = workflow.read_text()

    # then it says what the GITHUB_TOKEN may do, at the workflow or the job level. Without a
    # block it takes the repository default, which an org setting can widen underneath it with no
    # change here - tests.yml ran that way until ARES-2327.
    assert re.search(r"^\s*permissions:\s*$", text, re.M), (
        f"{workflow.name}: no permissions: block, so it runs with the repository default"
    )
