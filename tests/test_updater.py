"""Companion updater: image-ref parsing, target read, the signature gate, and the backends."""

from __future__ import annotations

import json
import os
import re
import types
from pathlib import Path

import httpx
import pytest

from updater import dockerd, kube, main, tlsconf, verify
from updater.backend import Role, SelfInspection, UpdatePlan
from updater.config import UpdaterSettings, repo_of, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


@pytest.fixture(autouse=True)
def _clear_verified_cache(monkeypatch: pytest.MonkeyPatch):
    # the verified-digest caches and the retry clock are module globals; isolate them between tests.
    main._verified.clear()
    main._verified_self.clear()
    main._self_retry_after.clear()
    main._declined_downgrades.clear()
    monkeypatch.setattr(main, "_predecessor_removed", False)
    yield


def test_container_name_reads_the_documented_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # the docs / compose / k8s use ARES_UPDATE_CONTAINER; it must actually set container_name
    # (reading only the *_NAME alias was a silent-misconfig bug).
    monkeypatch.setenv("ARES_UPDATE_CONTAINER", "custom-agent")
    assert _settings().container_name == "custom-agent"


def test_image_ref_parsing() -> None:
    assert tag_of("assailai/ares-agent:2.5.0") == "2.5.0"
    assert repo_of("assailai/ares-agent:2.5.0") == "assailai/ares-agent"
    assert tag_of("assailai/ares-agent") == ""  # no tag
    assert repo_of("reg:5000/ares-agent") == "reg:5000/ares-agent"  # the ":" is a registry port
    assert repo_of("assailai/ares-agent@sha256:abc123") == "assailai/ares-agent"  # digest ref
    assert tag_of("assailai/ares-agent@sha256:abc123") == ""  # a digest is not a tag


def test_read_target(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "update-target.json"
    monkeypatch.setattr(main, "settings", _settings(target_file=target))
    assert main._read_target() is None  # not written yet
    target.write_text('{"version": "2.5.0"}')
    assert main._read_target() == "2.5.0"
    target.write_text("not json")  # malformed is ignored, not crashed on
    assert main._read_target() is None


def test_verify_gate() -> None:
    # dev override returns the ref unpinned (with a warning); fail-closed (None) when on but
    # unconfigured (identity + issuer cleared, no key), even though the image now ships a default
    # signer identity.
    assert verify.verify("img:1", UpdaterSettings(require_signature=False)) == "img:1"
    unconfigured = UpdaterSettings(require_signature=True, cosign_identity="", cosign_issuer="")
    assert verify.verify("img:1", unconfigured) is None


def _san(workflow: str, ref: str, repo: str = "assailai/docker-agent-ares") -> str:
    """A GitHub Actions signer identity as Fulcio writes it into the certificate SAN."""
    return f"https://github.com/{repo}/.github/workflows/{workflow}@{ref}"


def test_default_signer_identity_matches_what_ci_actually_signs_with() -> None:
    # a stock updater (no env) verifies signatures out of the box: identity + issuer are baked in,
    # so the docker-run / compose / k8s install commands do not each spell the regexp out.
    # Assert on the regexp's BEHAVIOUR, not its text: a substring check on the repo name let the
    # default drift to a workflow file that never signs anything, and every update failed closed.
    settings = UpdaterSettings()
    assert settings.require_signature is True
    assert settings.cosign_issuer == "https://token.actions.githubusercontent.com"

    identity = re.compile(settings.cosign_identity)
    # the release path (auto-tag.yml -> docker-build.yml) signs at the caller's ref, refs/heads/main;
    # a hand-pushed v* tag signs at the tag ref. Both are ours.
    assert identity.search(_san("docker-build.yml", "refs/heads/main"))
    assert identity.search(_san("docker-build.yml", "refs/tags/v3.3.1"))
    # not ours, or not a signer: another owner/repo, the caller workflow that holds no cosign step,
    # and an unmerged PR build (which does not push or sign at all).
    assert not identity.search(_san("docker-build.yml", "refs/heads/main", repo="attacker/evil"))
    assert not identity.search(_san("docker-publish.yml", "refs/heads/main"))
    assert not identity.search(_san("docker-build.yml", "refs/pull/30/merge"))
    # cosign's -regexp flags are substring matches, so the anchors have to hold on both ends.
    assert not identity.search(_san("docker-build.yml", "refs/heads/main") + ".evil.example")
    assert not identity.search("https://evil.example/" + _san("docker-build.yml", "refs/heads/main"))


def test_default_signer_identity_names_the_workflow_that_signs() -> None:
    # the regexp must name the workflow file containing the `cosign sign` step, because Fulcio takes
    # the certificate SAN from the OIDC job_workflow_ref claim - the file holding the signing job,
    # not the entrypoint workflow that calls it. Deriving the expected file from CI (rather than
    # hardcoding it here) is what catches the signing step moving between workflows again.
    workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    if not workflows.is_dir():
        pytest.skip("no .github/workflows checkout (e.g. running inside the built image)")
    signing = sorted(p.name for p in workflows.glob("*.yml") if "cosign sign" in p.read_text())
    assert signing, "no workflow runs `cosign sign`; the updater's identity regexp is unverifiable"

    identity = re.compile(UpdaterSettings().cosign_identity)
    for workflow in signing:
        assert identity.search(_san(workflow, "refs/heads/main")), (
            f"{workflow} signs images but its identity does not match the updater's regexp"
        )


def test_verify_pins_the_cosign_verified_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    # cosign resolves the tag and attests a digest; verify returns that exact digest pinned to
    # the repo, so the caller applies the verified content rather than re-resolving the tag.
    payload = '[{"critical": {"image": {"docker-manifest-digest": "sha256:abc123"}}}]'
    monkeypatch.setattr(
        verify.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=payload, stderr=""),
    )
    pinned = verify.verify(
        "assailai/ares-agent:3.0.0",
        UpdaterSettings(require_signature=True, cosign_identity="^id$", cosign_issuer="iss"),
    )
    assert pinned == "assailai/ares-agent@sha256:abc123"


def test_docker_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Config": {"Image": "assailai/ares-agent:2.4.0"}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    assert DockerBackend().running_image(_settings()) == "assailai/ares-agent:2.4.0"


def test_docker_apply_verifies_new_then_swaps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            return httpx.Response(201, json={"Id": "new123"})
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={"Config": {}, "HostConfig": {}, "State": {"Running": True}})
        return httpx.Response(200, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
    monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:2.5.0"))

    # pulled, created the replacement, started it, then removed the old and renamed the new in.
    assert ("POST", "/images/create") in calls
    assert ("POST", "/containers/create") in calls
    assert ("POST", "/containers/new123/start") in calls
    assert ("DELETE", "/containers/ares-agent") in calls
    assert ("POST", "/containers/new123/rename") in calls


def _apply_capturing_create_body(
    monkeypatch: pytest.MonkeyPatch, *, old_container: dict, image_response: httpx.Response
) -> dict:
    """Run one ``apply`` against a mocked dockerd and return the ``/containers/create`` body."""
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/containers/create":
            bodies.append(json.loads(request.content))
            return httpx.Response(201, json={"Id": "new123"})
        if path.startswith("/images/") and path.endswith("/json"):
            return image_response
        if path.endswith("/json"):
            return httpx.Response(200, json=old_container)
        return httpx.Response(200, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
    monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:3.3.3"))

    assert len(bodies) == 1
    return bodies[0]


_OLD_CONTAINER = {
    "Image": "sha256:oldimage",
    "Config": {
        "Env": ["ARES_TOKEN=t", "PATH=/usr/bin"],
        # the version label was inherited from the OLD image; customer.tier is the operator's own.
        "Labels": {"org.opencontainers.image.version": "3.3.0", "customer.tier": "gold"},
        "Entrypoint": ["/old-entrypoint"],
        "Cmd": ["serve"],
        "Healthcheck": {"Test": ["CMD", "/old-check"]},
        "User": "10001",
        "WorkingDir": "/old-app",
    },
    "HostConfig": {
        "Binds": ["ares-agent-data:/data", "/etc/ssl/certs:/host-ca:ro"],
        "RestartPolicy": {"Name": "always"},
    },
    "State": {"Running": True},
}


def test_docker_apply_carries_only_the_operator_owned_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The replacement must not shadow the new image's own config with the old image's.

    Regression (July 2026): ``apply`` copied the old container's whole ``Config`` forward, so an
    updated agent kept reporting ``org.opencontainers.image.version`` from the version it was FIRST
    deployed at - ``docker inspect`` claimed 3.3.0 on a container genuinely running 3.3.2 - and a
    release that changed its entrypoint or healthcheck would have been silently ignored.
    """
    body = _apply_capturing_create_body(
        monkeypatch,
        old_container=_OLD_CONTAINER,
        image_response=httpx.Response(
            200, json={"Config": {"Labels": {"org.opencontainers.image.version": "3.3.0"}}}
        ),
    )

    # the image-contributed label is left unset, so the NEW image's real version comes through and
    # docker inspect reports what the agent is actually running.
    assert body["Labels"] == {"customer.tier": "gold"}
    # what the operator owns survives: env (ARES_TOKEN et al) and the whole HostConfig.
    assert body["Env"] == ["ARES_TOKEN=t", "PATH=/usr/bin"]
    assert body["HostConfig"] == _OLD_CONTAINER["HostConfig"]
    # the host CA mount specifically. This is why the fix is a mount rather than a `docker cp`
    # into the container: a copied-in root CA lives in the writable layer, which the recreate
    # throws away, so an auto-update would silently break TLS again on a customer's inspecting
    # network. A bind is HostConfig, and HostConfig is carried over whole.
    assert "/etc/ssl/certs:/host-ca:ro" in body["HostConfig"]["Binds"]
    assert body["Image"] == "assailai/ares-agent:3.3.3"
    # everything the image owns is left to the new image rather than pinned to the old one.
    for key in ("Entrypoint", "Cmd", "Healthcheck", "User", "WorkingDir"):
        assert key not in body, f"{key} must come from the new image, not the old container"


@pytest.mark.parametrize("reported", [0, -1, None])
def test_docker_apply_does_not_replay_an_unset_swappiness(
    monkeypatch: pytest.MonkeyPatch, reported: int | None
) -> None:
    # given Podman's inspect of a container that never set a swappiness (it reports 0; Docker
    # reports null or -1), on a cgroup v2 host where crun refuses any explicit value
    host_config = {**_OLD_CONTAINER["HostConfig"], "MemorySwappiness": reported}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    # when the updater re-creates the agent from it
    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    # then the swappiness is left unset, and everything else the operator set is carried over
    assert "MemorySwappiness" not in body["HostConfig"]
    assert body["HostConfig"]["Binds"] == _OLD_CONTAINER["HostConfig"]["Binds"]
    assert body["HostConfig"]["RestartPolicy"] == {"Name": "always"}


def test_docker_apply_keeps_a_swappiness_the_operator_actually_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_config = {**_OLD_CONTAINER["HostConfig"], "MemorySwappiness": 10}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    assert body["HostConfig"]["MemorySwappiness"] == 10


def test_docker_apply_replays_a_podman_cpu_limit_without_the_conflicting_nanocpus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given Podman's inspect of an agent run with --cpus=1.5: the limit three ways at once, which
    # its own compat create refuses ("NanoCpus conflicts with CpuPeriod and CpuQuota")
    cpu = {"CpuPeriod": 100000, "CpuQuota": 150000, "NanoCpus": 1500000000}
    host_config = {**_OLD_CONTAINER["HostConfig"], **cpu}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    # when the updater re-creates the agent from it
    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    # then the limit survives as period and quota, which are the exact original
    assert "NanoCpus" not in body["HostConfig"]
    assert body["HostConfig"]["CpuPeriod"] == 100000
    assert body["HostConfig"]["CpuQuota"] == 150000


def test_docker_apply_keeps_a_docker_cpu_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    # Docker reports --cpus as NanoCpus alone, with period and quota zero: nothing to drop.
    host_config = {**_OLD_CONTAINER["HostConfig"], "NanoCpus": 1500000000, "CpuPeriod": 0}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    assert body["HostConfig"]["NanoCpus"] == 1500000000


def test_docker_apply_removes_a_replacement_it_could_not_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an engine that creates the replacement but refuses to start it (as Podman did on
    # cgroup v2 before the swappiness fix)
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        path = request.url.path
        if path == "/containers/create":
            return httpx.Response(201, json={"Id": "new123"})
        if path == "/containers/new123/start":
            return httpx.Response(500, json={"message": "crun: OCI runtime error"})
        if path.startswith("/images/") and path.endswith("/json"):
            return httpx.Response(200, json={"Config": {}})
        if path.endswith("/json"):
            return httpx.Response(200, json=_OLD_CONTAINER)
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)

    # when the updater applies an update, then the failure still surfaces to the caller
    with pytest.raises(httpx.HTTPStatusError):
        DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:3.3.3"))

    # and the half-made replacement is gone, while the running agent is untouched
    after_start = calls[calls.index(("POST", "/containers/new123/start")) + 1 :]
    assert ("DELETE", "/containers/ares-agent-next") in after_start
    assert ("DELETE", "/containers/ares-agent") not in calls


def test_docker_apply_drops_labels_when_the_old_image_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unreadable old image: keep no labels at all rather than carrying the stale ones.

    Losing a custom operator label is the safe direction; reporting a version the agent is not
    running is not.
    """
    body = _apply_capturing_create_body(
        monkeypatch,
        old_container=_OLD_CONTAINER,
        image_response=httpx.Response(404, json={"message": "no such image"}),
    )

    assert "Labels" not in body
    assert body["Env"] == ["ARES_TOKEN=t", "PATH=/usr/bin"]  # env still survives


def test_k8s_apply_patches_the_deployment_image(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            seen["body"] = request.read().decode()
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://k8s")
    monkeypatch.setattr(kube, "_client", lambda: client)
    monkeypatch.setattr(kube, "_namespace", lambda _s: "default")

    K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:2.5.0"))
    container = json.loads(seen["body"])["spec"]["template"]["spec"]["containers"][0]
    assert container == {"name": "ares-agent", "image": "assailai/ares-agent:2.5.0"}


class _FakeBackend:
    """Stand-in backend that records what it was asked to apply. Unmanaged by default, so a test
    about the agent sees only the agent."""

    def __init__(self, running: str | None, me: SelfInspection | None = None) -> None:
        self.running = running
        self.me = me or SelfInspection(role=Role.UNMANAGED)
        self.plan: UpdatePlan | None = None
        self.predecessor_removals = 0

    @property
    def applied(self) -> str | None:
        return self.plan.agent if self.plan else None

    def available(self) -> bool:
        return True

    def running_image(self, settings: UpdaterSettings) -> str | None:
        return self.running

    def inspect_self(self, settings: UpdaterSettings) -> SelfInspection:
        return self.me

    def remove_predecessor(self, settings: UpdaterSettings) -> None:
        self.predecessor_removals += 1

    def apply(self, settings: UpdaterSettings, plan: UpdatePlan) -> None:
        self.plan = plan


def test_tick_derives_repo_from_the_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())  # image_repo unset -> derive
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == "assailai/ares-agent:2.5.0"


def test_tick_noop_when_already_on_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.5.0")
    main._tick(backend)
    assert backend.applied is None


def test_tick_applies_the_verified_digest_then_noops(monkeypatch: pytest.MonkeyPatch) -> None:
    # the tick applies the DIGEST verify returned (not the tag), closing the TOCTOU; once the
    # agent runs that digest, the cache makes a re-tick a noop (no churn, no re-verify).
    monkeypatch.setattr(main, "settings", _settings())  # verify is mocked below, so the gate is moot
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    pinned = "assailai/ares-agent@sha256:abc123"
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: pinned)

    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == pinned  # the verified digest, not the 2.5.0 tag

    backend.running, backend.plan = pinned, None  # agent now runs the pinned digest
    main._tick(backend)
    assert backend.applied is None  # cache hit -> no re-apply


# --- the updater updating itself (ARES-2049) ------------------------------------------------------

_UPDATER = "docker.io/assailai/ares-updater"
_MY_ID = "a1b2c3d4e5f6" + "0" * 52  # the engine sets a container's hostname to its first 12 chars


def _updater_container(*, instance: str = "", container_id: str = _MY_ID) -> dict:
    """An updater container as the engine reports it: its env, its socket mount, its image."""
    env = ["ARES_UPDATE_CONTAINER=ares-agent", "PATH=/usr/bin"]
    if instance:
        env.append(f"ARES_UPDATE_INSTANCE={instance}")
    return {
        "Id": container_id,
        "Image": "sha256:updaterimage",
        "Config": {"Image": f"{_UPDATER}:3.13.2", "Env": env, "Labels": {}},
        "HostConfig": {
            "Binds": ["ares-agent-data:/data:ro", "/var/run/docker.sock:/var/run/docker.sock"],
            "RestartPolicy": {"Name": "always"},
        },
        "State": {"Running": True},
    }


class _FakeEngine:
    """A Docker engine that records every call in order, for asserting the handoff's sequence."""

    def __init__(
        self,
        *,
        me: dict | None,
        successor_runs: bool = True,
        successor_restarting: bool = False,
        successor_restarts: int = 0,
        take_fails: bool = False,
    ) -> None:
        self.me = me
        self.successor = {
            "State": {"Running": successor_runs, "Restarting": successor_restarting},
            "RestartCount": successor_restarts,
        }
        self.take_fails = take_fails
        self.calls: list[tuple[str, str, str]] = []  # (method, path, name param)
        self.created: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, path, request.url.params.get("name", "")))
        if path == "/containers/create":
            self.created.append(json.loads(request.content))
            return httpx.Response(201, json={"Id": f"new{len(self.created)}"})
        if path in ("/containers/ares-updater/json", "/containers/ares-agent/json"):
            if self.me is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.me)
        if path.startswith("/containers/new") and path.endswith("/json"):
            return httpx.Response(200, json=self.successor)
        if path.endswith("/rename") and self.take_fails and path.startswith("/containers/new"):
            return httpx.Response(409, json={"message": "name in use"})
        return httpx.Response(200, text="")

    def install(self, monkeypatch: pytest.MonkeyPatch, *, hostname: str = _MY_ID[:12]) -> None:
        monkeypatch.setattr(dockerd.socket, "gethostname", lambda: hostname)
        # a fresh client per call, as the real one is: a plan that moves both opens it twice
        transport = httpx.MockTransport(self.handler)
        monkeypatch.setattr(
            dockerd, "_client", lambda: httpx.Client(transport=transport, base_url="http://docker")
        )
        monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
        monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    def index(self, method: str, path: str, name: str = "") -> int:
        """Where a call LAST happened: the handoff also clears leftovers by the same names first."""
        return len(self.calls) - 1 - self.calls[::-1].index((method, path, name))


def test_a_manually_installed_updater_owns_its_container(monkeypatch: pytest.MonkeyPatch) -> None:
    # given the updater an install started (no stamp), whose hostname is that container's short id
    _FakeEngine(me=_updater_container()).install(monkeypatch)

    # when it inspects the container that holds its name
    me = DockerBackend().inspect_self(_settings())

    # then that container is its own, and it reports the image it runs
    assert me == SelfInspection(role=Role.OWNER, image=f"{_UPDATER}:3.13.2")


@pytest.mark.parametrize(
    "hostname",
    ["0f0f0f0f0f0f", "agent-host-01"],
    ids=["another-installs-updater", "operator-set-hostname"],
)
def test_an_installed_updater_that_cannot_prove_the_container_is_its_own_leaves_it_alone(
    hostname: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given a second install on the host whose updater kept the default name, so "ares-updater" is
    # the FIRST install's updater; or an operator-set hostname that is no container id
    _FakeEngine(me=_updater_container()).install(monkeypatch, hostname=hostname)

    # when it inspects ares-updater
    me = DockerBackend().inspect_self(_settings())

    # then it is unmanaged: it keeps updating its agent and never hands over a container it cannot
    # prove is its own (standing by instead would stop its agent's updates)
    assert me.role is Role.UNMANAGED


def test_a_successor_stands_by_while_its_predecessor_holds_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor (stamped "abc") whose predecessor still holds the ares-updater name
    _FakeEngine(me=_updater_container()).install(monkeypatch)

    # when the successor inspects ares-updater mid-handoff
    me = DockerBackend().inspect_self(_settings(instance="abc"))

    # then it is not its own: acting on it would start a handoff of the predecessor
    assert me.role is Role.STANDBY


def test_a_successor_owns_the_name_once_it_holds_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # given the handoff finished: ares-updater now carries the successor's own stamp
    _FakeEngine(me=_updater_container(instance="abc")).install(monkeypatch)

    # when the successor inspects it, then it is the owner
    assert DockerBackend().inspect_self(_settings(instance="abc")).role is Role.OWNER


def test_an_updater_run_under_another_name_is_unmanaged(monkeypatch: pytest.MonkeyPatch) -> None:
    # given nothing named ares-updater (e.g. a compose project that never set container_name)
    _FakeEngine(me=None).install(monkeypatch)

    # when it inspects, then it cannot find itself: it updates the agent and never itself
    assert DockerBackend().inspect_self(_settings()).role is Role.UNMANAGED


def test_docker_hands_over_to_a_successor_then_removes_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an updater that a previous handoff started (it carries stamp "old")
    engine = _FakeEngine(me=_updater_container(instance="old"))
    engine.install(monkeypatch)

    # when it moves itself to the new release
    DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # then the successor runs the new image with this container's settings and socket...
    (body,) = engine.created
    assert body["Image"] == f"{_UPDATER}@sha256:new"
    assert "/var/run/docker.sock:/var/run/docker.sock" in body["HostConfig"]["Binds"]
    assert "ARES_UPDATE_CONTAINER=ares-agent" in body["Env"]
    # ...under a fresh stamp that REPLACES the inherited one: two containers must never share one
    stamps = [e for e in body["Env"] if e.startswith("ARES_UPDATE_INSTANCE=")]
    assert len(stamps) == 1 and stamps != ["ARES_UPDATE_INSTANCE=old"]
    # and only once it stays up does this updater step aside, hand over the name, and go
    started = engine.index("POST", "/containers/new1/start")
    aside = engine.index("POST", "/containers/ares-updater/rename", name="ares-updater-old")
    taken = engine.index("POST", "/containers/new1/rename", name="ares-updater")
    removed = engine.index("DELETE", "/containers/ares-updater-old")
    assert started < aside < taken < removed
    assert removed == len(engine.calls) - 1  # removing itself is the last thing it does


def test_docker_keeps_the_updater_when_its_successor_does_not_stay_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor that crashes as soon as it starts
    engine = _FakeEngine(me=_updater_container(), successor_runs=False)
    engine.install(monkeypatch)

    # when the updater tries to hand over
    DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # then the successor is removed and this updater never gave up its name
    assert ("DELETE", "/containers/new1", "") in engine.calls
    assert not [c for c in engine.calls if c[1].endswith("/rename")]


@pytest.mark.parametrize(
    "crash",
    [{"successor_restarting": True}, {"successor_restarts": 1}],
    ids=["restarting", "restarted-once"],
)
def test_docker_keeps_the_updater_when_its_successor_is_crash_looping(
    crash: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given a successor that dies on start and comes back under the restart policy it inherited:
    # the engine still reports it Running, with Restarting set or a RestartCount above zero
    engine = _FakeEngine(me=_updater_container(), **crash)
    engine.install(monkeypatch)

    # when the updater tries to hand over
    DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # then it does not hand its name to a container that cannot stay up (the e2e found this one)
    assert ("DELETE", "/containers/new1", "") in engine.calls
    assert not [c for c in engine.calls if c[1].endswith("/rename")]


def test_docker_keeps_the_old_agent_when_the_new_one_is_crash_looping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a new agent the engine reports Running while its restart policy brings it back
    engine = _FakeEngine(me=_updater_container(), successor_restarts=3)
    engine.install(monkeypatch)

    # when the agent is moved
    DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a"))

    # then the old agent is kept, not deleted for a replacement that never stays up
    assert ("DELETE", "/containers/ares-agent", "") not in engine.calls
    assert ("DELETE", "/containers/new1", "") in engine.calls


def test_docker_takes_its_name_back_when_the_successor_cannot_take_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor that comes up but cannot be renamed into ares-updater
    engine = _FakeEngine(me=_updater_container(), take_fails=True)
    engine.install(monkeypatch)

    # when the updater hands over, then the failure surfaces...
    with pytest.raises(httpx.HTTPStatusError):
        DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # ...after it took its own name back and removed the successor, rather than removing itself
    back = engine.index("POST", "/containers/ares-updater-old/rename", name="ares-updater")
    assert engine.index("DELETE", "/containers/new1") > back
    assert ("DELETE", "/containers/ares-updater-old", "") not in engine.calls[back:]


def test_docker_moves_the_agent_before_the_updater(monkeypatch: pytest.MonkeyPatch) -> None:
    # given both behind
    engine = _FakeEngine(me=_updater_container())
    engine.install(monkeypatch)

    # when one plan moves both
    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    DockerBackend().apply(_settings(), plan)

    # then the agent's replacement is created and renamed in before the updater's successor exists
    assert [b["Image"] for b in engine.created] == [plan.agent, plan.updater]
    agent_done = engine.index("POST", "/containers/new1/rename", name="ares-agent")
    assert agent_done < engine.index("POST", "/containers/new2/start")


def test_docker_leaves_the_updater_alone_when_the_agent_swap_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent replacement that does not stay up
    engine = _FakeEngine(me=_updater_container(), successor_runs=False)
    engine.install(monkeypatch)

    # when one plan moves both
    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    DockerBackend().apply(_settings(), plan)

    # then the updater does not move while the agent is not on the target
    assert [b["Image"] for b in engine.created] == [plan.agent]


def test_docker_removes_a_predecessor_that_failed_to_remove_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor that now holds the name
    engine = _FakeEngine(me=_updater_container())
    engine.install(monkeypatch)

    # when it removes its predecessor
    DockerBackend().remove_predecessor(_settings())

    # then that is the stepped-aside container, and nothing else
    assert engine.calls == [("DELETE", "/containers/ares-updater-old", "")]


def _k8s_deployment(monkeypatch: pytest.MonkeyPatch, containers: list[dict]) -> list[dict]:
    """Serve a Deployment with ``containers``; return the patches the backend sends."""
    patches: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            patches.append(json.loads(request.read()))
            return httpx.Response(200, json={})
        deployment = {"spec": {"template": {"spec": {"containers": containers}}}}
        return httpx.Response(200, json=deployment)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://k8s")
    monkeypatch.setattr(kube, "_client", lambda: client)
    monkeypatch.setattr(kube, "_namespace", lambda _s: "default")
    return patches


def test_k8s_moves_the_agent_and_the_updater_in_one_rollout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given the agent Deployment, with the updater as its sidecar
    patches = _k8s_deployment(monkeypatch, containers=[])

    # when both are behind
    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    K8sBackend().apply(_settings(), plan)

    # then one patch sets both images, so the pod rolls once rather than twice
    (patch,) = patches
    assert patch["spec"]["template"]["spec"]["containers"] == [
        {"name": "ares-agent", "image": plan.agent},
        {"name": "ares-updater", "image": plan.updater},
    ]


def test_k8s_moves_only_the_updater_when_the_agent_is_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent already on the target
    patches = _k8s_deployment(monkeypatch, containers=[])

    # when only the updater moves
    K8sBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:u"))

    # then the patch names the updater container alone
    (patch,) = patches
    assert patch["spec"]["template"]["spec"]["containers"] == [
        {"name": "ares-updater", "image": f"{_UPDATER}@sha256:u"}
    ]


def test_k8s_finds_the_updater_sidecar_or_reports_it_unmanaged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a Deployment with the sidecar, it is the owner of that container and reports its image
    _k8s_deployment(
        monkeypatch,
        containers=[
            {"name": "ares-agent", "image": "assailai/ares-agent:3.13.2"},
            {"name": "ares-updater", "image": f"{_UPDATER}:3.13.2"},
        ],
    )
    assert K8sBackend().inspect_self(_settings()) == SelfInspection(
        role=Role.OWNER, image=f"{_UPDATER}:3.13.2"
    )

    # and without one (an operator who removed it), it updates nothing of its own
    _k8s_deployment(monkeypatch, containers=[{"name": "ares-agent", "image": "a:1"}])
    assert K8sBackend().inspect_self(_settings()).role is Role.UNMANAGED


def _owner(image: str = f"{_UPDATER}:3.13.2") -> SelfInspection:
    return SelfInspection(role=Role.OWNER, image=image)


def _verify_to_digest(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stand cosign in with one pinning ``repo:tag`` to ``repo@sha256:tag``; return what it saw."""
    seen: list[str] = []

    def fake(image: str, settings: UpdaterSettings) -> str:
        seen.append(image)
        repo, _, tag = image.rpartition(":")
        return f"{repo}@sha256:{tag}"

    monkeypatch.setattr(main.verify, "verify", fake)
    return seen


def test_tick_moves_the_agent_and_the_updater_together(monkeypatch: pytest.MonkeyPatch) -> None:
    # given both on 3.13.2, a 3.14.0 target, and this updater the owner of its container
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=_owner())

    # when it ticks
    main._tick(backend)

    # then one plan moves both, each verified from its own repo
    assert backend.plan == UpdatePlan(
        agent="docker.io/assailai/ares-agent@sha256:3.14.0",
        updater=f"{_UPDATER}@sha256:3.14.0",
    )


def test_tick_does_nothing_while_another_container_holds_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor mid-handoff, with the agent behind
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    seen = _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.13.2", me=SelfInspection(role=Role.STANDBY)
    )

    # when it ticks, then it moves nothing, not even the agent: only one updater acts at a time
    main._tick(backend)
    assert backend.plan is None and seen == []


def test_tick_holds_the_updater_back_when_the_agent_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent image cosign refuses
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: None)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=_owner())

    # when it ticks, then nothing moves: the updater follows the agent, never leads it
    main._tick(backend)
    assert backend.plan is None


def test_tick_moves_only_the_updater_once_the_agent_is_on_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent already on 3.14.0 and an updater still on 3.13.2 (installed before the release)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", me=_owner())

    # when it ticks
    main._tick(backend)

    # then the updater catches up on its own
    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.14.0")


@pytest.mark.parametrize(
    "me",
    [SelfInspection(role=Role.UNMANAGED), _owner(image=f"{_UPDATER}:3.14.0")],
    ids=["unmanaged", "already-on-target"],
)
def test_tick_leaves_the_updater_where_it_is(
    me: SelfInspection, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given an agent behind, and an updater that cannot find itself or is already on the target
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=me)

    # when it ticks
    main._tick(backend)

    # then only the agent moves
    assert backend.plan == UpdatePlan(agent="docker.io/assailai/ares-agent@sha256:3.14.0")


def test_tick_honours_self_update_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # given an operator who manages the updater elsewhere
    monkeypatch.setattr(main, "settings", _settings(self_update=False))
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=_owner())

    main._tick(backend)

    # then the agent moves and the updater does not
    assert backend.plan == UpdatePlan(agent="docker.io/assailai/ares-agent@sha256:3.14.0")


def test_a_failed_updater_move_waits_before_it_is_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent on the target and an updater whose new image cosign cannot verify
    # (e.g. a private mirror that carries the agent's tag and not the updater's)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    seen: list[str] = []
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: seen.append(image))
    clock = types.SimpleNamespace(now=1000.0)
    monkeypatch.setattr(main.time, "monotonic", lambda: clock.now)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", me=_owner())

    # when it ticks twice in a row, then cosign is asked once, not every poll
    main._tick(backend)
    main._tick(backend)
    assert seen == [f"{_UPDATER}:3.14.0"]

    # and once the wait has passed, it tries again
    clock.now += main._SELF_RETRY_SECONDS
    main._tick(backend)
    assert len(seen) == 2


def test_a_handoff_that_returns_waits_before_it_is_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a backend whose handoff comes back (a successor that did not stay up)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", me=_owner())

    # when it ticks twice, then the second tick does not start another successor straight away
    main._tick(backend)
    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.14.0")
    backend.plan = None
    main._tick(backend)
    assert backend.plan is None


@pytest.mark.parametrize(
    "target", ["3.13.2", "nightly"], ids=["an-older-release", "no-release-at-all"]
)
def test_the_updater_never_moves_itself_backwards(
    target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given an updater built as 3.14.0, and a target older than that (an operator rolling the agent
    # back), or a target it cannot read as a release
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: target)
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks
    main._tick(backend)

    # then the agent follows the target and the updater stays: one taken below 3.14.0 could never
    # update itself again
    assert backend.plan == UpdatePlan(agent=f"docker.io/assailai/ares-agent@sha256:{target}")


def test_the_updater_moves_forward_past_its_own_release(monkeypatch: pytest.MonkeyPatch) -> None:
    # given an updater built as 3.14.0-rc1 (a suffix reads as its release) and a 3.15.0 target
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.15.0")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0-rc1")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.15.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks, then it moves itself forward as usual
    main._tick(backend)
    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.15.0")


def test_the_owner_removes_its_predecessor_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # given an updater that holds its name, with nothing to update
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks twice
    main._tick(backend)
    main._tick(backend)

    # then it looked for a predecessor once, not on every poll
    assert backend.predecessor_removals == 1


# --- CA trust: cosign is a subprocess, so SSL_CERT_FILE is the only lever that reaches it -------


def _prepare_ca_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    host_ca, extra = tmp_path / "host-ca", tmp_path / "certs"
    image_bundle = tmp_path / "image-bundle.crt"
    image_bundle.write_text("PUBLIC ROOTS\n")
    monkeypatch.setattr(tlsconf, "HOST_CA_DIR", host_ca)
    monkeypatch.setattr(tlsconf, "EXTRA_CA_DIR", extra)
    monkeypatch.setattr(tlsconf, "IMAGE_BUNDLE", image_bundle)
    monkeypatch.setattr(tlsconf, "MERGED_BUNDLE", tmp_path / "merged.pem")
    # install_ca_bundle writes straight to os.environ (that is the point: children inherit it), so
    # register the variable with monkeypatch first or whatever it sets leaks into later tests.
    # setenv records the pre-test state; the delenv leaves the code seeing it as unset.
    monkeypatch.setenv("SSL_CERT_FILE", "")
    monkeypatch.delenv("SSL_CERT_FILE")
    return host_ca, extra


def test_no_mounted_cas_leaves_ssl_cert_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the common case: nothing mounted, so the image's own store is already the whole truth and
    # we must not narrow it by pointing SSL_CERT_FILE at a bundle of our own.
    _prepare_ca_dirs(tmp_path, monkeypatch)

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_mounted_cas_are_merged_with_the_image_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # union, never replacement: dropping the public roots would break the registry pull itself.
    host_ca, extra = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "corp-root.crt").write_text("CORP ROOT\n")
    extra.mkdir()
    (extra / "internal.pem").write_text("INTERNAL ROOT\n")

    bundle = tlsconf.install_ca_bundle()

    assert bundle is not None
    body = bundle.read_text()
    assert "PUBLIC ROOTS" in body and "CORP ROOT" in body and "INTERNAL ROOT" in body
    # cosign is a Go binary we shell out to; it reads this variable and nothing else we control.
    assert os.environ["SSL_CERT_FILE"] == str(bundle)


def test_dangling_symlinks_are_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # a mounted /etc/ssl/certs is mostly symlinks into a directory that was not mounted.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "dangling.pem").symlink_to("/usr/share/ca-certificates/nowhere.crt")

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_an_operator_set_ssl_cert_file_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # someone who pointed it somewhere deliberately gets to keep their answer.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "corp-root.crt").write_text("CORP ROOT\n")
    monkeypatch.setenv("SSL_CERT_FILE", "/operators/own.pem")

    assert tlsconf.install_ca_bundle() is None
    assert os.environ["SSL_CERT_FILE"] == "/operators/own.pem"


def test_an_unreadable_image_bundle_leaves_the_default_trust_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SSL_CERT_FILE *replaces* the default trust, so writing a bundle of only the mounted roots
    # would narrow the updater to the corporate CA and break public TLS. Fail toward the image's
    # own store instead.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "corp-root.crt").write_text("CORP ROOT\n")
    monkeypatch.setattr(tlsconf, "IMAGE_BUNDLE", tmp_path / "does-not-exist.crt")

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_unreadable_mounted_files_leave_the_default_trust_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing mounted actually loaded, so there is nothing to add and no reason to point
    # SSL_CERT_FILE at a copy of what the image already trusts.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    unreadable = host_ca / "corp-root.crt"
    unreadable.write_text("CORP ROOT\n")
    unreadable.chmod(0o000)

    try:
        assert tlsconf.install_ca_bundle() is None
        assert "SSL_CERT_FILE" not in os.environ
    finally:
        unreadable.chmod(0o644)
