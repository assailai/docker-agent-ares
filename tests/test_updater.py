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
from updater.config import UpdaterSettings, repo_of, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


@pytest.fixture(autouse=True)
def _clear_verified_cache():
    # the verified-digest cache is a module global; isolate it between tests.
    main._verified.clear()
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

    DockerBackend().apply(_settings(), "assailai/ares-agent:2.5.0")

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

    DockerBackend().apply(_settings(), "assailai/ares-agent:3.3.3")

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

    K8sBackend().apply(_settings(), "assailai/ares-agent:2.5.0")
    container = json.loads(seen["body"])["spec"]["template"]["spec"]["containers"][0]
    assert container == {"name": "ares-agent", "image": "assailai/ares-agent:2.5.0"}


class _FakeBackend:
    """Stand-in backend that records what it was asked to apply."""

    def __init__(self, running: str | None) -> None:
        self.running = running
        self.applied: str | None = None

    def available(self) -> bool:
        return True

    def running_image(self, settings: UpdaterSettings) -> str | None:
        return self.running

    def apply(self, settings: UpdaterSettings, image_ref: str) -> None:
        self.applied = image_ref


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

    backend.running, backend.applied = pinned, None  # agent now runs the pinned digest
    main._tick(backend)
    assert backend.applied is None  # cache hit -> no re-apply


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
