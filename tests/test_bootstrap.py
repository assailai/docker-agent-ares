"""The bootstrap installer, where it makes decisions the agent then depends on.

Only the CA detection is pinned here, and deliberately: the same candidate list is written a
second time in the other repo, in the install command the dashboard hands operators
(``apps/web/src/lib/agent-install.ts``, ``caDetection``). Two copies of one list across two
repositories is a drift trap, and nothing can fail the build in *both* of them, so each side pins
its own copy. That does not detect cross-repo drift, but it does mean neither list can change by
accident: whoever edits one gets a failure telling them the other exists.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

_REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = _REPO / "scripts" / "bootstrap.sh"
COMPOSE = _REPO / "docker-compose.yml"
K8S = _REPO / "deploy" / "k8s" / "ares-agent.yaml"
VERSION_FILE = _REPO / "agent" / "__version__.py"

# The order matters as much as the membership. /etc/ssl/certs is a symlink into /etc/pki on RHEL,
# so checking it first and resolving with `readlink -f` lands on the real bundle on every distro;
# checking the pki path first would work too, but only by accident on Debian.
EXPECTED_CA_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, SUSE
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Fedora, Amazon Linux
]


def _candidates() -> list[str]:
    match = re.search(r"for bundle in (.+?); do", BOOTSTRAP.read_text())
    assert match, "host_ca_dir no longer loops over a list of candidate bundles"
    return match.group(1).split()


def test_the_ca_candidates_match_the_dashboard_install_command() -> None:
    assert _candidates() == EXPECTED_CA_CANDIDATES, (
        "The host CA candidate list changed. The dashboard's install command carries the same "
        "list in ares-v2 (apps/web/src/lib/agent-install.ts, caDetection), and the two must stay "
        "identical or the same host gets diagnosed differently depending on how it was installed."
    )


def test_the_host_ca_mount_is_read_only_and_never_exposes_private_keys() -> None:
    body = BOOTSTRAP.read_text()

    assert ":/host-ca:ro" in body, "the host CA mount must be read-only"
    assert "/host-ca:rw" not in body
    # /etc/ssl/private sits beside the certificate directory on Debian and holds host private
    # keys. Mounting the parent, or that path, would hand them to a container that has no use
    # for them.
    assert "/etc/ssl/private" not in body
    assert '-v "/etc/ssl:' not in body


def test_the_kept_identity_marker_is_matched_before_agent_online() -> None:
    # Ordering, not membership, is the bug here. On a re-install that could not re-enroll, BOTH
    # strings are in the log by the time wait_until_online reads it: the agent really is online,
    # just as the agent it already was. Matching "Agent online" first is precisely how a failed
    # re-enrollment used to be reported as a successful install.
    body = BOOTSTRAP.read_text()

    kept = body.find('*"Keeping the existing agent identity"*)')
    online = body.find('*"Agent online"*)')

    assert kept != -1, "wait_until_online no longer detects a re-install that kept its identity"
    assert online != -1, "wait_until_online no longer detects the agent coming online"
    assert kept < online, (
        "the kept-identity case must be matched before 'Agent online', which is also in the log "
        "by then; otherwise a re-install that failed to re-enroll exits 0 as a success."
    )


def test_the_reset_flag_removes_both_containers_before_the_volume() -> None:
    # The engine refuses to remove a volume any container still references, and ares-updater
    # mounts this one read-only. Removing the agent alone would leave `volume rm` failing, which
    # (before the guard below) meant starting the agent on the very identity ARES_RESET was asked
    # to discard.
    body = BOOTSTRAP.read_text()
    reset = body[body.index("reset_state() {") : body.index("# Echo this host's CA directory")]

    rm_containers = reset.index('rm -f "$CONTAINER_NAME" "$UPDATER_CONTAINER_NAME"')
    rm_volume = reset.index('volume rm "$VOLUME_NAME"')

    assert rm_containers < rm_volume, "both containers must be removed before the volume"
    # And a volume that will not go away has to stop the install rather than be shrugged off.
    assert "exit 1" in reset, "a failed volume removal must abort instead of enrolling anyway"


def test_the_reset_is_opt_in() -> None:
    # The data volume is deliberately kept across a re-install: it is what lets an agent survive
    # being recreated, and the agent re-enrolls on its own when handed a token it was not minted
    # from. Discarding it by default would turn every upgrade into a brand-new agent.
    body = BOOTSTRAP.read_text()

    assert '[ -n "${ARES_RESET:-}" ] || return 0' in body, (
        "reset_state must return early unless ARES_RESET is set"
    )


# ── The updater's engine socket (ARES-1725) ─────────────────────────────────────────────────────
#
# A rootful Podman host has no /var/run/docker.sock, and the installer used to hand the updater
# that path anyway. Podman refused the mount, the installer printed one warning and then "Done",
# and the agent stayed on its install version for good. Three customer hosts sat on 3.6.0 through
# four releases that way.


def _function(name: str) -> str:
    match = re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", BOOTSTRAP.read_text(), re.DOTALL | re.MULTILINE
    )
    assert match, f"bootstrap.sh no longer defines {name}"
    return match.group(0)


class _SocketRun(NamedTuple):
    engine_sock: str
    systemctl_calls: list[str]
    output: str


def _setup_podman(
    *, is_podman: bool, uid: int, systemctl_succeeds: bool, disable_autoupdate: bool = False
) -> _SocketRun:
    """Run setup_rootful_podman in bash with `id` and `systemctl` stubbed.

    The stubbed `enable --now podman.socket` creates a real Unix socket, as socket activation
    would. It lives under a short /tmp directory because a Unix socket path is capped at ~104 bytes
    on macOS, which a pytest tmp_path can exceed.
    """
    workdir = Path(tempfile.mkdtemp(prefix="ab", dir="/tmp"))
    sock = workdir / "podman.sock"
    calls = workdir / "calls"
    calls.touch()
    bind = (
        f"{sys.executable} -c "
        "'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])'"
    )
    script = f"""
set -euo pipefail
id() {{ echo {uid}; }}
systemctl() {{
    echo "$*" >> {calls}
    [ {int(systemctl_succeeds)} -eq 1 ] || return 1
    if [ "$*" = "enable --now podman.socket" ]; then {bind} {sock}; fi
}}
step() {{ :; }}
info() {{ echo "INFO $1"; }}
warn() {{ echo "WARN $1"; }}
IS_PODMAN={"true" if is_podman else "false"}
ENGINE_SOCK=/var/run/docker.sock
PODMAN_ROOTFUL_SOCK={sock}
{_function("setup_rootful_podman")}
setup_rootful_podman
echo "ENGINE_SOCK=$ENGINE_SOCK"
"""
    env = {"PATH": "/usr/bin:/bin"}
    if disable_autoupdate:
        env["ARES_DISABLE_AUTOUPDATE"] = "1"
    done = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env, check=True, timeout=30
    )
    engine_sock = done.stdout.strip().splitlines()[-1].removeprefix("ENGINE_SOCK=")
    return _SocketRun(
        engine_sock=engine_sock.replace(str(sock), "<podman.sock>"),
        systemctl_calls=calls.read_text().splitlines(),
        output=done.stdout,
    )


def test_rootful_podman_enables_its_api_socket_and_hands_that_to_the_updater() -> None:
    # given a rootful Podman host where podman.socket is not yet enabled (a stock RHEL host)
    # when the installer sets up the runtime
    run = _setup_podman(is_podman=True, uid=0, systemctl_succeeds=True)

    # then it enables podman.socket and uses Podman's own socket, not /var/run/docker.sock
    assert "enable --now podman.socket" in run.systemctl_calls
    assert run.engine_sock == "<podman.sock>"
    assert "INFO Enabled podman.socket" in run.output


def test_rootful_podman_restarts_the_agent_after_a_reboot() -> None:
    # given rootful Podman, which has no daemon to honour --restart=always across a reboot
    # when the installer sets up the runtime, with or without auto-update
    run = _setup_podman(is_podman=True, uid=0, systemctl_succeeds=True)
    no_update = _setup_podman(
        is_podman=True, uid=0, systemctl_succeeds=True, disable_autoupdate=True
    )

    # then podman-restart is enabled either way: it is about the agent, not the updater
    assert "enable podman-restart.service" in run.systemctl_calls
    assert no_update.systemctl_calls == ["enable podman-restart.service"]


def test_rootful_podman_that_cannot_enable_the_socket_says_so() -> None:
    # given a rootful Podman host where podman.socket cannot be enabled (no systemd, or a policy)
    # when the installer sets up the runtime
    run = _setup_podman(is_podman=True, uid=0, systemctl_succeeds=False)

    # then it still points at Podman's socket, so the updater fails on the real reason, and warns
    assert run.engine_sock == "<podman.sock>"
    assert "WARN Could not enable podman.socket" in run.output


def test_docker_and_rootless_podman_keep_the_socket_they_already_had() -> None:
    # given Docker, or rootless Podman (whose socket setup_persistence already chose)
    # when the installer sets up the runtime
    docker = _setup_podman(is_podman=False, uid=0, systemctl_succeeds=True)
    rootless = _setup_podman(is_podman=True, uid=1000, systemctl_succeeds=True)

    # then nothing changes and no system service is touched
    assert docker.engine_sock == "/var/run/docker.sock"
    assert rootless.engine_sock == "/var/run/docker.sock"
    assert docker.systemctl_calls == rootless.systemctl_calls == []


def test_the_socket_is_resolved_before_the_updater_starts_and_a_failure_is_reported_last() -> None:
    body = BOOTSTRAP.read_text()
    main = body[body.index("main() {") :]

    order = [
        main.index("setup_persistence"),
        main.index("setup_rootful_podman"),
        main.index("start_updater"),
        main.index("print_summary"),
        main.index("report_autoupdate_failure"),
    ]
    assert order == sorted(order), (
        "the rootful socket has to be resolved after setup_persistence (which owns the rootless "
        "one) and before the updater starts; a failed updater is reported after the summary, so "
        "it is the last thing the operator reads rather than a warning above 'Done'"
    )
    assert "exit 1" in _function("report_autoupdate_failure"), (
        "an install whose updater could not run must exit non-zero"
    )


def test_the_updater_may_use_the_engine_socket_under_selinux() -> None:
    # SELinux (enforcing by default on RHEL and Fedora) stops a container connecting to the engine
    # socket, so an updater without this starts fine and then fails every check.
    assert "updater_args+=(--security-opt label=disable)" in _function("start_updater")
    assert "      - label=disable" in COMPOSE.read_text()


def test_every_install_path_pins_the_release_being_cut() -> None:
    # 3.10.0 and 3.11.0 were cut without moving these, so the installer fetched from the v3.11.0
    # tag installed 3.9.0 and left the catch-up to the updater, which is the one part that may not
    # be running.
    version = re.search(r'__version__ = "(.+?)"', VERSION_FILE.read_text())
    assert version
    expected = version.group(1)

    image_pin = r"ares-(?:agent|updater):(\d+\.\d+\.\d+)"
    pins = {
        "scripts/bootstrap.sh": re.findall(r":-(\d+\.\d+\.\d+)\}", BOOTSTRAP.read_text()),
        "docker-compose.yml": re.findall(image_pin, COMPOSE.read_text()),
        "deploy/k8s/ares-agent.yaml": re.findall(image_pin, K8S.read_text()),
    }
    for path, found in pins.items():
        assert len(found) == 2, f"{path}: expected an agent and an updater pin, found {found}"
        assert set(found) == {expected}, (
            f"{path} pins {found}, but agent/__version__.py is {expected}"
        )
