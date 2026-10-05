"""Ares Docker Agent configuration (zero-touch, environment-driven).

One command brings the agent up: ``docker run -e ARES_TOKEN=... assailai/ares-agent``.
Everything else has a sensible default. There is no interactive setup wizard.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from agent.__version__ import __version__


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARES_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # One-time registration token minted in the Ares dashboard (Settings -> Agents).
    # REQUIRED: the agent exits with a clear message if it is missing.
    # SecretStr, not str, so the value cannot reach a log by accident: this settings object is the
    # one place the enrollment token lives, and a plain str would render in full through any
    # `repr(settings)` or unhandled pydantic validation error. Read it with `.get_secret_value()`.
    token: SecretStr = SecretStr("")
    # Base URL of the Ares control plane.
    # api.assailai.com never existed (it is NXDOMAIN), so every install that did not set ARES_URL
    # explicitly failed its very first control-plane call with a DNS error that read like the
    # customer's network blocking us.
    url: str = "https://ares.assailai.com"
    # Optional comma-separated CIDRs that override auto-detected internal networks.
    networks: str = ""
    # Optional friendly name shown in the dashboard (defaults to the host's name).
    agent_name: str = ""
    # Skip TLS verification. LOCAL DEV ONLY (e.g. plain http or a self-signed ares-v2).
    insecure: bool = False
    # Extra CA roots to trust, as a PEM file or a directory of them. The escape hatch, not the
    # normal path: the agent already trusts everything in the host CA store the install command
    # mounts at /host-ca, plus anything dropped in /certs. Set this only for a root that is in
    # neither, such as an internal CA on a build that never had it installed on the host.
    ca_bundle: str = ""
    # Static hostname pins, as ``name=address`` pairs separated by commas or spaces, e.g.
    # "sso.acme.internal=10.1.2.3,portal.acme.internal=10.1.2.4". The escape hatch for a name the
    # host's resolver will not answer; the agent already reads the host's own /etc/hosts (mounted
    # at /host-hosts by the install command), so this is only for a pin that is not in there.
    # A pin supplies an address, never authorization: the result is still checked against the
    # registered networks / what ares approved. See agent.hostpins.
    host_aliases: str = ""

    # how broadly to scan when ARES_NETWORKS is unset: "reachable" (default; the attached subnets
    # widened to /16, PLUS every private network the agent can demonstrably reach, found from the
    # kernel's routing and neighbour tables and by probing private space -- see agent.reachability),
    # "supernet16" (each attached subnet widened to its enclosing /16, the pre-3.9 default),
    # "attached" (interface prefixes only), "rfc1918" (all private ranges, each capped at
    # scan_max_hosts and logged, so the largest are partial -- blunt and slow), or "host-all"
    # (supernet16 plus the docker bridge subnets and the host loopback -- for a container run with
    # host networking). See agent.netdetect.
    scan_scope: str = "reachable"
    # Whether "reachable" runs its ACTIVE probe, as opposed to reading the kernel's tables only.
    # The probe is what makes the default work in an ordinary bridge-networked container, where the
    # routing table describes the container's own bridge and nothing else, so turning it off on the
    # standard install reduces the default to roughly the old behaviour. Worth having anyway: an
    # estate that does not want unsolicited connects across its private space can set this false
    # and set ARES_NETWORKS instead.
    reach_probe: bool = True
    # Wall clock the reachability probe may spend, in seconds. It stops when this is gone and
    # advertises what it found, logging the truncation; it is never a per-scan cost, only a
    # per-enrollment and per-redetect one.
    reach_budget_seconds: float = 600.0
    # Concurrent connects during the probe. Below the scan's own concurrency on purpose: this
    # reaches across a customer's whole private space rather than one advertised network.
    reach_concurrency: int = 1024
    # How often the agent re-runs reachability discovery and reports the result, in seconds. A
    # network that came into reach after install (a new VLAN, a route that appeared) would
    # otherwise stay invisible for the life of the container, because registration happens once
    # and a self-updating agent never registers again. 0 disables re-detection.
    reach_refresh_seconds: int = 21_600
    # max simultaneous TCP connects. Clamped at startup to what the file-descriptor budget allows.
    scan_concurrency: int = 2048
    # per-connect timeout (seconds) for the phase-2 full port sweep on a live host.
    scan_connect_timeout: float = 1.0
    # faster per-connect timeout (seconds) for the phase-1 liveness sweep across every host.
    scan_discovery_timeout: float = 0.5
    # hosts are scanned this prefix at a time (a /24 by default) for bounded memory + live progress.
    scan_chunk_prefix: int = 24
    # safety ceiling on hosts scanned per task; truncation beyond this is logged, never silent.
    scan_max_hosts: int = 262_144

    # After the port sweep, ask each live host what it is called (reverse DNS, the host file, the
    # TLS certificate it serves, its web title, its NetBIOS name), so the dashboard can show
    # "esxi-01.corp.local" instead of an address. See agent.identify.
    #
    # Unlike the sweep, this sends application-layer bytes into the network, so every source is
    # separately disableable: an estate with fragile devices (OT controllers, older printers) can
    # keep the parts it trusts and turn off the rest, or set ARES_IDENTIFY=false for none of it.
    identify: bool = True
    # Ask the customer's resolver for a PTR record per live host.
    identify_reverse_dns: bool = True
    # Read the certificate served on TLS ports. Handshake only; nothing is sent afterwards.
    identify_tls: bool = True
    # One unauthenticated GET / on web ports, for the page title and Server header. Never sends a
    # credential and never follows a redirect, so it cannot trip a lockout.
    identify_http: bool = True
    # A NetBIOS node-status query (UDP 137), which names Windows machines that have no PTR.
    identify_netbios: bool = True
    # Read the cluster API for the real Service and workload names behind pod addresses. See
    # agent.kubeinfo.
    #
    # Off by default and deliberately separate from the probes above: those send bytes to the
    # hosts being scanned, this one needs read credentials for the cluster itself, which is a
    # power the agent does not otherwise hold. Turning it on without granting the credentials
    # costs one failed call per scan and nothing else.
    identify_kubernetes: bool = False
    # Label for the cluster being read, shown beside the name it produced. One agent can watch
    # more than one cluster, and the same Service name in the same namespace is a different
    # workload in each. Empty means the names are reported without a cluster beside them.
    kube_cluster_name: str = ""
    # API server url for the cluster to read. SET THIS even when the agent runs inside the cluster:
    # the standard Kubernetes install deliberately turns off the pod-wide ServiceAccount token and
    # projects one into the UPDATER container alone, so the scanning container has no in-cluster
    # credentials to fall back on. The patch file points this at https://kubernetes.default.svc
    # with the reader token mounted beside it. Leaving it empty works only where something else
    # mounted a ServiceAccount into this container.
    kube_api_url: str = ""
    # Bearer token file for kube_api_url. Required when that is set; ignored otherwise.
    kube_token_file: str = ""
    # CA bundle verifying kube_api_url. Empty verifies against the public roots, which is almost
    # never right for a cluster API, so set it unless the endpoint has a publicly issued
    # certificate.
    kube_ca_file: str = ""
    # Seconds one request to the cluster API may take.
    kube_timeout: float = 15.0
    # Wall clock for the whole cluster read, all four kinds and every page. It runs beside the
    # sweep, so this is the most naming can wait for it. Capped because ares requeues a task 1800s
    # after dispatch whatever it is doing, and a default scan plus its naming share already uses
    # about 1125s of that.
    kube_budget_seconds: float = Field(default=120.0, gt=0, le=600)

    # Per-source timeouts. Kept short: on a live LAN these all answer in milliseconds, and the
    # value only decides how long a host that will never answer costs us.
    identify_dns_timeout: float = 2.0
    identify_tls_timeout: float = 3.0
    identify_http_timeout: float = 3.0
    identify_netbios_timeout: float = 1.0

    # If the agent cannot successfully reach Ares (heartbeat or task poll) for this long, it exits
    # so the container runtime restarts it fresh: a new process re-resolves DNS and rebuilds its
    # client, recovering from a wedged / network-isolated state that in-loop retries cannot (e.g. a
    # thread pool starved by hung DNS lookups). Generous, so a brief blip self-heals without a
    # restart (10 min is roughly 20 missed 30s heartbeats).
    max_offline_seconds: int = Field(default=600, ge=60, le=86400)

    log_level: str = "INFO"
    data_dir: Path = Field(default=Path("/data"))
    # single source of truth lives in agent/__version__.py
    agent_version: str = Field(default=__version__)

    @property
    def base_url(self) -> str:
        return self.url.rstrip("/")

    @property
    def state_path(self) -> Path:
        return self.data_dir / "agent-state.json"

    @property
    def update_target_path(self) -> Path:
        # the companion updater reads this from the shared data dir; the agent only writes it.
        return self.data_dir / "update-target.json"

    def network_overrides(self) -> list[str]:
        return [n.strip() for n in self.networks.split(",") if n.strip()]


settings = Settings()
