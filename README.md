# Ares Agent

[![Docker Image Version](https://img.shields.io/docker/v/assailai/ares-agent?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/assailai/ares-agent)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

Customer-deployable Docker agent that lets the [Ares](https://www.assailai.com) platform hunt
internal services that aren't exposed to the internet. Deploy it inside your network with one
command: it registers itself, shows up in your dashboard, scans the internal ranges you approve,
and gives Ares a way to reach the discovered hosts for assessment.

The agent is **outbound-only and headless**. There is no web UI, no inbound port to open, and no
host privileges to grant.

## How it works

```
  Your internal network                              Ares platform (cloud)
 ┌───────────────────────────┐                      ┌──────────────────────────┐
 │  ares-agent (container)    │   HTTPS (443)        │  control plane           │
 │   1. read ARES_TOKEN       │ ───────────────────▶ │   register / heartbeat   │
 │   2. auto-detect LAN CIDRs │                      │   poll tasks / report    │
 │   3. connect-scan locally  │   WebSocket (443)    │                          │
 │   4. proxy to internal     │ ◀═══════════════════▶ │  hunt assessment         │
 │      hosts during a hunt   │   (opened on demand) │                          │
 └───────────────────────────┘                      └──────────────────────────┘
```

1. **Register** - on start the agent reads its one-time registration token, auto-detects the
   internal networks it can see, and registers over HTTPS. It then appears in your dashboard.
2. **Heartbeat + poll** - it checks in on a fixed cadence and polls for scan tasks. No inbound
   connections are ever made to the agent.
3. **Scan** - when you launch an internal hunt, the agent runs a TCP-connect scan of the
   approved CIDRs and reports the live hosts it found.
4. **Reach-in** - while a hunt is running the agent opens an outbound WebSocket back to Ares and
   proxies TCP streams to the destination being assessed. The tunnel is closed when no hunt is
   active. Two kinds of destination are allowed, and the agent decides:
   - an **IP address** must be inside the networks you approved for this agent;
   - a **hostname** is resolved by *this host*, on your own DNS, which is how Ares assesses a URL
     that only exists inside your network. It is allowed when every address it resolves to is
     inside your approved networks, or when it is the target of an assessment you launched in
     Ares (Ares names that host on the heartbeat, and only while the run is live). The agent then
     connects to the address it checked, so a second lookup cannot redirect the connection.

   A federated login visits hosts nobody can list in advance, so while an interactive sign-in is
   waiting Ares may approve a whole *domain* (or briefly any name at all). Those broader approvals
   are limited to **public** addresses: a name approved by pattern rather than by name cannot
   resolve to loopback, link-local (so not cloud metadata), private, carrier-grade NAT, multicast
   or reserved space. A destination you approved by exact name or address is unaffected, so an
   internal host you added by hand still works.

## Getting started

**Get your install command from the Ares platform, not by hand.** In Ares, open
**Settings -> Agents -> Deploy an agent**. It generates a ready-to-run command with your one-time
registration token, the correct control-plane URL for your environment, and the agent name already
filled in. Copy that command and run it on the host you want to deploy on; that is the whole setup.
The token is single-use (one agent per token), and the dashboard pins the current release version
for you.

The options below just show the *shape* of what the dashboard hands you (each needs the
`ARES_TOKEN` it issues), in case you want to adapt it for Compose, Kubernetes, or your own tooling.

### Option A: Docker run

The dashboard's Deploy flow gives you exactly this command, filled in. Pin to a specific version
(the deploy command shows the current release); avoid `:latest` so deploys are reproducible.

```bash
docker run -d --name ares-agent \
  -e ARES_TOKEN=<your-registration-token> \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:<version>
```

Watch it enroll and come online:

```bash
docker logs -f ares-agent
# ... Registered as agent <id> ("<name>")
# ... Agent online as "<name>" (agent <id>).
```

The name and id on that last line are the ones **Ares** holds for this agent, not the
`ARES_AGENT_NAME` you passed in, so it is the line to check when you want to be sure a host
enrolled as the agent you meant it to.

Images are published to Docker Hub: `assailai/ares-agent` and `assailai/ares-updater` (the companion updater), tagged per release.

### Option B: Docker Compose

```bash
ARES_TOKEN=<your-registration-token> docker compose up -d
docker compose logs -f
```

See [docker-compose.yml](docker-compose.yml) for the full configuration.

### Option C: Bootstrap script

The bootstrap script checks Docker is available, starts the container, and waits until the agent
reports online:

```bash
ARES_TOKEN=<your-registration-token> bash <(curl -fsSL https://raw.githubusercontent.com/assailai/ares-agent/main/scripts/bootstrap.sh)
```

It also accepts the token as an argument or prompts for it interactively. Works on macOS, Linux,
and Windows (Git Bash / WSL).

### Option D: Kubernetes

Apply the bundled manifest, [`deploy/k8s/ares-agent.yaml`](deploy/k8s/ares-agent.yaml). It is the
canonical, auto-updating deployment and bundles everything the agent needs on k8s:

- the agent plus the companion `ares-updater` **sidecar** (a ServiceAccount scoped to patch only
  this Deployment, so a dashboard "Update" triggers a native rolling update),
- a PVC for the agent's state, and
- `securityContext.fsGroup: 10001` so the non-root agent (uid/gid 10001) can write that volume.
  Without it the agent cannot persist its identity, the liveness check fails, and the pod
  crash-loops (a PVC mounts root-owned, unlike a Docker volume).

The `assailai/ares-agent` and `assailai/ares-updater` images are public on Docker Hub, so no
image pull secret is required.

```bash
curl -fsSLO https://raw.githubusercontent.com/assailai/ares-agent/main/deploy/k8s/ares-agent.yaml
# set ARES_TOKEN in the Secret at the top of the file (and pin the image to a release), then:
kubectl apply -f ares-agent.yaml
kubectl rollout status deploy/ares-agent
```

To opt out of auto-update, delete the `ares-updater` container plus its ServiceAccount, Role, and
RoleBinding, and update the image through your own pipeline instead.

## Configuration

The agent is configured entirely through environment variables (all prefixed `ARES_`).

| Variable | Default | Description |
|----------|---------|-------------|
| `ARES_TOKEN` | *(required)* | One-time registration token from the dashboard. The agent exits with a clear message if it is missing. |
| `ARES_URL` | `https://ares.assailai.com` | Base URL of the Ares control plane. Override when self-hosting. |
| `ARES_NETWORKS` | *(auto-detected)* | Comma-separated CIDRs to scan, e.g. `10.0.0.0/24,192.168.1.0/24`. Overrides auto-detection and switches network discovery off entirely: an explicit list is a decision, so nothing widens it — including a scan task, which the agent refuses if its target is not inside this list. You can also edit the networks in the dashboard after enrollment. |
| `ARES_SCAN_SCOPE` | `reachable` | How broadly to scan when `ARES_NETWORKS` is unset. See [Network discovery](#network-discovery). `reachable` (default), `supernet16`, `attached`, `rfc1918`, `host-all`. |
| `ARES_REACH_PROBE` | `true` | Whether `reachable` runs its active probe of private space, as opposed to reading the machine's routing and neighbour tables only. |
| `ARES_REACH_BUDGET_SECONDS` | `600` | Wall clock the probe may spend. When it runs out the agent advertises what it found and logs the truncation. |
| `ARES_REACH_REFRESH_SECONDS` | `21600` | How often to look again, so a network that appears after the install is picked up. `0` runs discovery once, at startup. |
| `ARES_AGENT_NAME` | *(host name)* | Friendly name shown in the dashboard. |
| `ARES_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `ARES_INSECURE` | `false` | Skip TLS verification. Local and staging URLs only; the agent refuses to start with this set against a production URL. |
| `ARES_CA_BUNDLE` | *(none)* | Extra CA roots to trust, as a PEM file or a directory of them. Rarely needed: the agent already trusts this host's CA store (see [TLS inspection](#tls-inspection-corporate-proxy)). Set it only for a root that is in neither the host store nor `/certs`. |
| `ARES_HOST_ALIASES` | *(none)* | Static `name=address` pins, comma or space separated, e.g. `sso.acme.internal=10.1.2.3`. Rarely needed: the agent already reads this host's `/etc/hosts` (see [Name resolution](#name-resolution)). Set it only for a pin that is not in there. |
| `ARES_DNS` | *(none)* | Extra resolvers for the container, comma separated. Read by the install command, not the agent. Only needed when this host's own resolver cannot answer an internal name. |

### Network discovery

An agent is deployed to find what is on a customer's internal networks, and until 3.9 it only ever
looked at the network its own interface sat on, widened to the enclosing /16. An agent on
172.23.104.x therefore scanned 172.23.0.0/16 and nothing else, so an estate with services on
10.20.x.x was invisible, with nothing on screen to say so. What an interface is attached to says
where the agent **is**; it says nothing about where the agent can **go**.

The default scope, `reachable`, answers the second question from three sources:

1. **The attached subnets**, widened to /16 exactly as `supernet16` did. Nothing that used to be
   scanned stops being scanned; the other two sources only ever add.
2. **The machine's routing and neighbour tables.** Every private destination the kernel holds a
   route for, plus the /24 of every address it has exchanged a frame with. Free, and it is exactly
   the corporate case: a static route pointing 10.20.0.0/16 at the router. Its blind spot is the
   ordinary bridge-networked container, which has its own network namespace and so sees only its
   own bridge and a default route.
3. **An active probe of private space** (10/8, 172.16/12, 192.168/16 and RFC 6598 100.64/10),
   which is what covers that blind spot: it tests reachability rather than inferring it, so it
   works the same in a bridge-networked container, under host networking, and in Kubernetes. It
   samples every /24 thinly, then goes back over the /16s that showed any life and samples those
   densely, so a sparse VLAN inside a populated range is still found. Nothing but a TCP connect and
   an immediate close is sent, and a refused connection counts as a hit (a host that refuses is
   still a host).

**Discovery never delays enrollment.** The agent registers on its attached subnets and comes online
in seconds, then discovery runs in the background and reports what it finds on the next heartbeat;
Ares widens the scan scope and starts a scan of anything new. It repeats on
`ARES_REACH_REFRESH_SECONDS`, because an agent registers exactly once and a self-updating one never
registers again, so a VLAN added six months later would otherwise never be seen.

The dashboard shows the difference: an agent's panel lists the networks in its scope, and separately
anything it reported it can reach that is not in scope yet.

| Scope | What it scans |
|-------|---------------|
| `reachable` *(default)* | The attached subnets widened to /16, plus every private network the agent can demonstrably reach. |
| `supernet16` | Each attached subnet widened to its enclosing /16. The pre-3.9 default. |
| `attached` | The interface prefixes exactly as configured, unwidened. |
| `rfc1918` | All private ranges, blindly, each capped at `ARES_SCAN_MAX_HOSTS` and logged. Slow and coarse; `reachable` supersedes it. |
| `host-all` | `supernet16` plus the docker bridge subnets and the host loopback. For a container run with host networking. |

Set `ARES_REACH_PROBE=false` to keep the routing-table half and skip the packets, or set
`ARES_NETWORKS` to skip discovery altogether.

### Hosts added by hand

Discovery is thorough, but an operator knows the estate better than any scan. A campaign agent's
panel in the dashboard takes an address or an internal hostname, with an optional name and a note.
An entry added there is marked **Manual** and, unlike anything a scan finds, is never removed by a
later rescan: every scan from then on includes it, and the agent is authorized to dial it through
the tunnel even when it falls outside the networks the agent detected for itself. Adding an IP
address also queues a scan of it immediately, so its services fill in without waiting for the next
full rescan.

### Host identification

After the port sweep, the agent asks each live host what it is called, so the dashboard can show
`esxi-01.corp.local` (VMware ESXi host) instead of `10.1.0.5:443`. It reads the name from this
host's resolver, this host's `/etc/hosts`, the TLS certificate the device serves, its web page
title and `Server` header, and its NetBIOS name, and sends those observations to Ares, which
decides the name and the device type.

Unlike the port sweep, this sends application-layer bytes to your devices, so every source can be
turned off independently. The HTTP probe is a single unauthenticated `GET /` that never follows a
redirect and never sends a credential, so it cannot trip an account lockout.

| Variable | Default | Description |
|----------|---------|-------------|
| `ARES_IDENTIFY` | `true` | Master switch for host identification. `false` turns off everything below and restores the previous behaviour exactly. |
| `ARES_IDENTIFY_REVERSE_DNS` | `true` | Ask this host's resolver for a PTR record per discovered host. |
| `ARES_IDENTIFY_TLS` | `true` | Read the certificate served on TLS ports. Handshake only; nothing is sent afterwards. |
| `ARES_IDENTIFY_HTTP` | `true` | One unauthenticated `GET /` on web ports, for the page title and `Server` header. |
| `ARES_IDENTIFY_NETBIOS` | `true` | A NetBIOS node-status query (UDP 137), which names Windows machines that have no PTR record. |
| `ARES_IDENTIFY_DNS_TIMEOUT` | `2.0` | Seconds to wait for a PTR answer. |
| `ARES_IDENTIFY_TLS_TIMEOUT` | `3.0` | Seconds to wait for a TLS handshake. |
| `ARES_IDENTIFY_HTTP_TIMEOUT` | `3.0` | Seconds to wait for an HTTP response. |
| `ARES_IDENTIFY_NETBIOS_TIMEOUT` | `1.0` | Seconds to wait for a NetBIOS reply. |

Identification runs once per *live* host (never per open port), under its own concurrency limit,
and inside a fixed share of the scan's overall time budget. If that share runs out, the remaining
hosts are reported with their ports and without a name; the port results are never affected.

### Volume

| Path | Description |
|------|-------------|
| `/data` | Persistent state. Holds `agent-state.json` (the agent id and its auth token) so the agent keeps its identity across restarts. |
| `/host-ca` | *(optional, read-only)* This host's CA directory, mounted by the install command. Lets the agent trust whatever the host trusts. See [TLS inspection](#tls-inspection-corporate-proxy). |
| `/certs` | *(optional, read-only)* Drop-in for extra CA roots the host store does not have, e.g. a Kubernetes ConfigMap. Every `.crt`, `.pem`, or `.cer` inside is trusted. |

## Network requirements

The agent only makes **outbound** connections, all to your Ares URL:

| Direction | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Outbound | 443 | HTTPS | Registration, heartbeat, task polling, result reporting |
| Outbound | 443 | WebSocket (WSS) | Data-plane tunnel, opened only while a hunt is running |

**No inbound firewall rules are required.** Locally, the agent connects to the internal hosts on
whatever ports your hunt targets (commonly 80, 443, 8080, 8443).

### TLS inspection (corporate proxy)

**This works out of the box; there is nothing to configure.** If your network terminates and
re-signs outbound TLS, the install command mounts this host's CA directory into the agent
read-only at `/host-ca`, and the agent trusts those roots alongside the public ones. Your
inspection root is already trusted on the host (it has to be, or nothing on the machine could
browse), so that is all it takes.

Confirm it from the logs. The agent reports its trust before it connects to anything, then
rehearses both planes at startup so you find out at enrollment rather than mid-assessment:

```
INFO ares.agent TLS trust: image store, certifi, /host-ca (1 file)
INFO ares.agent Preflight: control plane OK (https://ares.assailai.com)
INFO ares.agent Preflight: data-plane tunnel OK (wss://ares.assailai.com/api/v1/agent/tunnel)
```

Both lines matter. Hunts that reach into your network run over the tunnel, and a proxy that
allows our HTTPS while refusing WebSocket upgrades leaves an agent that looks perfectly healthy
until the first assessment. If the second line reads `FAILED`, it names the likely cause; a
blocked upgrade usually means the proxy needs WebSocket allowed explicitly for this host. The
agent stays up either way.

If it says only `image store, certifi`, the mount did not happen. Add it by hand:

```bash
# Debian, Ubuntu, Alpine, SUSE. On RHEL / Fedora / Amazon Linux use
# /etc/pki/ca-trust/extracted/pem instead.
-v /etc/ssl/certs:/host-ca:ro
```

Both halves of the agent are covered: the control plane and the `wss://` data-plane tunnel that
live missions run over. `bash scripts/e2e_tls_inspection.sh` proves it against a real mitmproxy,
driving a stream through the inspected tunnel to an internal host and asserting it comes back
byte for byte.

Two cases need more than the host store:

- **Kubernetes**, where there is no host directory to mount. Put the root in a ConfigMap and
  mount it at `/certs` (see `deploy/k8s/ares-agent.yaml`).
- **A root that was never installed on the host.** Mount the directory holding it at `/certs`, or
  point `ARES_CA_BUNDLE` at the file.

Mount the same thing into `ares-updater`. It runs `cosign` to verify image signatures through the
same proxy and fails closed, so without the CAs the agent stays online but silently stops
auto-updating.

**When your inspection root rotates**, restart the agent so it picks the new one up:

```bash
docker restart ares-agent ares-updater
```

The agent reads the CA store once, at startup. The mount is of the *directory*, so the container
already sees the rotated file, but the running process is still verifying against what it read
when it started and will fail until it is restarted. No need to recreate the container or re-run
the install command: the mount and the token are unchanged, only the process needs to re-read.

**On an agent older than 3.4.0**, which verified against a bundle inside the Python package and
ignored the OS trust store entirely, the equivalent is two flags:

```bash
-v /etc/ssl/certs:/host-ca:ro -e SSL_CERT_FILE=/host-ca/ca-certificates.crt
```

## Name resolution

A hunt that reaches an internal host resolves that host's name **on this machine**, deliberately:
an internal name often only exists on your DNS, and split-horizon DNS would give Ares the wrong
answer. So the agent is only as good as this host's resolver.

**The agent reads this host's `/etc/hosts`.** The install command mounts it read-only at
`/host-hosts`, and the agent prefers a pin found there over DNS. This is worth stating plainly
because the obvious thing does *not* work on its own: a container gets Docker's own `/etc/hosts`
even under `--network host` (host networking shares the network namespace, not the mount
namespace), so before 3.5.0, editing `/etc/hosts` on the machine had no effect on the agent at
all. The file is re-read when it changes, so adding a pin later needs no restart:

```bash
echo "10.1.2.3  sso.acme.internal" | sudo tee -a /etc/hosts
```

For a pin you do not want in the host file, `ARES_HOST_ALIASES=sso.acme.internal=10.1.2.3` does
the same thing. Either way a pin only supplies the *address* DNS would have; the destination is
still checked against this agent's registered networks and what Ares approved, so pinning a name
can never widen what the agent will reach.

**A slow resolver is not a broken one.** glibc walks the nameservers in `/etc/resolv.conf` in
order at roughly five seconds each, so a name the first server will not answer only resolves once
it falls through to the second. The agent allows 15s for a lookup for exactly this reason. If you
see `did not resolve on this agent within 15s`, the resolver genuinely never answered: pin the
name, or point the container at a resolver that can answer it with `ARES_DNS`.

**One limit worth knowing.** All of the above covers *transparent* inspection, where the proxy is
in the network path and the agent dials Ares directly. An **explicit** proxy (one you point at
with `HTTPS_PROXY`) is not supported end to end: httpx honours the variable for the control
plane, but the tunnel's `websockets` client does not, so hunts would fail while the agent looked
online. If your network requires an explicit proxy rather than inspecting in-path, tell us before
you deploy.

## Security

- **Non-root, no privileges** - the container runs as an unprivileged user (uid 10001). It needs
  no `NET_ADMIN`, no `/dev/net/tun`, and no host `sysctl` changes.
- **Outbound-only** - the agent initiates every connection. Nothing listens for inbound traffic.
- **Scoped reach-in** - the data-plane tunnel only proxies to the networks you approved for the
  agent, or to the hostname of a target you explicitly approved and launched in Ares, enforced on
  the agent side. It exists only while a hunt is running. Names are resolved here, never in the
  cloud, and every refusal is logged with its reason. A broader, pattern-based approval (a login
  domain, or the wildcard used while an interactive sign-in is parked) reaches public addresses
  only, so it can never become a route into private, loopback or link-local space.
- **Scan scope is enforced twice** - a scan task names the network to scan, and the agent checks
  that network against its own scope before it starts. With `ARES_NETWORKS` set explicitly, that
  list is a ceiling the agent will not scan outside of, even if it is asked to.
- **Minimal image** - multi-stage Alpine build with runtime dependencies only; no secrets baked
  into the image.
- **Token at rest** - the agent's auth token lives in the `/data` volume (mode 0700), supplied at
  runtime and never in the image.

## Upgrading

Pin the agent to a specific version (the current release is shown in the Ares dashboard under
Settings -> Agents) rather than a moving tag, so deploys are reproducible. The `/data` volume
holds the agent's identity, so an upgrade is a pull and re-create on the new tag:

```bash
docker rm -f ares-agent
docker pull assailai/ares-agent:<new-version>
# re-run the docker run command from Getting started with the new tag (the volume is reused)
```

Or with Compose: bump the pinned `image:` tag, then `docker compose pull && docker compose up -d`.

### Re-installing over an existing agent

Reusing the volume keeps the identity, which is what makes an upgrade an upgrade rather than a
second agent. The agent decides from the `ARES_TOKEN` it is handed:

- **The same token it enrolled with** (an upgrade, or the auto-update companion recreating the
  container) - it keeps its identity and makes no registration call at all.
- **A registration token for a different agent** - it enrols under that one and logs
  `Re-enrolled as a new agent <id>`. The previous identity stops heartbeating and goes offline
  in the dashboard.
- **A token that is already spent** - it cannot become a new agent, so it keeps the identity it
  has and says so (`Keeping the existing agent identity`) rather than quietly carrying on as the
  wrong agent. Generate a fresh token, or discard the identity with `ARES_RESET=1`.

### Auto-update (the companion updater)

The deployment bundles a small `ares-updater` companion that keeps the agent on the version you
mark current in the dashboard. The **agent stays unprivileged**; only the updater holds the
platform access, verifies the target image's signature, and applies it:

- **Docker Compose** (`docker-compose.yml`): the `ares-updater` service holds the Docker socket
  and recreates the agent container on the new version, verify-then-swap (the replacement is
  confirmed up before the old container is removed, so a bad version never takes the agent down).
- **Kubernetes** (`deploy/k8s/ares-agent.yaml`): the updater runs as a sidecar with a
  ServiceAccount scoped to patch only the agent Deployment, triggering a native rolling update.

Notes:

- The agent moves to the exact version the dashboard marks current (a pinned tag), so rollouts
  are deterministic and promotable across environments.
- Verification is **fail-closed** (`ARES_UPDATE_REQUIRE_SIGNATURE=true`): the updater refuses an
  image it cannot cosign-verify. Set it `false` only for local/dev, before image signing is wired.
  To reproduce the updater's check by hand (cosign ships inside the updater image, so you do not
  need it installed locally):

  ```bash
  docker run --rm --entrypoint cosign assailai/ares-updater:3.3.3 \
    verify assailai/ares-agent:3.3.3 \
    --certificate-identity-regexp '^https://github\.com/assailai/docker-agent-ares/\.github/workflows/docker-build\.yml@refs/(heads/main|tags/v.*)$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

  If this fails while the image is genuinely published, the expected signer identity has drifted from
  what CI signs with — the updater logs both sides of the comparison on failure.
- The updater keeps the **agent** current; it does not update itself. Moving the updater to a new
  version is an operator action: re-run `scripts/bootstrap.sh`, `docker compose pull && docker
  compose up -d`, or re-apply the k8s manifest.
- Only the updater touches the runtime (the Docker socket, or the scoped k8s RBAC); the agent has
  neither. To disable auto-update, remove the updater service/sidecar and update the image
  yourself (`docker compose pull && docker compose up -d`, or your GitOps pipeline).

## Troubleshooting

Start with the logs: `docker logs ares-agent`. The agent narrates each step.

| Symptom in the logs | Cause and fix |
|---------------------|---------------|
| `ARES_TOKEN is required` | No token was passed. Add `-e ARES_TOKEN=...`. |
| `Registration token rejected` | The token expired or was already used. Generate a fresh one in Settings -> Agents. |
| `Cannot reach Ares at ...` | The host can't reach your Ares URL on 443. Check egress / proxy rules. The agent keeps retrying. |
| `CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain` | Your network is inspecting TLS and the agent does not trust the root doing it. See [TLS inspection](#tls-inspection-corporate-proxy). Check the `TLS trust:` line at startup to see what the agent did load. Installing the root *inside* the container with `update-ca-certificates` is not enough on agents older than 3.4.0, and does not survive an update on any version. |
| `Preflight: data-plane tunnel FAILED` | The agent can reach Ares but not open the tunnel that hunts run over, so it is online but cannot assess your internal network. The message names the likely cause. An HTTP status where a `101` belongs means something refused the upgrade rather than blocking the connection: allow WebSocket upgrades to your Ares host. The agent keeps running and retries when a hunt starts. |
| `No internal LAN auto-detected` | Auto-detection found nothing scannable. Set `ARES_NETWORKS=10.0.0.0/24,...` or edit the networks in the dashboard. |
| `Reachability probe budget of Ns is spent` | The probe ran out of wall clock and advertised what it had found so far. Raise `ARES_REACH_BUDGET_SECONDS`, or set `ARES_NETWORKS` to skip discovery. |
| `Heartbeat unauthorized` | The stored agent credentials were rejected (a decommissioned agent, or stale credentials from a kept `/data` volume). After a few consecutive rejections the agent tries to re-enroll with `ARES_TOKEN`: if the token is still unused it adopts a fresh identity and recovers; if the token is spent it keeps the current credentials and retries (it does not exit or wipe anything), so a decommissioned agent idles quietly. To give such an agent a new identity, redeploy with a fresh token. |
| `Keeping the existing agent identity` | You re-installed on a host that is already enrolled, with a registration token that is already spent, so this host stayed the agent it already was. Nothing was lost: it keeps serving under the identity it has. Generate a fresh token in Settings -> Agents, or re-run the installer with `ARES_RESET=1` to discard the stored identity first. See [Re-installing over an existing agent](#re-installing-over-an-existing-agent). |
| `Ares knows this agent as "..." which differs from ARES_AGENT_NAME` | Harmless when the name came from the deploy wizard (which overrides `ARES_AGENT_NAME` at enrollment) or was changed in the dashboard. If you meant to install a *new* agent on this host, it means the container is serving on an earlier enrollment - re-run the installer with a fresh token, or with `ARES_RESET=1`. |

**Health check.** The container is healthy once it has registered, which is when
`/data/agent-state.json` exists:

```bash
docker exec ares-agent test -f /data/agent-state.json && echo "registered"
```

**Complete reset** (you'll need a new registration token). The updater has to go too: it mounts
the same volume, and the engine will not remove a volume any container still references.

```bash
docker rm -f ares-agent ares-updater
docker volume rm ares-agent-data
```

Or let the installer do it, which is the same thing plus a clean re-enrollment:

```bash
ARES_RESET=1 ARES_TOKEN=<fresh-token> bash <(curl -fsSL https://raw.githubusercontent.com/assailai/ares-agent/main/scripts/bootstrap.sh)
```

## Versioning

We use [Semantic Versioning](https://semver.org/). For available versions, see the
[tags on Docker Hub](https://hub.docker.com/r/assailai/ares-agent/tags).

### Cutting a release

`agent/__version__.py` is the trigger. Bump it, move the pins that name the old version
(`scripts/bootstrap.sh`, `docker-compose.yml`, `deploy/k8s/ares-agent.yaml`), and merge to `main`.
`auto-tag.yml` then creates the `v<version>` tag and the GitHub release, and builds, pushes and
cosign-signs both images (`assailai/ares-agent` and `assailai/ares-updater`) as
`<version>`, `<major>.<minor>` and `<major>`.

Two things that are easy to get wrong:

- **Don't push the `v<version>` tag by hand.** `auto-tag.yml` skips its image build when the tag
  already exists, so a hand-pushed tag leaves you with a tag and a release but **no images**.
- **A release that changes `updater/` does not roll itself out.** The updater keeps the *agent*
  current; nothing updates the updater. Every deployment has to recreate it before the change takes
  effect — see [Auto-update](#auto-update-the-companion-updater).

## Support

- **Documentation**: [https://www.assailai.com](https://www.assailai.com)
- **Email**: support@assailai.com
- **Issues**: [GitHub Issues](https://github.com/assailai/ares-agent/issues)

If you discover a security vulnerability, please email security@assailai.com instead of opening a
public issue.

## License

This software is proprietary and provided under the [Assail, Inc. Terms of Service](https://www.assailai.com/terms).
Use of this agent requires an active Ares subscription. See [LICENSE](LICENSE) for details.

---

Copyright 2025 Assail, Inc. All rights reserved.
