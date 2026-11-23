# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.15.x  | :white_check_mark: |
| 3.x     | :white_check_mark: |
| < 3.0   | :x:                |

> **IMPORTANT**: Only the current 3.x line receives security fixes. The companion updater
> automatically rolls deployments to the version the platform marks current, so running the
> latest 3.x is the supported configuration. Anything older than 3.0 should be upgraded.

## Reporting a Vulnerability

We take the security of the Ares Agent seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **security@assailai.com**

Include the following information:
- Type of vulnerability (e.g., authentication bypass, injection, etc.)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue and potential attack scenarios

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Assessment**: We will investigate and assess the vulnerability within 7 days
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days
- **Credit**: With your permission, we will credit you in our security advisories

### Safe Harbor

We consider security research conducted in accordance with this policy to be:
- Authorized concerning any applicable anti-hacking laws
- Authorized concerning any relevant anti-circumvention laws
- Exempt from restrictions in our Terms of Service that would interfere with conducting security research

We will not pursue civil or criminal action against researchers who follow this policy.

## Security Measures

The Ares Agent implements multiple layers of security:

### Container Security
- Non-root execution (UID 10001)
- Multi-stage builds with minimal attack surface
- No secrets baked into images
- Compatible with `--security-opt no-new-privileges:true`
- Images signed with keyless cosign (Sigstore/OIDC); the companion updater cosign-verifies the target digest before applying an update
- Regular Docker Scout vulnerability scanning

### Install Integrity
- Update integrity below begins once an updater is running, so the first image has to establish
  it. All three documented install paths verify before anything starts: `scripts/bootstrap.sh`
  does it itself, and Compose and Kubernetes go through `scripts/verify-images.sh`
- Verification is a digest-pinned cosign from Sigstore, never the `ares-updater` image: one of the
  two artifacts being checked must not be the thing that vouches for itself
- What is started is the **digest** that was verified, not the tag it was found under. The
  `ares-updater` container holds the Docker socket or a ServiceAccount able to patch its own
  Deployment, so an image substituted at install time is host-equivalent access and would then
  decide every later verification
- Compose enforces this: `docker-compose.yml` names no image of its own and refuses to start until
  the verified digests are in `.env`. Kubernetes cannot — `kubectl` has no variable substitution,
  so pinning the manifest is a documented step rather than a gate, and an admission policy is what
  enforces it if you need that
- Fail-closed, with no skip flag: a host that cannot reach the registry, ghcr.io, Fulcio or Rekor
  fails the install instead of proceeding unverified

### Release Integrity
- Release images are built and signed only by `docker-build.yml` on `refs/heads/main`, the
  protected branch. The job refuses to push from any other ref, and its credentials live in a
  deployment environment restricted to that branch
- Every third-party action is pinned by commit, and so is every container those actions run on the
  signing runner — the QEMU emulator it runs `--privileged` and the BuildKit builder that produces
  the bytes being signed. An action pinned by commit whose image floats pins nothing
- `v*` tags can be created only by the release workflow. `auto-tag.yml` additionally refuses a
  pre-existing release tag that does not resolve to a commit in `main`'s history that cut that
  exact version, rather than trusting the tag's name

### Update Integrity
- The companion updater applies only an image cosign verifies against this repository's build
  workflow at `refs/heads/main`, and applies the digest that was attested rather than re-resolving
  the tag
- A signature proves the artifact, not that the version is the current one, so the updater
  separately refuses any target that is not a plain `x.y.z` release, and any release older than
  the one the updater itself was built as. `ARES_UPDATE_ALLOW_DOWNGRADE=true` lets an operator
  move the agent back to an older release deliberately; nothing admits a non-release target
- Known limitation, Kubernetes: the updater is a container in the Deployment it patches, and the
  shipped manifest uses `strategy: Recreate` (a ReadWriteOnce PVC cannot attach to two pods at
  once). Its own patch therefore usually terminates it, so **the automatic restore does not run on
  that topology**; recovery from a bad rollout is `kubectl rollout undo`. What the updater does
  guarantee there is that a failed rollout is never recorded as applied: the replacement sidecar
  reads the Deployment's *status*, not its spec, so it keeps reporting the update as unfinished
  instead of silently believing it succeeded. On Docker and Podman the updater is a separate
  container, and it does restore the previous image itself
- Known limitation, downgrade floor: the floor is the updater's own release, so with
  `ARES_UPDATE_SELF_UPDATE=false` it stays at the release the updater was installed as while the
  agent moves past it. The updater says so in its startup log

### Authentication
- bcrypt password hashing (cost factor 12)
- Secure session management with HttpOnly cookies
- Account lockout after failed attempts
- Forced password change on first login

### Data Protection
- Sensitive data encrypted at rest using Fernet (AES-128-CBC + HMAC)
- Encryption keys derived via HKDF with unique contexts per data type
- Protected fields: WireGuard private key, JWT tokens, registration tokens
- Master encryption key stored separately from database with 0600 permissions

### Network Security
- TLS 1.2+ for all connections, verified against the union of the image's CA store, certifi's
  public roots, and any CA the operator mounts that the host trusts for TLS **server**
  authentication (a host's e-mail and code-signing trust extracts are not loaded)
- Outbound-only: the control plane is HTTPS and the data plane is an outbound WebSocket the agent
  opens only while a hunt runs. No inbound ports are required.
- The host CA mount (`/host-ca`) is read-only and covers the public certificate directory only;
  `/etc/ssl/private` is never mounted, so no host private key is exposed to the container

### Dependencies
- Direct dependencies pinned in `requirements.txt` / `requirements-updater.txt`; the full
  transitive set, and a hash for every artifact, in the generated `*-lock.txt` beside them
- The shipped images install from the lock with `pip --require-hashes`, so a release build
  installs exactly the artifacts a reviewed commit recorded, or it fails
- Every `FROM` that contributes to a shipped image is pinned by digest; `apk upgrade` still takes
  Alpine's current packages on each build
- Regular security audits and CVE monitoring
- Automated dependency updates via Dependabot, covering the transitive set as well as the direct
  one
