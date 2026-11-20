# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.12.x  | :white_check_mark: |
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
