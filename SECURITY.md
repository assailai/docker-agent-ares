# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :x: (security vulnerabilities - upgrade immediately) |
| 1.0.x   | :x: |

> **IMPORTANT**: Version 2.1.0 contains critical security fixes. All users should upgrade immediately.

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
- TLS 1.2+ for all connections
- WireGuard VPN with ChaCha20-Poly1305 encryption
- No inbound ports required

### Dependencies
- All dependencies pinned to specific versions
- Regular security audits and CVE monitoring
- Automated dependency updates via Dependabot
