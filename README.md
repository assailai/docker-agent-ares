# Ares Agent

[![Docker Image Version](https://img.shields.io/docker/v/assailai/ares-agent?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/assailai/ares-agent)
[![GitHub Container Registry](https://img.shields.io/badge/ghcr.io-available-blue)](https://github.com/assailai/ares-agent/pkgs/container/ares-agent)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/Security-Hardened-green.svg)](#security)

Customer-deployable Docker agent for scanning internal APIs through the [Ares](https://www.assailai.com) platform. Deploy this agent inside your network to enable secure API security testing of internal services that aren't exposed to the internet.

## Overview

The Ares Agent establishes a secure WireGuard VPN tunnel from your internal network to the Ares platform, allowing Ares to perform comprehensive API security testing on your internal services without requiring inbound firewall rules or exposing your APIs to the internet.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Your Internal Network                         │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐  │
│  │ Internal    │      │   Ares      │      │  Internal APIs      │  │
│  │ Services    │◄────►│   Agent     │◄────►│  (10.x.x.x)         │  │
│  └─────────────┘      └──────┬──────┘      └─────────────────────┘  │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │ WireGuard VPN (Outbound UDP 51820)
                               │ ChaCha20-Poly1305 Encryption
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Ares Cloud Platform                          │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐  │
│  │ API Security│      │   Tunnel    │      │  Results &          │  │
│  │ Scanner     │◄────►│   Gateway   │◄────►│  Dashboard          │  │
│  └─────────────┘      └─────────────┘      └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

- **Web-Based Setup Wizard** - Intuitive browser-based configuration with step-by-step guidance
- **Secure by Default** - Non-root execution, TLS encryption, bcrypt password hashing, session management
- **Encryption at Rest** - Sensitive data (keys, tokens) encrypted using Fernet (AES-128-CBC + HMAC)
- **WireGuard VPN Tunnel** - Industry-standard encrypted tunnel using ChaCha20-Poly1305
- **No Inbound Firewall Rules** - Agent initiates all connections; no ports need to be opened inbound
- **Persistent Configuration** - Settings survive container restarts via Docker volumes
- **Health Monitoring** - Built-in health checks for container orchestration
- **Audit Logging** - All administrative actions logged locally

## Quick Start

### Pull and Run

```bash
# Using Docker Hub
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:latest

# Or using GitHub Container Registry
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  ghcr.io/assailai/ares-agent:latest
```

> **Note:** The flags above are **required** for WireGuard VPN to function:
> - `--user root` - WireGuard needs root to create network interfaces
> - `--cap-add=NET_ADMIN` - Required capability for network interface management
> - `--device /dev/net/tun` - TUN device for WireGuard userspace implementation
> - `--sysctl net.ipv4.ip_forward=1` - Enable IP forwarding for routing to internal networks
> - `-e ARES_RUN_AS_ROOT=true` - Tells entrypoint to keep running as root

### Get Initial Password

```bash
docker logs ares-agent
```

You'll see output like:

```
╔══════════════════════════════════════════════════════════════════════╗
║                    ARES DOCKER AGENT v1.1.0                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Web Interface:  https://192.168.1.50:8443                           ║
║  Initial Password:  xK9#mP2$vL5@nQ8                                  ║
║                                                                      ║
║  NOTE: You MUST change this password on first login.                 ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Access Web Interface

1. Navigate to `https://<your-host>:8443` in your browser
2. Accept the self-signed certificate warning
3. Log in with the initial password from the logs
4. Complete the setup wizard

## Upgrading

To upgrade an existing agent to the latest version while preserving your configuration:

```bash
# Stop and remove current container
docker stop ares-agent && docker rm ares-agent

# Pull latest image
docker pull assailai/ares-agent:latest

# Start upgraded agent (with all required flags)
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:latest
```

Your registration, WireGuard keys, and settings are stored in the `ares-agent-data` volume and will be preserved across upgrades.

## Requirements

| Requirement | Details |
|-------------|---------|
| **Docker** | Version 20.10 or later |
| **Root User** | `--user root` (required for WireGuard VPN) |
| **NET_ADMIN** | `--cap-add=NET_ADMIN` (required for network interface creation) |
| **TUN Device** | `--device /dev/net/tun:/dev/net/tun` |
| **IP Forwarding** | `--sysctl net.ipv4.ip_forward=1` (required for routing to internal networks) |
| **Environment** | `-e ARES_RUN_AS_ROOT=true` (keeps agent running as root) |
| **Outbound UDP** | Port 51820 to Ares platform (WireGuard) |
| **Outbound TCP** | Port 443 to Ares platform (Registration) |
| **Memory** | Minimum 256MB |
| **Disk** | Minimum 100MB for data volume |

> **No host WireGuard installation required** - The agent includes wireguard-go (userspace WireGuard implementation).

## Installation

### Docker Run

```bash
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:latest
```

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  ares-agent:
    image: assailai/ares-agent:latest
    container_name: ares-agent
    user: root
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    environment:
      - ARES_RUN_AS_ROOT=true
    ports:
      - "8443:8443"
    volumes:
      - ares-agent-data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "--no-check-certificate", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

volumes:
  ares-agent-data:
```

Then run:

```bash
docker-compose up -d
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ares-agent
  labels:
    app: ares-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ares-agent
  template:
    metadata:
      labels:
        app: ares-agent
    spec:
      containers:
      - name: ares-agent
        image: assailai/ares-agent:latest
        env:
        - name: ARES_RUN_AS_ROOT
          value: "true"
        ports:
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: data
          mountPath: /data
        - name: tun-device
          mountPath: /dev/net/tun
        securityContext:
          runAsUser: 0
          capabilities:
            add:
            - NET_ADMIN
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: ares-agent-pvc
      - name: tun-device
        hostPath:
          path: /dev/net/tun
          type: CharDevice
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ares-agent-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: ares-agent
spec:
  selector:
    app: ares-agent
  ports:
  - port: 8443
    targetPort: 8443
    name: https
  type: ClusterIP
```

## Configuration

### Setup Wizard Steps

1. **Login** - Use the initial password from container logs
2. **Change Password** - Set a strong password (minimum 12 characters)
3. **Platform URL** - Enter your Ares platform URL (e.g., `https://api.assail.ai`)
4. **Registration Token** - Generate a token from the Ares dashboard and enter it here
5. **Internal Networks** - Define which CIDR ranges can be scanned (e.g., `10.0.0.0/8`, `172.16.0.0/12`)
6. **Agent Name** - Give your agent a descriptive name for the dashboard
7. **Connect** - Establish the WireGuard tunnel

### Restarting the Agent After Configuration Changes

After making changes to agent settings (such as updating internal networks, agent name, or other configuration), you need to restart the agent for changes to take effect.

**Via the Web Interface (Recommended):**
1. Navigate to **Settings** in the web interface
2. Click the **Restart Agent** button
3. Wait for the tunnel to reconnect (usually takes 5-10 seconds)

**Via Docker Command Line:**
```bash
# Restart the container (preserves configuration)
docker restart ares-agent

# View logs to confirm successful restart
docker logs -f ares-agent
```

**Via Docker Compose:**
```bash
docker-compose restart ares-agent
```

> **Note:** Restarting the agent will briefly disconnect the WireGuard tunnel. Any in-progress scans will automatically resume once the tunnel is re-established.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Directory for persistent data |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `HTTPS_PORT` | `8443` | Port for web interface |

### Volumes

| Path | Description |
|------|-------------|
| `/data` | All persistent data (config, database, certificates) |
| `/data/tls` | TLS certificates for web interface |
| `/data/wireguard` | WireGuard VPN configuration |
| `/data/db` | SQLite database |

### Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 8443 | TCP | Web interface (HTTPS) |

## Network Requirements

### Outbound (Required)

| Destination | Port | Protocol | Description |
|-------------|------|----------|-------------|
| Ares Platform | 51820 | UDP | WireGuard VPN tunnel |
| Ares Platform | 443 | TCP | Initial registration and API |

### Inbound

**No inbound firewall rules required.** The agent initiates all connections outbound.

## Security

The Ares Agent is built with security as a top priority:

### Container Security
- **Root + NET_ADMIN required** - WireGuard VPN requires root and NET_ADMIN capability for network interface management
- **Userspace WireGuard** - Uses wireguard-go, no kernel module required
- **Minimal attack surface** - Multi-stage build with only runtime dependencies
- **No secrets in image** - All credentials provided at runtime
- **Isolated networking** - WireGuard creates an isolated overlay network
- **Auto-recovery** - Automatically attempts to restore tunnel if it goes down

### Authentication & Sessions
- **bcrypt password hashing** - Cost factor 12
- **Secure sessions** - 24-hour expiry, HttpOnly, SameSite=Strict cookies
- **Account lockout** - 5 failed attempts triggers 30-minute lockout
- **Forced password change** - Initial password must be changed on first login

### Data Protection
- **Encryption at rest** - Sensitive data encrypted using Fernet (AES-128-CBC + HMAC)
- **Key derivation** - HKDF with unique contexts per data type
- **Protected fields** - WireGuard private keys, JWT tokens, registration tokens
- **Secure key storage** - Master encryption key stored with 0600 permissions

### Network Security
- **TLS 1.2+** - Self-signed certificate auto-generated on first run
- **WireGuard VPN** - ChaCha20-Poly1305 authenticated encryption
- **No inbound ports** - Agent initiates all connections

### Audit & Compliance
- **Audit logging** - All administrative actions logged with timestamps
- **Docker Scout compliant** - Passes Docker security scanning
- **CVE monitoring** - Dependencies pinned to versions with known CVE fixes

## Troubleshooting

### Container Won't Start

**Symptom:** Container exits immediately

**Solution:** Ensure all required flags are provided:
```bash
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:latest
```

### WireGuard Tunnel Failed to Start

**Symptom:** Error message "Failed to start WireGuard tunnel"

**Common causes and solutions:**

| Cause | Solution |
|-------|----------|
| Not running as root | Add `--user root` flag |
| Missing NET_ADMIN capability | Add `--cap-add=NET_ADMIN` flag |
| Missing TUN device | Add `--device /dev/net/tun:/dev/net/tun` flag |
| Missing IP forwarding | Add `--sysctl net.ipv4.ip_forward=1` flag |
| Missing environment variable | Add `-e ARES_RUN_AS_ROOT=true` flag |

The agent now performs pre-flight checks and will log specific errors indicating which flag is missing.

### Can't Access Web Interface

**Checklist:**
1. Verify container is running: `docker ps | grep ares-agent`
2. Check container logs: `docker logs ares-agent`
3. Verify port mapping: `docker port ares-agent`
4. Test local access from host: `curl -k https://localhost:8443/health`

### WireGuard Tunnel Not Connecting

**Checklist:**
1. Verify outbound UDP 51820 is allowed by your firewall
2. Check registration token hasn't expired (24-hour validity)
3. Verify platform URL is correct
4. Check agent logs in web interface (Dashboard > Logs)

### Remove and Reinstall (Complete Reset)

Use this when you forgot your password, need to re-register with a new token, or encounter any issues:

```bash
# One-liner: Stop, remove container and data, pull latest, and run
docker rm -f ares-agent; \
docker volume rm ares-agent-data; \
docker pull assailai/ares-agent:latest && \
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:latest
```

Then get the new initial password:
```bash
docker logs ares-agent
```

### Update to Latest Version

```bash
# Pull latest image and recreate container (preserves data)
docker pull assailai/ares-agent:latest && \
docker rm -f ares-agent && \
docker run -d --name ares-agent \
  --user root \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -e ARES_RUN_AS_ROOT=true \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:latest
```

### Health Check Failing

View detailed health status:
```bash
docker exec ares-agent wget -qO- --no-check-certificate https://localhost:8443/health
```

## Versioning

We use [Semantic Versioning](https://semver.org/). For available versions, see the [tags on Docker Hub](https://hub.docker.com/r/assailai/ares-agent/tags).

| Version | Status | Notes |
|---------|--------|-------|
| 2.0.x | Current | Improved WireGuard diagnostics, pre-flight checks, auto-recovery, simplified docker run |
| 1.1.x | Legacy | WireGuard fixes, required privileged mode |
| 1.0.x | Legacy | May have WireGuard connectivity issues |

## Support

- **Documentation**: [https://www.assailai.com](https://www.assailai.com)
- **Email**: support@assailai.com
- **Issues**: [GitHub Issues](https://github.com/assailai/ares-agent/issues)

### Reporting Security Vulnerabilities

If you discover a security vulnerability, please email security@assailai.com instead of opening a public issue. We take security seriously and will respond promptly.

## License

This software is proprietary and provided under the [Assail, Inc. Terms of Service](https://www.assailai.com/terms). Use of this agent requires an active Ares subscription.

See [LICENSE](LICENSE) for details.

---

Copyright 2025 Assail, Inc. All rights reserved.
