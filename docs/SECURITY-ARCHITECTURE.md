# Security Architecture & Validation

This document covers the Ares Agent's multi-tenant isolation model and answers common security questions about the deployment.

## Architecture Overview

Each agent is one container, one customer. The agent opens a WireGuard tunnel to the Ares platform, then proxies scan traffic into the customer's internal network.

```
Customer A Network          Customer B Network
┌──────────────────┐        ┌──────────────────┐
│  Agent A          │        │  Agent B          │
│  WG key: keyA     │        │  WG key: keyB     │
│  Overlay: 10.200.1.10 │   │  Overlay: 10.200.1.20 │
│  Networks: 10.0.0.0/8 │   │  Networks: 10.0.0.0/8 │
└────────┬─────────┘        └────────┬─────────┘
         │ WireGuard                  │ WireGuard
         └────────────┬───────────────┘
                      ▼
              Ares Platform Gateway
              (routes by overlay IP)
```

---

## Can a customer on Agent A's network reach Agent B's network?

**No.** There are three things stopping this:

**WireGuard keys are unique per agent.** Each agent generates its own Curve25519 key pair (`agent/wireguard/keys.py`) and gets a unique overlay IP from the platform. Agents can only talk to the gateway — they can't peer with each other.

**The SOCKS5 proxy validates destinations.** `SOCKS5Proxy._handle_connect_request()` checks that the target IP is within the agent's configured `internal_networks`. It also rejects any source IP outside `10.200.0.0/16`. So even a misrouted request to the wrong agent gets blocked unless the destination happens to be in that agent's allowed list too.

**The HTTP proxy does the same, plus more.** `_is_target_allowed()` in `web/routers/proxy.py` resolves hostnames and validates ALL resulting IPs against internal networks. It blocks AWS metadata endpoints, localhost, multicast, and ignores X-Forwarded-For headers entirely.

**One gap:** `TENANT_ID` exists in the `AgentConfig` schema but is never populated or checked. Isolation works without it — it's enforced at the network level — but the dead field is confusing. It should either be wired up during registration (useful for audit logs) or removed.

---

## Concurrent operation limits

There aren't any enforced right now.

The SOCKS5 proxy tracks `_active_connections` but never caps it. The HTTP proxy defines `MAX_REQUESTS_PER_MINUTE = 1000` and has `_request_counts` / `_last_reset` variables ready to go, but the check is never called in `proxy_request()`. Both should be wired up.

All traffic goes through a single WireGuard tunnel per agent.

---

## VPN tunnel performance

WireGuard's ChaCha20-Poly1305 adds very little overhead on modern hardware. The SOCKS5 relay (`SOCKS5Proxy._relay()`) is pure asyncio with 32KB buffers — no threads, no copies.

The `WireGuardManager` monitors the tunnel every 30 seconds and retries up to 3 times on failure with backoff (1s, 2s, 5s). Keepalive is set to 25 seconds for NAT traversal.

Main bottlenecks are network latency to the gateway and asyncio event loop saturation under many concurrent connections. No benchmarks exist in the repo yet.

---

## Known agent vulnerabilities

### Accepted trade-offs
| Finding | Why it's fine |
|---------|---------------|
| HTTP proxy uses `verify=False` | Internal services often have self-signed certs. This is intentional. |
| SOCKS5 uses `NO_AUTH` | It only listens on the overlay IP and validates source IPs. WireGuard already encrypts the traffic. |
| JWT token stored unencrypted in the DB | The DB file is on a permissioned volume. Encrypting it adds complexity without real benefit. |

### Fixed
| Finding | Fix |
|---------|-----|
| Rate limiting was defined but not enforced | `_check_rate_limit()` now enforces `MAX_REQUESTS_PER_MINUTE` (1000/min) in `proxy_request()` |
| No SOCKS5 connection cap | `MAX_SOCKS5_CONNECTIONS` (200) rejects new connections at capacity |
| Domain resolution trusted agent's DNS | Resolved IPs are pinned — the validated IP is used for the connection, preventing DNS rebinding |

---

## What happens when two customers both use 10.0.0.1?

This works fine. Each agent proxies to its own local network — Agent A reaches 10.0.0.1 on Customer A's LAN, Agent B reaches 10.0.0.1 on Customer B's LAN. The platform routes to the right agent using the unique overlay IP (10.200.x.x). There's no cross-agent routing.

The risk is on the platform side: if it routes to the wrong overlay IP, the scan hits the wrong customer's network. The agent can't tell the difference. This is a platform routing concern, not an agent one.

---

## Tenant ID filtering

Not implemented. `TENANT_ID` is defined as a config key in `AgentConfig` but never set during registration, never checked in proxy or SOCKS5 code, and not included in audit logs.

The agent relies on implicit isolation (unique keys, overlay IPs, network validation) rather than explicit tenant ID checks. To improve this:

1. Have the platform return `tenant_id` during registration
2. Store it in the agent config
3. Include it in audit log entries
4. Optionally have the platform send `X-Tenant-ID` in proxy requests so the agent can verify it matches

---

## Summary

| Area | Status | Risk |
|------|--------|------|
| Cross-tenant isolation | Three layers of enforcement | Low |
| Concurrent operations | Rate limiting + connection caps enforced | Low |
| VPN performance | Solid, but no benchmarks | Low |
| Agent vulnerabilities | Reviewed and addressed | Low |
| Overlapping networks | Works by design | Low |
| Tenant ID filtering | Not implemented | Medium |
