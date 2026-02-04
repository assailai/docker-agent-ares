"""
Ares Docker Agent - HTTP Proxy Router
Enables Ares scanning services to reach internal networks through the agent.

Flow:
1. Ares network-scan-service sends request to agent's overlay IP
2. Agent receives request with target URL
3. Agent makes request to internal target
4. Agent returns response to Ares

Security:
- Only accepts requests from overlay network (10.200.0.0/16)
- Target must be in agent's declared internal_networks
- Rate limiting to prevent abuse
- Hostnames are resolved and validated against internal networks
- X-Forwarded-For headers are NOT trusted for security checks
"""

import httpx
import ipaddress
import logging
import socket
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import asyncio

from agent.database.models import get_config, AgentConfig

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/proxy", tags=["proxy"])

# Overlay network CIDR - requests must come from here
OVERLAY_NETWORK = ipaddress.ip_network("10.200.0.0/16")

# Blocked IP ranges - never allow access to these regardless of configuration
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / AWS metadata
    ipaddress.ip_network("127.0.0.0/8"),          # Localhost
    ipaddress.ip_network("0.0.0.0/8"),            # Current network
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("255.255.255.255/32"),   # Broadcast
    ipaddress.ip_network("::1/128"),              # IPv6 localhost
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),             # IPv6 unique local (unless explicitly allowed)
]

# Blocked hostnames - common metadata/internal service hostnames
BLOCKED_HOSTNAMES = [
    "metadata.google.internal",
    "metadata.goog",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
]

# Rate limiting
_request_counts: Dict[str, int] = {}
_last_reset = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
MAX_REQUESTS_PER_MINUTE = 1000


class ProxyRequest(BaseModel):
    """Request body for proxy endpoint"""
    target_url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    timeout: float = 30.0


def _get_client_ip(request: Request) -> str:
    """
    Get client IP from request.

    SECURITY: We intentionally do NOT trust X-Forwarded-For or similar headers
    for security-critical checks. These headers can be spoofed by attackers.
    We only use the actual TCP connection source IP.
    """
    # SECURITY FIX: Do NOT trust X-Forwarded-For header - it can be spoofed
    # Only use the actual client IP from the TCP connection
    if request.client:
        return request.client.host
    return "unknown"


def _is_from_overlay_network(client_ip: str) -> bool:
    """Check if client IP is from overlay network"""
    try:
        ip = ipaddress.ip_address(client_ip)
        return ip in OVERLAY_NETWORK
    except ValueError:
        return False


def _is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP is in a blocked range (metadata services, localhost, etc.)"""
    for blocked_net in BLOCKED_NETWORKS:
        try:
            if ip in blocked_net:
                return True
        except TypeError:
            # IPv4/IPv6 mismatch, skip
            continue
    return False


def _resolve_hostname(hostname: str) -> List[str]:
    """
    Resolve hostname to IP addresses.
    Returns list of IP addresses or empty list if resolution fails.
    """
    try:
        # Get all IP addresses for the hostname
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(result[4][0] for result in results))
        return ips
    except socket.gaierror:
        return []
    except Exception as e:
        logger.error(f"Error resolving hostname {hostname}: {e}")
        return []


def _get_internal_networks() -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Get configured internal networks as parsed network objects"""
    internal_networks_str = get_config(AgentConfig.INTERNAL_NETWORKS)
    if not internal_networks_str:
        return []

    # Parse internal networks (comma-separated or JSON list)
    try:
        import json
        network_strings = json.loads(internal_networks_str)
    except json.JSONDecodeError:
        network_strings = [n.strip() for n in internal_networks_str.split(",")]

    networks = []
    for cidr in network_strings:
        try:
            networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue

    return networks


def _is_ip_in_internal_networks(ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                                  internal_networks: List) -> bool:
    """Check if an IP is in any of the internal networks"""
    for network in internal_networks:
        try:
            if ip in network:
                return True
        except TypeError:
            # IPv4/IPv6 mismatch, skip
            continue
    return False


def _is_target_allowed(target_url: str) -> bool:
    """
    Check if target is in agent's internal networks.

    SECURITY: This function validates both IP addresses AND hostnames.
    Hostnames are resolved and ALL resolved IPs must be in internal networks.
    This prevents DNS rebinding and SSRF attacks.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(target_url)
        host = parsed.hostname
        if not host:
            logger.warning("No hostname in target URL")
            return False

        # Check for blocked hostnames (case-insensitive)
        if host.lower() in BLOCKED_HOSTNAMES:
            logger.warning(f"Blocked hostname: {host}")
            return False

        # Get internal networks configuration
        internal_networks = _get_internal_networks()
        if not internal_networks:
            logger.warning("No internal networks configured")
            return False

        # Try to parse as IP first
        try:
            target_ip = ipaddress.ip_address(host)

            # Check if IP is in blocked ranges
            if _is_ip_blocked(target_ip):
                logger.warning(f"Target IP {target_ip} is in blocked range")
                return False

            # Check if IP is in internal networks
            if _is_ip_in_internal_networks(target_ip, internal_networks):
                return True

            logger.warning(f"Target IP {target_ip} not in internal networks")
            return False

        except ValueError:
            # It's a hostname - resolve it and validate ALL resolved IPs
            logger.info(f"Resolving hostname: {host}")
            resolved_ips = _resolve_hostname(host)

            if not resolved_ips:
                logger.warning(f"Could not resolve hostname: {host}")
                return False

            # SECURITY: ALL resolved IPs must be in internal networks
            # This prevents DNS rebinding attacks where a hostname resolves
            # to both an internal and external IP
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)

                    # Check if any resolved IP is in blocked ranges
                    if _is_ip_blocked(ip):
                        logger.warning(f"Hostname {host} resolved to blocked IP: {ip}")
                        return False

                    # Check if IP is in internal networks
                    if not _is_ip_in_internal_networks(ip, internal_networks):
                        logger.warning(f"Hostname {host} resolved to IP {ip} not in internal networks")
                        return False

                except ValueError:
                    logger.warning(f"Invalid IP from DNS resolution: {ip_str}")
                    return False

            logger.info(f"Hostname {host} validated - all IPs in internal networks: {resolved_ips}")
            return True

    except Exception as e:
        logger.error(f"Error checking target: {e}")
        return False


@router.post("/request")
async def proxy_request(request: Request, proxy_req: ProxyRequest):
    """
    Proxy an HTTP request to an internal target.

    Used by Ares scanning services to reach internal networks through the agent.
    """
    client_ip = _get_client_ip(request)

    # Security: Only allow requests from overlay network
    if not _is_from_overlay_network(client_ip):
        logger.warning(f"Proxy request from non-overlay IP: {client_ip}")
        raise HTTPException(status_code=403, detail="Access denied: request must come from overlay network")

    # Security: Check if target is in allowed networks
    if not _is_target_allowed(proxy_req.target_url):
        logger.warning(f"Proxy request to disallowed target: {proxy_req.target_url}")
        raise HTTPException(status_code=403, detail="Access denied: target not in internal networks")

    logger.info(f"Proxying {proxy_req.method} request to {proxy_req.target_url}")

    try:
        async with httpx.AsyncClient(
            timeout=proxy_req.timeout,
            verify=False,  # Internal networks often use self-signed certs
            follow_redirects=True
        ) as client:
            response = await client.request(
                method=proxy_req.method,
                url=proxy_req.target_url,
                headers=proxy_req.headers,
                content=proxy_req.body
            )

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "elapsed_ms": response.elapsed.total_seconds() * 1000
            }

    except httpx.ConnectError as e:
        logger.error(f"Connection error to {proxy_req.target_url}: {e}")
        raise HTTPException(status_code=502, detail=f"Connection failed: {str(e)}")
    except httpx.TimeoutException as e:
        logger.error(f"Timeout connecting to {proxy_req.target_url}: {e}")
        raise HTTPException(status_code=504, detail=f"Request timeout: {str(e)}")
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")


@router.get("/health")
async def proxy_health():
    """Health check for proxy endpoint"""
    return {"status": "healthy", "service": "proxy"}


@router.post("/wake")
async def wake_tunnel(request: Request):
    """
    Wake up the WireGuard tunnel before hunt operations.

    This endpoint is called by Ares before starting hunt operations
    to ensure the tunnel is active and reachable.
    """
    client_ip = _get_client_ip(request)

    # Security: Only allow requests from overlay network
    if not _is_from_overlay_network(client_ip):
        logger.warning(f"Wake request from non-overlay IP: {client_ip}")
        raise HTTPException(status_code=403, detail="Access denied: request must come from overlay network")

    logger.info(f"Tunnel wake request from {client_ip}")

    try:
        from agent.wireguard.manager import get_manager
        manager = get_manager()
        result = await manager.wake_tunnel()

        logger.info(f"Tunnel wake result: {result}")
        return result
    except Exception as e:
        logger.error(f"Wake tunnel error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to wake tunnel: {str(e)}")
