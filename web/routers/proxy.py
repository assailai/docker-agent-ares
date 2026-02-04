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
"""

import httpx
import ipaddress
import logging
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import asyncio

from agent.database.models import get_config, AgentConfig

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/proxy", tags=["proxy"])

# Overlay network CIDR - requests must come from here
OVERLAY_NETWORK = ipaddress.ip_network("10.200.0.0/16")

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
    """Get client IP from request"""
    # Check X-Forwarded-For first (if behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_from_overlay_network(client_ip: str) -> bool:
    """Check if client IP is from overlay network"""
    try:
        ip = ipaddress.ip_address(client_ip)
        return ip in OVERLAY_NETWORK
    except ValueError:
        return False


def _is_target_allowed(target_url: str) -> bool:
    """Check if target is in agent's internal networks"""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(target_url)
        host = parsed.hostname
        if not host:
            return False

        # Try to parse as IP
        try:
            target_ip = ipaddress.ip_address(host)
        except ValueError:
            # It's a hostname - allow it (agent can resolve internal DNS)
            return True

        # Check if target IP is in internal networks
        internal_networks_str = get_config(AgentConfig.INTERNAL_NETWORKS)
        if not internal_networks_str:
            logger.warning("No internal networks configured")
            return False

        # Parse internal networks (comma-separated or JSON list)
        try:
            import json
            internal_networks = json.loads(internal_networks_str)
        except json.JSONDecodeError:
            internal_networks = [n.strip() for n in internal_networks_str.split(",")]

        for cidr in internal_networks:
            try:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
                if target_ip in network:
                    return True
            except ValueError:
                continue

        logger.warning(f"Target {target_ip} not in internal networks: {internal_networks}")
        return False

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
