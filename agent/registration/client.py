"""
Ares Docker Agent - Platform Registration Client
Registers agent with Ares platform via gRPC with TLS 1.3
"""
import grpc
import platform
import socket
import os
import ssl
import logging
from typing import Tuple, Optional, List
from dataclasses import dataclass

from agent.config import settings
from agent.database.models import get_config, set_config, set_config_json, AgentConfig
from agent.wireguard.keys import get_public_key

logger = logging.getLogger(__name__)

# TLS 1.3 minimum - no fallback to older protocols
TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_3


@dataclass
class RegistrationResult:
    """Result of agent registration"""
    success: bool
    agent_id: Optional[str] = None
    overlay_ip: Optional[str] = None
    gateway_public_key: Optional[str] = None
    gateway_endpoint: Optional[str] = None
    jwt_token: Optional[str] = None
    error_message: Optional[str] = None


def get_system_info() -> dict:
    """Gather system information for registration"""
    hostname = socket.gethostname()
    os_name = platform.system().lower()  # linux, windows, darwin
    arch = platform.machine()  # x86_64, aarch64, etc.

    # Normalize architecture
    if arch in ['x86_64', 'AMD64']:
        arch = 'amd64'
    elif arch in ['aarch64', 'arm64']:
        arch = 'arm64'

    # Get public IP (best effort)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "unknown"

    # Get resource info
    cpu_cores = os.cpu_count() or 1
    try:
        with open('/proc/meminfo', 'r') as f:
            mem_line = f.readline()
            memory_kb = int(mem_line.split()[1])
            memory_mb = memory_kb // 1024
    except Exception:
        memory_mb = 1024  # Default to 1GB

    return {
        "hostname": hostname,
        "os": os_name,
        "arch": arch,
        "ip_address": ip_address,
        "cpu_cores": cpu_cores,
        "memory_mb": memory_mb,
        "agent_version": settings.agent_version
    }


async def register_with_platform(
    platform_url: str,
    registration_token: str,
    internal_networks: List[str],
    agent_name: str = None
) -> RegistrationResult:
    """
    Register agent with Ares platform via HTTPS with TLS 1.3.

    Args:
        platform_url: Ares platform URL (e.g., "https://ares.assailai.com")
        registration_token: One-time registration token from UI
        internal_networks: List of internal networks in CIDR notation
        agent_name: Optional agent name

    Returns:
        RegistrationResult with registration outcome
    """
    try:
        # Get WireGuard public key
        wireguard_public_key = get_public_key()

        # Get system information
        system_info = get_system_info()
        if agent_name:
            system_info["hostname"] = agent_name

        logger.info(f"Registering with platform: {platform_url}")

        # Use HTTPS registration endpoint with TLS 1.3
        result = await _register_https(
            platform_url=platform_url,
            registration_token=registration_token,
            internal_networks=internal_networks,
            wireguard_public_key=wireguard_public_key,
            system_info=system_info
        )

        if result.success:
            # Store registration data
            set_config(AgentConfig.PLATFORM_URL, platform_url)
            set_config(AgentConfig.AGENT_ID, result.agent_id)
            set_config(AgentConfig.OVERLAY_IP, result.overlay_ip)
            set_config(AgentConfig.GATEWAY_PUBLIC_KEY, result.gateway_public_key)
            set_config(AgentConfig.GATEWAY_ENDPOINT, result.gateway_endpoint)
            # Store jwt_token unencrypted - it's already a cryptographically secure random token
            # Encrypting it adds complexity without security benefit and causes issues on reinstall
            # when the encryption key changes
            set_config(AgentConfig.JWT_TOKEN, result.jwt_token, encrypted=False)
            set_config_json(AgentConfig.INTERNAL_NETWORKS, internal_networks)
            if agent_name:
                set_config(AgentConfig.AGENT_NAME, agent_name)

            logger.info(f"Registration successful. Agent ID: {result.agent_id}")

        return result

    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return RegistrationResult(
            success=False,
            error_message=str(e)
        )


async def _register_https(
    platform_url: str,
    registration_token: str,
    internal_networks: List[str],
    wireguard_public_key: str,
    system_info: dict
) -> RegistrationResult:
    """
    HTTPS-based registration with TLS 1.3 minimum.
    Connects to the tunnel-gateway's /agent-gateway/register endpoint.
    Uses Let's Encrypt certificate verification for the Ares platform.
    """
    import httpx

    # Create SSL context with TLS 1.3 minimum and proper certificate verification
    # The Ares platform (ares.assailai.com) uses Let's Encrypt certificates
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = TLS_MIN_VERSION
    ssl_context.check_hostname = True  # Verify hostname matches certificate
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # Require valid certificate

    # Build registration endpoint via the agent-gateway ingress path
    registration_url = f"{platform_url.rstrip('/')}/agent-gateway/register"

    payload = {
        "registration_token": registration_token,
        "wireguard_public_key": wireguard_public_key,
        "internal_networks": internal_networks,
        "system_info": system_info
    }

    logger.info(f"Connecting to registration endpoint: {registration_url}")

    try:
        async with httpx.AsyncClient(
            verify=ssl_context,
            timeout=30.0,
            http2=True  # Use HTTP/2 for better performance
        ) as client:
            response = await client.post(registration_url, json=payload)

            if response.status_code == 200:
                data = response.json()
                return RegistrationResult(
                    success=True,
                    agent_id=data.get("agent_id"),
                    overlay_ip=data.get("overlay_ip"),
                    gateway_public_key=data.get("gateway_public_key"),
                    gateway_endpoint=data.get("gateway_endpoint"),
                    jwt_token=data.get("jwt_token")
                )
            else:
                try:
                    error_data = response.json()
                except Exception:
                    error_data = {}
                return RegistrationResult(
                    success=False,
                    error_message=error_data.get("error", f"HTTP {response.status_code}: {response.text[:200]}")
                )

    except httpx.ConnectError as e:
        return RegistrationResult(
            success=False,
            error_message=f"Cannot connect to platform: {e}"
        )
    except ssl.SSLError as e:
        return RegistrationResult(
            success=False,
            error_message=f"TLS connection failed (requires TLS 1.3): {e}"
        )
    except Exception as e:
        return RegistrationResult(
            success=False,
            error_message=f"Registration request failed: {e}"
        )


def _parse_grpc_endpoint(platform_url: str) -> str:
    """Parse platform URL to gRPC endpoint"""
    from urllib.parse import urlparse

    parsed = urlparse(platform_url)
    host = parsed.hostname or parsed.path

    # Use port 8443 for gRPC (tunnel-gateway)
    return f"{host}:8443"


def is_registered() -> bool:
    """Check if agent is registered with platform"""
    agent_id = get_config(AgentConfig.AGENT_ID)
    jwt_token = get_config(AgentConfig.JWT_TOKEN)
    return bool(agent_id and jwt_token)


def get_registration_status() -> dict:
    """Get current registration status"""
    return {
        "registered": is_registered(),
        "agent_id": get_config(AgentConfig.AGENT_ID),
        "agent_name": get_config(AgentConfig.AGENT_NAME),
        "platform_url": get_config(AgentConfig.PLATFORM_URL),
        "overlay_ip": get_config(AgentConfig.OVERLAY_IP),
        "internal_networks": get_config(AgentConfig.INTERNAL_NETWORKS),
    }


async def deregister() -> bool:
    """
    Deregister agent from platform.
    Clears all registration data.
    """
    try:
        # Clear registration data
        from agent.database.models import get_session as get_db_session, AgentConfig as AC

        db = get_db_session()
        try:
            keys_to_clear = [
                AC.AGENT_ID,
                AC.JWT_TOKEN,
                AC.OVERLAY_IP,
                AC.GATEWAY_PUBLIC_KEY,
                AC.GATEWAY_ENDPOINT,
                AC.SETUP_COMPLETED,
            ]
            for key in keys_to_clear:
                config = db.query(AC).filter(AC.key == key).first()
                if config:
                    db.delete(config)
            db.commit()
        finally:
            db.close()

        return True

    except Exception as e:
        logger.error(f"Deregistration failed: {e}")
        return False
