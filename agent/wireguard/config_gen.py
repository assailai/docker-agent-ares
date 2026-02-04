"""
Ares Docker Agent - WireGuard Configuration Generator
"""
import ipaddress
import logging
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from agent.config import settings
from agent.database.models import get_config, AgentConfig

logger = logging.getLogger(__name__)

# Known NLB DNS endpoint for Ares WireGuard tunnel
ARES_WIREGUARD_NLB_DNS = "ares-production-nlb-802c652b4a422d55.elb.us-east-1.amazonaws.com"
ARES_WIREGUARD_PORT = 51820


def _is_ip_address(host: str) -> bool:
    """Check if a string is an IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_gateway_endpoint(endpoint: str, platform_url: str = None) -> str:
    """
    Normalize gateway endpoint to prefer DNS names over IP addresses.

    NLB IPs can change, causing WireGuard tunnels to break. This function
    ensures we use DNS names which will resolve to current IPs.

    Args:
        endpoint: The gateway endpoint (e.g., "1.2.3.4:51820" or "tunnel.example.com:51820")
        platform_url: The platform URL for deriving fallback DNS (e.g., "https://ares.assailai.com")

    Returns:
        Normalized endpoint with DNS name if possible
    """
    if not endpoint:
        return endpoint

    # Parse endpoint into host and port
    if ':' in endpoint:
        # Could be IPv6 or host:port
        if endpoint.count(':') == 1:
            # Simple host:port format
            host, port = endpoint.rsplit(':', 1)
        elif endpoint.startswith('['):
            # IPv6 with port: [::1]:51820
            bracket_end = endpoint.rfind(']')
            if bracket_end != -1 and bracket_end + 1 < len(endpoint) and endpoint[bracket_end + 1] == ':':
                host = endpoint[1:bracket_end]
                port = endpoint[bracket_end + 2:]
            else:
                return endpoint  # Can't parse, return as-is
        else:
            # Bare IPv6 without port - unlikely for our use case
            return endpoint
    else:
        # No port specified
        host = endpoint
        port = str(ARES_WIREGUARD_PORT)

    # Check if host is an IP address
    if _is_ip_address(host):
        # IP address detected - convert to DNS
        logger.warning(
            f"Gateway endpoint uses IP address ({host}), converting to DNS name. "
            f"IPs can change; DNS names are more reliable."
        )

        # Use the known Ares NLB DNS endpoint
        # In the future, this could be derived from platform_url or a config
        new_endpoint = f"{ARES_WIREGUARD_NLB_DNS}:{port}"
        logger.info(f"Converted endpoint: {endpoint} -> {new_endpoint}")
        return new_endpoint

    # Already using DNS name, return as-is
    return endpoint


def generate_wg_config(
    private_key: str,
    overlay_ip: str,
    gateway_public_key: str,
    gateway_endpoint: str,
    allowed_ips: List[str] = None
) -> str:
    """
    Generate WireGuard configuration file content for use with `wg setconf`.

    Note: This generates a config for `wg setconf`, NOT `wg-quick`.
    The Address is NOT included here as it's not supported by `wg setconf`.
    IP address is assigned separately using `ip addr add`.

    Args:
        private_key: Agent's WireGuard private key (base64)
        overlay_ip: Agent's overlay IP (e.g., "10.200.1.50") - stored but not in config
        gateway_public_key: Gateway's WireGuard public key (base64)
        gateway_endpoint: Gateway's endpoint (e.g., "agents.ares.com:51820")
        allowed_ips: List of allowed IPs/networks (default: ["10.200.0.0/16"])

    Returns:
        WireGuard configuration file content
    """
    if allowed_ips is None:
        allowed_ips = ["10.200.0.0/16"]

    # Normalize endpoint to use DNS name instead of IP (NLB IPs can change)
    normalized_endpoint = _normalize_gateway_endpoint(gateway_endpoint)

    # Note: Address is NOT included - it's a wg-quick extension, not supported by `wg setconf`
    # The manager.py handles IP assignment using `ip addr add`
    config = f"""# Ares Docker Agent WireGuard Configuration
# Generated automatically - do not edit manually
# Note: IP address ({overlay_ip}) is assigned separately via `ip addr add`

[Interface]
PrivateKey = {private_key}

[Peer]
PublicKey = {gateway_public_key}
Endpoint = {normalized_endpoint}
AllowedIPs = {', '.join(allowed_ips)}
PersistentKeepalive = 25
"""
    return config


def write_wg_config(config_content: str, config_path: Path = None) -> Path:
    """
    Write WireGuard configuration to file.

    Args:
        config_content: WireGuard configuration content
        config_path: Path to write config (default: from settings)

    Returns:
        Path to written config file
    """
    config_path = config_path or settings.wireguard_config_path

    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Write config with restrictive permissions
    with open(config_path, 'w') as f:
        f.write(config_content)

    # Set permissions (600 - owner read/write only)
    import os
    os.chmod(config_path, 0o600)

    return config_path


def generate_and_write_config() -> Optional[Path]:
    """
    Generate and write WireGuard config from stored registration data.

    Returns:
        Path to config file, or None if required data is missing
    """
    # Get required values from database
    private_key = get_config(AgentConfig.WIREGUARD_PRIVATE_KEY)
    overlay_ip = get_config(AgentConfig.OVERLAY_IP)
    gateway_public_key = get_config(AgentConfig.GATEWAY_PUBLIC_KEY)
    gateway_endpoint = get_config(AgentConfig.GATEWAY_ENDPOINT)

    if not all([private_key, overlay_ip, gateway_public_key, gateway_endpoint]):
        return None

    # Generate config
    config_content = generate_wg_config(
        private_key=private_key,
        overlay_ip=overlay_ip,
        gateway_public_key=gateway_public_key,
        gateway_endpoint=gateway_endpoint
    )

    # Write config
    return write_wg_config(config_content)


def get_config_path() -> Path:
    """Get the WireGuard config file path"""
    return settings.wireguard_config_path


def config_exists() -> bool:
    """Check if WireGuard config file exists"""
    return settings.wireguard_config_path.exists()
