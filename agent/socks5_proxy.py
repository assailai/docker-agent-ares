"""
Ares Docker Agent - Secure SOCKS5 Proxy for Internal Network Access
====================================================================
This module provides a SOCKS5 proxy that allows the Ares tunnel-gateway
to route traffic through the agent to reach internal networks.

SECURITY CONTROLS:
1. Listens ONLY on the WireGuard overlay IP (10.200.x.x), NOT 0.0.0.0
2. Validates source IP is from gateway overlay network (10.200.0.0/16)
3. Only allows CONNECT to agent's configured internal_networks
4. Logs all connection attempts for audit trail

This supports multi-tenant deployments where multiple tenants may have
overlapping internal network ranges (e.g., 192.168.1.0/24).
"""

import asyncio
import ipaddress
import logging
import socket
import struct
from typing import List, Optional, Tuple

from agent.database.models import get_config, AgentConfig

logger = logging.getLogger(__name__)

# SOCKS5 Protocol Constants
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NO_AUTH = 0x00
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_GENERAL_FAIL = 0x01
SOCKS5_REP_NOT_ALLOWED = 0x02
SOCKS5_REP_NET_UNREACH = 0x03
SOCKS5_REP_HOST_UNREACH = 0x04
SOCKS5_REP_CONN_REFUSED = 0x05

SOCKS5_PROXY_PORT = 1080

# max concurrent SOCKS5 connections before rejecting new ones
MAX_SOCKS5_CONNECTIONS = 200


class SOCKS5Proxy:
    """
    Secure SOCKS5 proxy for internal network access via WireGuard overlay.
    """

    def __init__(self):
        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._active_connections = 0
        self._gateway_network = ipaddress.ip_network("10.200.0.0/16")
        self._internal_networks: List[ipaddress.IPv4Network] = []
        self._overlay_ip: Optional[str] = None

    async def start(self) -> bool:
        """
        Start the SOCKS5 proxy server.
        Returns True if successful.
        """
        if self._running:
            logger.warning("SOCKS5 proxy already running")
            return True

        # Get overlay IP from database
        self._overlay_ip = get_config(AgentConfig.OVERLAY_IP)
        if not self._overlay_ip:
            logger.error("Cannot start SOCKS5 proxy: no overlay IP configured")
            return False

        # Remove CIDR notation if present
        if "/" in self._overlay_ip:
            self._overlay_ip = self._overlay_ip.split("/")[0]

        # Get internal networks from database
        internal_networks_str = get_config(AgentConfig.INTERNAL_NETWORKS)
        if internal_networks_str:
            try:
                import json
                networks = json.loads(internal_networks_str)
                for cidr in networks:
                    try:
                        self._internal_networks.append(
                            ipaddress.ip_network(cidr, strict=False)
                        )
                    except ValueError as e:
                        logger.warning(f"Invalid internal network CIDR {cidr}: {e}")
            except json.JSONDecodeError:
                logger.warning("Failed to parse internal_networks JSON")

        if not self._internal_networks:
            logger.error("Cannot start SOCKS5 proxy: no internal networks configured")
            return False

        try:
            # SECURITY: Listen ONLY on the overlay IP, not 0.0.0.0
            self._server = await asyncio.start_server(
                self._handle_client,
                self._overlay_ip,
                SOCKS5_PROXY_PORT
            )

            self._running = True
            logger.info(f"[SOCKS5] Secure proxy listening on {self._overlay_ip}:{SOCKS5_PROXY_PORT}")
            logger.info(f"[SOCKS5] Allowed source network: {self._gateway_network}")
            logger.info(f"[SOCKS5] Allowed destinations: {[str(n) for n in self._internal_networks]}")

            # Start serving in background
            asyncio.create_task(self._serve_forever())
            return True

        except Exception as e:
            logger.error(f"Failed to start SOCKS5 proxy: {e}")
            return False

    async def _serve_forever(self):
        """Serve connections until stopped."""
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"SOCKS5 server error: {e}")

    async def stop(self):
        """Stop the SOCKS5 proxy server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("[SOCKS5] Proxy stopped")

    def is_running(self) -> bool:
        """Check if the proxy is running."""
        return self._running

    def get_active_connections(self) -> int:
        """Get the number of active connections."""
        return self._active_connections

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle a new SOCKS5 client connection."""
        if self._active_connections >= MAX_SOCKS5_CONNECTIONS:
            logger.warning(f"[SOCKS5] Connection limit reached ({MAX_SOCKS5_CONNECTIONS}), rejecting")
            writer.close()
            await writer.wait_closed()
            return

        self._active_connections += 1
        client_addr = writer.get_extra_info('peername')

        try:
            client_ip = ipaddress.ip_address(client_addr[0])
            if client_ip not in self._gateway_network:
                logger.warning(
                    f"[SOCKS5] BLOCKED: Connection from unauthorized source {client_ip} "
                    f"(not in {self._gateway_network})"
                )
                writer.close()
                await writer.wait_closed()
                return

            # SOCKS5 handshake
            if not await self._handle_handshake(reader, writer):
                return

            # Handle CONNECT request
            target_host, target_port = await self._handle_connect_request(
                reader, writer, client_ip
            )
            if not target_host:
                return

            # Connect to target
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"[SOCKS5] Timeout connecting to {target_host}:{target_port}")
                await self._send_reply(writer, SOCKS5_REP_HOST_UNREACH)
                return
            except ConnectionRefusedError:
                logger.warning(f"[SOCKS5] Connection refused to {target_host}:{target_port}")
                await self._send_reply(writer, SOCKS5_REP_CONN_REFUSED)
                return
            except OSError as e:
                logger.warning(f"[SOCKS5] Network error to {target_host}:{target_port}: {e}")
                await self._send_reply(writer, SOCKS5_REP_NET_UNREACH)
                return

            # Send success reply
            await self._send_reply(writer, SOCKS5_REP_SUCCESS)
            logger.info(f"[SOCKS5] Tunnel established: {client_ip} -> {target_host}:{target_port}")

            # Bidirectional relay
            await self._relay(reader, writer, target_reader, target_writer)

        except Exception as e:
            logger.error(f"[SOCKS5] Error handling client {client_addr}: {e}")
        finally:
            self._active_connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> bool:
        """
        Handle SOCKS5 greeting handshake.
        Returns True if successful.
        """
        try:
            # Read version and number of auth methods
            header = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            version, nmethods = struct.unpack('BB', header)

            if version != SOCKS5_VERSION:
                logger.warning(f"[SOCKS5] Unsupported SOCKS version: {version}")
                return False

            # Read auth methods
            methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10.0)

            # We only support NO_AUTH (traffic is already secured via WireGuard)
            if SOCKS5_AUTH_NO_AUTH in methods:
                writer.write(struct.pack('BB', SOCKS5_VERSION, SOCKS5_AUTH_NO_AUTH))
                await writer.drain()
                return True
            else:
                # No acceptable auth method
                writer.write(struct.pack('BB', SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE))
                await writer.drain()
                logger.warning("[SOCKS5] No acceptable auth method")
                return False

        except asyncio.TimeoutError:
            logger.warning("[SOCKS5] Handshake timeout")
            return False
        except Exception as e:
            logger.error(f"[SOCKS5] Handshake error: {e}")
            return False

    async def _handle_connect_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: ipaddress.IPv4Address
    ) -> Tuple[Optional[str], Optional[int]]:
        """
        Handle SOCKS5 CONNECT request.
        Returns (target_host, target_port) or (None, None) on error.
        """
        try:
            # Read request header: [VER, CMD, RSV, ATYP]
            header = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
            version, cmd, _, atyp = struct.unpack('BBBB', header)

            if version != SOCKS5_VERSION:
                logger.warning(f"[SOCKS5] Invalid version in request: {version}")
                return None, None

            if cmd != SOCKS5_CMD_CONNECT:
                logger.warning(f"[SOCKS5] Unsupported command: {cmd}")
                await self._send_reply(writer, SOCKS5_REP_NOT_ALLOWED)
                return None, None

            # Parse destination address
            if atyp == SOCKS5_ATYP_IPV4:
                addr_data = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
                target_host = socket.inet_ntoa(addr_data)

            elif atyp == SOCKS5_ATYP_DOMAIN:
                length = (await asyncio.wait_for(reader.readexactly(1), timeout=10.0))[0]
                domain = await asyncio.wait_for(reader.readexactly(length), timeout=10.0)
                target_host = domain.decode('utf-8')

            elif atyp == SOCKS5_ATYP_IPV6:
                addr_data = await asyncio.wait_for(reader.readexactly(16), timeout=10.0)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_data)

            else:
                logger.warning(f"[SOCKS5] Unsupported address type: {atyp}")
                await self._send_reply(writer, SOCKS5_REP_NOT_ALLOWED)
                return None, None

            # Read port
            port_data = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            target_port = struct.unpack('!H', port_data)[0]

            # resolve domain names to IPs so we validate and connect to the same address
            # (prevents DNS rebinding between validation and connection)
            try:
                target_ip = ipaddress.ip_address(target_host)
            except ValueError:
                try:
                    info = await asyncio.wait_for(
                        asyncio.get_event_loop().getaddrinfo(
                            target_host, target_port,
                            family=socket.AF_INET, type=socket.SOCK_STREAM
                        ),
                        timeout=5.0
                    )
                    if not info:
                        logger.warning(f"[SOCKS5] Failed to resolve {target_host}")
                        await self._send_reply(writer, SOCKS5_REP_HOST_UNREACH)
                        return None, None
                    resolved_ip = info[0][4][0]
                    target_ip = ipaddress.ip_address(resolved_ip)
                    # pin to resolved IP for the actual connection
                    target_host = resolved_ip
                except Exception as e:
                    logger.warning(f"[SOCKS5] DNS resolution failed for {target_host}: {e}")
                    await self._send_reply(writer, SOCKS5_REP_HOST_UNREACH)
                    return None, None

            if not any(target_ip in network for network in self._internal_networks):
                logger.warning(
                    f"[SOCKS5] BLOCKED: Destination {target_host}:{target_port} "
                    f"not in allowed networks (from {source_ip})"
                )
                await self._send_reply(writer, SOCKS5_REP_NOT_ALLOWED)
                return None, None

            logger.info(f"[SOCKS5] ALLOWED: {source_ip} -> {target_host}:{target_port}")
            return target_host, target_port

        except asyncio.TimeoutError:
            logger.warning("[SOCKS5] Connect request timeout")
            return None, None
        except Exception as e:
            logger.error(f"[SOCKS5] Connect request error: {e}")
            return None, None

    async def _send_reply(self, writer: asyncio.StreamWriter, reply_code: int):
        """Send SOCKS5 CONNECT reply."""
        # Reply: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
        reply = struct.pack(
            '!BBBB',
            SOCKS5_VERSION,
            reply_code,
            0x00,  # RSV
            SOCKS5_ATYP_IPV4
        )
        reply += struct.pack('!IH', 0, 0)  # BND.ADDR=0.0.0.0, BND.PORT=0
        writer.write(reply)
        await writer.drain()

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter
    ):
        """Bidirectional relay between client and target."""

        async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter, name: str):
            try:
                while True:
                    data = await src.read(32 * 1024)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception as e:
                logger.debug(f"[SOCKS5] {name} relay ended: {e}")

        try:
            task1 = asyncio.create_task(forward(client_reader, target_writer, "client->target"))
            task2 = asyncio.create_task(forward(target_reader, client_writer, "target->client"))

            done, pending = await asyncio.wait(
                [task1, task2],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        except Exception as e:
            logger.error(f"[SOCKS5] Relay error: {e}")
        finally:
            target_writer.close()
            try:
                await target_writer.wait_closed()
            except Exception:
                pass


# Global instance
_proxy: Optional[SOCKS5Proxy] = None


def get_proxy() -> SOCKS5Proxy:
    """Get the global SOCKS5 proxy instance."""
    global _proxy
    if _proxy is None:
        _proxy = SOCKS5Proxy()
    return _proxy
