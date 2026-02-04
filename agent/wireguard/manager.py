"""
Ares Docker Agent - WireGuard Process Manager
Manages wireguard-go userspace implementation
"""
import asyncio
import subprocess
import os
import re
import stat
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

from agent.config import settings
from agent.database.models import (
    get_session as get_db_session,
    TunnelStatus,
    add_audit_log,
    AuditLog
)
from agent.wireguard.config_gen import generate_and_write_config, config_exists

logger = logging.getLogger(__name__)

# Constants for retry logic
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 5]  # Exponential backoff in seconds


class WireGuardManager:
    """Manager for WireGuard tunnel using wireguard-go"""

    def __init__(self):
        self.interface = settings.wireguard_interface
        self.config_path = settings.wireguard_config_path
        self._process: Optional[subprocess.Popen] = None
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False

    def _check_tun_device(self) -> Tuple[bool, str]:
        """
        Check if /dev/net/tun exists and is accessible.
        Returns (success, error_message).
        """
        tun_path = "/dev/net/tun"

        # Check if device exists
        if not os.path.exists(tun_path):
            return False, (
                f"TUN device {tun_path} not found. "
                "Run container with: --device /dev/net/tun:/dev/net/tun"
            )

        # Check if it's a character device
        try:
            mode = os.stat(tun_path).st_mode
            if not stat.S_ISCHR(mode):
                return False, f"{tun_path} exists but is not a character device"
        except OSError as e:
            return False, f"Cannot stat {tun_path}: {e}"

        # Check read/write access
        if not os.access(tun_path, os.R_OK | os.W_OK):
            return False, (
                f"Cannot read/write {tun_path}. "
                "Ensure container runs as root or with --privileged flag"
            )

        return True, ""

    def _check_root_permissions(self) -> Tuple[bool, str]:
        """
        Check if running with sufficient permissions for WireGuard.
        Returns (success, error_message).
        """
        if os.geteuid() != 0:
            return False, (
                "WireGuard requires root permissions. "
                "Run container with: --user root -e ARES_RUN_AS_ROOT=true"
            )
        return True, ""

    def _check_net_admin_capability(self) -> Tuple[bool, str]:
        """
        Check if NET_ADMIN capability is available.
        Returns (success, error_message).
        """
        # Try to create a dummy interface to test NET_ADMIN
        result = subprocess.run(
            ["ip", "link", "add", "ares_test", "type", "dummy"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            # Cleanup test interface
            subprocess.run(
                ["ip", "link", "del", "ares_test"],
                capture_output=True
            )
            return True, ""

        if "Operation not permitted" in result.stderr:
            return False, (
                "NET_ADMIN capability not available. "
                "Run container with: --cap-add=NET_ADMIN"
            )

        # Some other error, but might still work
        return True, ""

    def _check_wireguard_go_binary(self) -> Tuple[bool, str]:
        """
        Check if wireguard-go binary is available and executable.
        Returns (success, error_message).
        """
        result = subprocess.run(
            ["which", "wireguard-go"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return False, "wireguard-go binary not found in PATH"

        wg_path = result.stdout.strip()
        if not os.access(wg_path, os.X_OK):
            return False, f"wireguard-go at {wg_path} is not executable"

        return True, ""

    def run_preflight_checks(self) -> Tuple[bool, List[str]]:
        """
        Run all pre-flight checks before starting WireGuard.
        Returns (all_passed, list_of_errors).
        """
        errors = []

        # Check wireguard-go binary
        ok, err = self._check_wireguard_go_binary()
        if not ok:
            errors.append(err)

        # Check root permissions
        ok, err = self._check_root_permissions()
        if not ok:
            errors.append(err)

        # Check TUN device
        ok, err = self._check_tun_device()
        if not ok:
            errors.append(err)

        # Check NET_ADMIN capability (only if root)
        if os.geteuid() == 0:
            ok, err = self._check_net_admin_capability()
            if not ok:
                errors.append(err)

        if errors:
            logger.error("WireGuard pre-flight checks failed:")
            for i, error in enumerate(errors, 1):
                logger.error(f"  {i}. {error}")

            # Log the recommended docker run command
            logger.error("")
            logger.error("Recommended docker run command:")
            logger.error("  docker run -d --name ares-agent \\")
            logger.error("    --user root \\")
            logger.error("    --cap-add=NET_ADMIN \\")
            logger.error("    --device /dev/net/tun:/dev/net/tun \\")
            logger.error("    -e ARES_RUN_AS_ROOT=true \\")
            logger.error("    -p 8443:8443 \\")
            logger.error("    -v ares-agent-data:/data \\")
            logger.error("    --restart unless-stopped \\")
            logger.error("    assailai/ares-agent:latest")

        return len(errors) == 0, errors

    async def _start_wireguard_go_with_retry(self) -> Tuple[bool, str]:
        """
        Start wireguard-go with retry logic and detailed error capture.
        Returns (success, error_message).
        """
        for attempt in range(MAX_RETRIES):
            if attempt > 0:
                delay = RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                logger.info(f"Retry attempt {attempt + 1}/{MAX_RETRIES} after {delay}s delay...")
                await asyncio.sleep(delay)

            # Create environment with flags
            wg_env = os.environ.copy()
            wg_env["WG_PROCESS_FOREGROUND"] = "1"

            logger.info(f"Starting wireguard-go (attempt {attempt + 1}/{MAX_RETRIES})")

            try:
                self._process = subprocess.Popen(
                    ["wireguard-go", "-f", self.interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=wg_env
                )
            except FileNotFoundError:
                return False, "wireguard-go binary not found"
            except PermissionError:
                return False, "Permission denied executing wireguard-go"
            except Exception as e:
                return False, f"Failed to spawn wireguard-go: {e}"

            # Wait for interface to come up (with progressive checks)
            for i in range(20):  # Up to 2 seconds
                await asyncio.sleep(0.1)

                # Check if process exited
                exit_code = self._process.poll()
                if exit_code is not None:
                    # Process exited - capture stderr
                    stderr = ""
                    if self._process.stderr:
                        try:
                            stderr = self._process.stderr.read().decode().strip()
                        except Exception:
                            pass

                    error_msg = self._diagnose_wireguard_failure(exit_code, stderr)
                    logger.warning(f"wireguard-go exited with code {exit_code}: {error_msg}")
                    break

                # Check if interface was created
                if self._interface_exists(self.interface):
                    logger.info(f"WireGuard interface {self.interface} created successfully")
                    return True, ""
            else:
                # Loop completed without break - process running but no interface
                # Give it one more second
                await asyncio.sleep(1)
                if self._interface_exists(self.interface):
                    logger.info(f"WireGuard interface {self.interface} created successfully")
                    return True, ""

                # Process running but no interface - this is unusual
                if self._process.poll() is None:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self._process.kill()

                stderr = ""
                if self._process.stderr:
                    try:
                        stderr = self._process.stderr.read().decode().strip()
                    except Exception:
                        pass

                error_msg = f"wireguard-go running but interface not created. Stderr: {stderr or '(empty)'}"
                logger.warning(error_msg)

        # All retries exhausted
        return False, f"Failed after {MAX_RETRIES} attempts. Last error: {error_msg if 'error_msg' in locals() else 'unknown'}"

    def _diagnose_wireguard_failure(self, exit_code: int, stderr: str) -> str:
        """
        Provide a human-readable diagnosis for wireguard-go failure.
        """
        stderr_lower = stderr.lower() if stderr else ""

        # Check for common failure patterns
        if "permission denied" in stderr_lower or "operation not permitted" in stderr_lower:
            return (
                "Permission denied. Ensure container has: "
                "--user root --cap-add=NET_ADMIN --device /dev/net/tun"
            )

        if "no such file or directory" in stderr_lower and "tun" in stderr_lower:
            return "TUN device not available. Run with: --device /dev/net/tun:/dev/net/tun"

        if "address already in use" in stderr_lower:
            return "WireGuard interface already exists. Try removing stale interface first."

        if "busy" in stderr_lower or "device or resource busy" in stderr_lower:
            return "Device busy. A previous wireguard-go process may still be running."

        # If stderr is empty, provide common causes
        if not stderr:
            if exit_code == 1:
                return (
                    "wireguard-go exited silently (code 1). Common causes: "
                    "1) /dev/net/tun not accessible, "
                    "2) Not running as root, "
                    "3) Missing NET_ADMIN capability"
                )
            return f"wireguard-go exited with code {exit_code} (no error output)"

        return stderr

    def _interface_exists(self, name: str) -> bool:
        """Check if a network interface exists."""
        result = subprocess.run(
            ["ip", "link", "show", "dev", name],
            capture_output=True
        )
        return result.returncode == 0

    async def start(self) -> bool:
        """
        Start the WireGuard tunnel.
        Returns True if successful.
        """
        if self._running:
            logger.warning("WireGuard tunnel already running")
            return True

        # Ensure config exists
        if not config_exists():
            config_path = generate_and_write_config()
            if not config_path:
                logger.error("Cannot start WireGuard: configuration not available")
                self._update_status(connected=False, error="Configuration not available")
                return False

        try:
            # Create WireGuard interface - prefer kernel module over wireguard-go
            logger.info(f"Starting WireGuard interface: {self.interface}")

            # First, try to remove any existing interface
            subprocess.run(
                ["ip", "link", "del", "dev", self.interface],
                capture_output=True,
                check=False
            )

            # Try native kernel module first (ip link add type wireguard)
            result = subprocess.run(
                ["ip", "link", "add", "dev", self.interface, "type", "wireguard"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                # Kernel module not available, fall back to wireguard-go
                logger.info(f"Kernel WireGuard not available (error: {result.stderr.strip()}), trying wireguard-go")

                # Run pre-flight checks before attempting wireguard-go
                preflight_ok, preflight_errors = self.run_preflight_checks()
                if not preflight_ok:
                    error_summary = "; ".join(preflight_errors)
                    self._update_status(connected=False, error=f"Pre-flight failed: {error_summary}")
                    return False

                # Start wireguard-go with retry logic
                success, error_msg = await self._start_wireguard_go_with_retry()
                if not success:
                    logger.error(f"Failed to start wireguard-go: {error_msg}")
                    self._update_status(connected=False, error=error_msg)
                    return False
            else:
                logger.info("Using native kernel WireGuard module")
                self._process = None  # No process for kernel module

            # Apply configuration using wg setconf
            result = subprocess.run(
                ["wg", "setconf", self.interface, str(self.config_path)],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Failed to apply WireGuard config: {result.stderr}")
                await self.stop()
                self._update_status(connected=False, error=f"Config error: {result.stderr}")
                return False

            # Bring interface up
            result = subprocess.run(
                ["ip", "link", "set", "up", "dev", self.interface],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Failed to bring up interface: {result.stderr}")
                await self.stop()
                self._update_status(connected=False, error=f"Interface error: {result.stderr}")
                return False

            # Get overlay IP from config and add to interface
            overlay_ip = self._get_overlay_ip_from_config()
            if overlay_ip:
                result = subprocess.run(
                    ["ip", "addr", "add", overlay_ip, "dev", self.interface],
                    capture_output=True,
                    text=True
                )
                # Ignore error if address already exists

            self._running = True
            self._update_status(connected=True)
            add_audit_log(AuditLog.ACTION_TUNNEL_CONNECTED, f"Interface: {self.interface}")

            # Start monitoring task
            self._monitor_task = asyncio.create_task(self._monitor_loop())

            logger.info("WireGuard tunnel started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start WireGuard: {e}")
            self._update_status(connected=False, error=str(e))
            return False

    async def stop(self) -> bool:
        """Stop the WireGuard tunnel"""
        self._running = False

        # Cancel monitor task
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        # Terminate wireguard-go process
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

        # Remove interface
        try:
            subprocess.run(
                ["ip", "link", "del", "dev", self.interface],
                capture_output=True,
                check=False
            )
        except Exception as e:
            logger.warning(f"Failed to remove interface: {e}")

        self._update_status(connected=False)
        add_audit_log(AuditLog.ACTION_TUNNEL_DISCONNECTED, f"Interface: {self.interface}")

        logger.info("WireGuard tunnel stopped")
        return True

    async def restart(self) -> bool:
        """Restart the WireGuard tunnel"""
        await self.stop()
        await asyncio.sleep(1)
        return await self.start()

    async def wake_tunnel(self) -> Dict[str, Any]:
        """
        Wake up the tunnel by sending traffic to the gateway.
        This is useful before hunt operations to ensure the tunnel is active.
        Returns status dict with success and details.
        """
        result = {
            "success": False,
            "tunnel_running": self.is_running(),
            "ping_successful": False,
            "handshake_active": False,
            "message": ""
        }

        if not self.is_running():
            # Try to start the tunnel
            logger.info("Tunnel not running, attempting to start...")
            started = await self.start()
            if not started:
                result["message"] = "Failed to start tunnel"
                return result
            result["tunnel_running"] = True
            # Wait a moment for interface to be ready
            await asyncio.sleep(2)

        # Send multiple pings to ensure handshake is established
        ping_success = False
        for attempt in range(3):
            if await self._ping_gateway():
                ping_success = True
                break
            await asyncio.sleep(1)

        result["ping_successful"] = ping_success

        # Check tunnel status after pinging
        status = self.get_status()
        result["handshake_active"] = status.get("last_handshake") not in [None, "none"]

        if ping_success:
            result["success"] = True
            result["message"] = "Tunnel is active and gateway is reachable"
        else:
            result["message"] = "Tunnel is up but gateway ping failed"

        return result

    def is_running(self) -> bool:
        """Check if tunnel is currently running"""
        if not self._running:
            return False
        # For kernel module, check if interface exists
        if self._process is None:
            result = subprocess.run(
                ["ip", "link", "show", "dev", self.interface],
                capture_output=True
            )
            return result.returncode == 0
        # For wireguard-go, check if process is alive
        return self._process.poll() is None

    def get_status(self) -> Dict[str, Any]:
        """Get current tunnel status"""
        status = {
            "connected": False,
            "overlay_ip": None,
            "last_handshake": None,
            "bytes_sent": 0,
            "bytes_received": 0,
            "error": None
        }

        if not self.is_running():
            return status

        try:
            # Parse wg show output
            result = subprocess.run(
                ["wg", "show", self.interface],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                output = result.stdout
                status["connected"] = True

                # Parse last handshake
                handshake_match = re.search(r'latest handshake: (.+)', output)
                if handshake_match:
                    status["last_handshake"] = handshake_match.group(1)

                # Parse transfer stats
                transfer_match = re.search(r'transfer: ([\d.]+\s+\w+) received, ([\d.]+\s+\w+) sent', output)
                if transfer_match:
                    status["bytes_received"] = self._parse_bytes(transfer_match.group(1))
                    status["bytes_sent"] = self._parse_bytes(transfer_match.group(2))

            # Get overlay IP
            result = subprocess.run(
                ["ip", "-o", "addr", "show", "dev", self.interface],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    status["overlay_ip"] = ip_match.group(1)

        except Exception as e:
            logger.error(f"Failed to get tunnel status: {e}")
            status["error"] = str(e)

        return status

    async def _ping_gateway(self) -> bool:
        """
        Ping the gateway overlay IP to keep the WireGuard tunnel warm.
        This ensures NAT mappings stay active and triggers handshakes.
        Returns True if ping succeeds.
        """
        gateway_ip = "10.200.0.1"  # Gateway's overlay IP
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "5", gateway_ip],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.debug(f"Gateway ping successful ({gateway_ip})")
                return True
            else:
                logger.warning(f"Gateway ping failed ({gateway_ip}): no response")
                return False
        except subprocess.TimeoutExpired:
            logger.warning(f"Gateway ping timed out ({gateway_ip})")
            return False
        except Exception as e:
            logger.warning(f"Gateway ping error: {e}")
            return False

    async def _monitor_loop(self):
        """Background task to monitor tunnel health and auto-recover"""
        consecutive_failures = 0
        max_auto_recovery_attempts = 3
        auto_recovery_cooldown = 60  # seconds between recovery attempts
        ping_interval = 30  # Ping gateway every 30 seconds to keep tunnel warm
        last_ping_time = 0

        while self._running:
            try:
                status = self.get_status()
                self._update_status(
                    connected=status["connected"],
                    overlay_ip=status.get("overlay_ip"),
                    bytes_sent=status.get("bytes_sent", 0),
                    bytes_received=status.get("bytes_received", 0),
                    error=status.get("error")
                )

                # Proactively ping gateway to keep tunnel warm
                import time
                current_time = time.time()
                if status["connected"] and (current_time - last_ping_time) >= ping_interval:
                    asyncio.create_task(self._ping_gateway())
                    last_ping_time = current_time

                # Check tunnel health
                if status["connected"]:
                    # Tunnel is healthy, reset failure counter
                    consecutive_failures = 0

                    # Parse and store last handshake
                    if status.get("last_handshake") and status["last_handshake"] != "none":
                        # Handshake exists, tunnel is fully healthy
                        pass
                else:
                    # Tunnel is down - attempt auto-recovery
                    consecutive_failures += 1

                    if consecutive_failures <= max_auto_recovery_attempts:
                        logger.warning(
                            f"Tunnel appears down (attempt {consecutive_failures}/{max_auto_recovery_attempts}). "
                            f"Attempting auto-recovery..."
                        )

                        # Wait before attempting recovery
                        await asyncio.sleep(auto_recovery_cooldown)

                        if not self._running:
                            break

                        # Attempt to restart
                        try:
                            success = await self.restart()
                            if success:
                                logger.info("Auto-recovery successful - tunnel restored")
                                consecutive_failures = 0
                            else:
                                logger.error(f"Auto-recovery failed (attempt {consecutive_failures})")
                        except Exception as recover_err:
                            logger.error(f"Auto-recovery error: {recover_err}")
                    else:
                        logger.error(
                            f"Auto-recovery exhausted ({max_auto_recovery_attempts} attempts). "
                            f"Manual intervention required. Check container permissions."
                        )
                        # Log the recommended docker run command
                        logger.error("To fix, restart container with correct permissions:")
                        logger.error(
                            "  docker run --user root --cap-add=NET_ADMIN "
                            "--device /dev/net/tun -e ARES_RUN_AS_ROOT=true ..."
                        )

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

            await asyncio.sleep(30)  # Check every 30 seconds

    def _update_status(
        self,
        connected: bool,
        overlay_ip: str = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        error: str = None
    ):
        """Update tunnel status in database"""
        db = get_db_session()
        try:
            status = db.query(TunnelStatus).first()
            if not status:
                status = TunnelStatus()
                db.add(status)

            status.connected = connected
            if overlay_ip:
                status.overlay_ip = overlay_ip
            status.bytes_sent = bytes_sent
            status.bytes_received = bytes_received
            status.error_message = error
            status.updated_at = datetime.utcnow()

            if connected:
                status.last_handshake = datetime.utcnow()

            db.commit()
        finally:
            db.close()

    def _get_overlay_ip_from_config(self) -> Optional[str]:
        """Get overlay IP from database (not config file since wg setconf doesn't support Address)"""
        from agent.database.models import get_config, AgentConfig
        try:
            overlay_ip = get_config(AgentConfig.OVERLAY_IP)
            if overlay_ip:
                # Ensure it has CIDR notation
                if "/" not in overlay_ip:
                    overlay_ip = f"{overlay_ip}/16"
                return overlay_ip
        except Exception:
            pass
        return None

    def _parse_bytes(self, size_str: str) -> int:
        """Parse byte size string (e.g., '1.5 MiB') to bytes"""
        try:
            parts = size_str.strip().split()
            if len(parts) != 2:
                return 0

            value = float(parts[0])
            unit = parts[1].upper()

            multipliers = {
                'B': 1,
                'KIB': 1024,
                'MIB': 1024**2,
                'GIB': 1024**3,
                'TIB': 1024**4,
                'KB': 1000,
                'MB': 1000**2,
                'GB': 1000**3,
                'TB': 1000**4,
            }

            return int(value * multipliers.get(unit, 1))
        except Exception:
            return 0


# Global instance
_manager: Optional[WireGuardManager] = None


def get_manager() -> WireGuardManager:
    """Get the global WireGuard manager instance"""
    global _manager
    if _manager is None:
        _manager = WireGuardManager()
    return _manager
