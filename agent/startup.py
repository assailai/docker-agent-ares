"""
Ares Docker Agent - Startup Script
Generates initial password and prints startup banner
"""
import os
import socket
import sys

from agent.config import settings
from agent.database.models import init_database, get_config, set_config, AgentConfig
from agent.security.password import generate_password, hash_password
from agent.security.session import create_admin_user, get_admin_user
from agent.security.tls import ensure_tls_cert


def get_container_ip() -> str:
    """Get the container's IP address"""
    try:
        # Connect to an external address to determine our IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback to hostname resolution
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception:
            return "localhost"


def get_host_ip() -> str | None:
    """
    Try to detect the Docker host's IP address.
    Returns None if unable to detect.
    """
    # Method 1: Check for explicit HOST_IP environment variable
    host_ip = os.environ.get('HOST_IP')
    if host_ip:
        return host_ip

    # Method 2: Try host.docker.internal (works on Docker Desktop for Mac/Windows)
    try:
        ip = socket.gethostbyname('host.docker.internal')
        if ip:
            return ip
    except socket.gaierror:
        pass

    # Method 3: Read the default gateway from /proc/net/route (Linux)
    # On Docker bridge networks, the gateway is typically the host
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == '00000000':  # Default route
                    gateway_hex = fields[2]
                    # Convert hex to IP (stored in little-endian)
                    gateway_ip = '.'.join([
                        str(int(gateway_hex[i:i+2], 16))
                        for i in range(6, -1, -2)
                    ])
                    # Validate it's not 0.0.0.0
                    if gateway_ip != '0.0.0.0':
                        return gateway_ip
    except Exception:
        pass

    return None


def initialize_agent():
    """Initialize agent on first run"""
    # Ensure directories exist
    settings.ensure_directories()

    # Initialize database
    init_database()

    # Generate TLS certificate if needed
    ensure_tls_cert()

    # Check if admin user exists
    admin = get_admin_user()

    if admin is None:
        # First run - generate initial password
        initial_password = generate_password(16)
        password_hash = hash_password(initial_password)

        # Create admin user
        create_admin_user(password_hash, must_change_password=True)

        # Store initial password for display (will be cleared after first login)
        # SECURITY: Store encrypted - will be auto-decrypted when retrieved
        set_config(AgentConfig.INITIAL_PASSWORD, initial_password, encrypted=True)

        return initial_password

    else:
        # Existing admin - get stored initial password if still set
        # Returns empty string if password was changed (cleared from config)
        initial_pwd = get_config(AgentConfig.INITIAL_PASSWORD, "")
        return initial_pwd if initial_pwd else None


def print_startup_banner(container_ip: str, host_ip: str | None, port: int, initial_password: str = None):
    """Print the startup banner with connection information"""

    # Determine the best IP to display
    display_ip = host_ip if host_ip else container_ip

    banner = f"""
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                    ║
║   █████╗ ██████╗ ███████╗███████╗     █████╗  ██████╗ ███████╗███╗   ██╗████████╗  ║
║  ██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝  ║
║  ███████║██████╔╝█████╗  ███████╗    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║     ║
║  ██╔══██║██╔══██╗██╔══╝  ╚════██║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║     ║
║  ██║  ██║██║  ██║███████╗███████║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║     ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝     ║
║                                                                                    ║
║                         DOCKER AGENT v{settings.agent_version:<29}              ║
║                                                                                    ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                    ║
║  Web Interface:  https://{display_ip}:{port:<47}  ║
║                                                                                    ║
║  NOTE: If accessing from another machine, use the host's physical IP address      ║
║        (e.g., run 'ip addr' or 'hostname -I' on the host to find it)              ║
║                                                                                    ║"""

    if initial_password:
        banner += f"""
╠════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                    ║
║  Initial Password:  {initial_password:<30}                              ║
║                                                                                    ║
║  NOTE: You MUST change this password on first login.                               ║
║                                                                                    ║"""

    banner += """
╠════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                    ║
║  Getting Started:                                                                  ║
║  1. Open the web interface in your browser                                         ║
║  2. Login with the initial password                                                ║
║  3. Complete the setup wizard to connect to Ares                                   ║
║                                                                                    ║
╚════════════════════════════════════════════════════════════════════════════════════╝
"""

    print(banner, flush=True)


def main():
    """Main startup function"""
    print("Initializing Ares Docker Agent...", flush=True)

    # Initialize and get initial password
    initial_password = initialize_agent()

    # Get container IP and host IP
    container_ip = get_container_ip()
    host_ip = get_host_ip()

    # Print startup banner
    print_startup_banner(container_ip, host_ip, settings.port, initial_password)

    # Return success
    return 0


if __name__ == "__main__":
    sys.exit(main())
