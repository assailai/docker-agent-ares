"""
Ares Docker Agent - Setup Wizard Routes
"""
import ipaddress
from pathlib import Path
from typing import List
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from agent.database.models import (
    is_setup_completed,
    set_config,
    get_config,
    add_audit_log,
    AuditLog,
    AgentConfig
)
from agent.security.session import validate_session, get_admin_user, update_admin_password
from agent.security.password import validate_password_strength, hash_password, get_password_requirements
from agent.registration.client import register_with_platform
from agent.wireguard.keys import get_or_create_keypair
from agent.wireguard.config_gen import generate_and_write_config
from agent.wireguard.manager import get_manager

router = APIRouter(prefix="/setup")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def require_login(request: Request):
    """Dependency to require login"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return None
    return session_id


def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("", response_class=HTMLResponse)
async def setup_wizard(request: Request, step: int = 1, error: str = None):
    """Show setup wizard"""
    # Require login
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    # If setup is already completed, redirect to dashboard
    if is_setup_completed():
        return RedirectResponse(url="/dashboard", status_code=302)

    # Generate WireGuard keys (needed for display in step 2)
    _, public_key = get_or_create_keypair()

    # Get any saved values
    saved_platform_url = get_config(AgentConfig.PLATFORM_URL, "")
    saved_agent_name = get_config(AgentConfig.AGENT_NAME, "")
    saved_networks = get_config(AgentConfig.INTERNAL_NETWORKS, "")

    return templates.TemplateResponse("setup_wizard.html", {
        "request": request,
        "step": step,
        "error": error,
        "public_key": public_key,
        "saved_platform_url": saved_platform_url,
        "saved_agent_name": saved_agent_name,
        "saved_networks": saved_networks,
        "password_requirements": get_password_requirements()
    })


@router.post("/step1")
async def setup_step1(request: Request, platform_url: str = Form(...)):
    """Step 1: Platform URL"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    # Validate URL format
    if not platform_url.startswith("http://") and not platform_url.startswith("https://"):
        return RedirectResponse(url="/setup?step=1&error=Invalid+URL+format.+Must+start+with+http://+or+https://", status_code=302)

    # Save platform URL
    set_config(AgentConfig.PLATFORM_URL, platform_url.rstrip("/"))

    return RedirectResponse(url="/setup?step=2", status_code=302)


@router.post("/step2")
async def setup_step2(request: Request, registration_token: str = Form(...)):
    """Step 2: Registration Token"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    # Validate token format (should be alphanumeric, 32+ chars)
    if len(registration_token.strip()) < 16:
        return RedirectResponse(url="/setup?step=2&error=Invalid+registration+token+format", status_code=302)

    # Save token temporarily
    set_config(AgentConfig.REGISTRATION_TOKEN, registration_token.strip())

    return RedirectResponse(url="/setup?step=3", status_code=302)


@router.post("/step3")
async def setup_step3(request: Request, internal_networks: str = Form(...)):
    """Step 3: Internal Networks (CIDR notation)"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    # Parse and validate networks (support both newline and comma separation)
    networks = []
    # Split by newlines first, then by commas
    raw_networks = internal_networks.strip().replace(",", "\n").split("\n")
    for line in raw_networks:
        network = line.strip()
        if not network:
            continue

        try:
            # Validate CIDR notation
            parsed_network = ipaddress.ip_network(network, strict=False)

            # Reject single-IP CIDRs (/32 for IPv4, /128 for IPv6)
            # API hunts are designed for network blocks, not individual IPs
            # For single target scanning, use the dashboard pentest feature instead
            if parsed_network.version == 4 and parsed_network.prefixlen == 32:
                return RedirectResponse(
                    url=f"/setup?step=3&error=Single+IP+addresses+(/32)+are+not+allowed.+API+hunts+require+network+blocks+(e.g.,+/24,+/16).+For+single+targets,+use+the+dashboard+pentest+feature.",
                    status_code=302
                )
            if parsed_network.version == 6 and parsed_network.prefixlen == 128:
                return RedirectResponse(
                    url=f"/setup?step=3&error=Single+IP+addresses+(/128)+are+not+allowed.+API+hunts+require+network+blocks.+For+single+targets,+use+the+dashboard+pentest+feature.",
                    status_code=302
                )

            networks.append(network)
        except ValueError:
            return RedirectResponse(
                url=f"/setup?step=3&error=Invalid+CIDR+notation:+{network}",
                status_code=302
            )

    if not networks:
        return RedirectResponse(url="/setup?step=3&error=Please+enter+at+least+one+network", status_code=302)

    # Save networks as JSON
    import json
    set_config(AgentConfig.INTERNAL_NETWORKS, json.dumps(networks))

    return RedirectResponse(url="/setup?step=4", status_code=302)


@router.post("/step4")
async def setup_step4(request: Request, agent_name: str = Form(...)):
    """Step 4: Agent Name"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    agent_name = agent_name.strip()
    if len(agent_name) < 3:
        return RedirectResponse(url="/setup?step=4&error=Agent+name+must+be+at+least+3+characters", status_code=302)

    set_config(AgentConfig.AGENT_NAME, agent_name)

    # Check if password change is still required
    admin = get_admin_user()
    if admin and admin.must_change_password:
        return RedirectResponse(url="/setup?step=5", status_code=302)

    # Skip to step 6 (connect) if password already changed
    return RedirectResponse(url="/setup?step=6", status_code=302)


@router.post("/step5")
async def setup_step5(
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Step 5: Change Password"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    # Check passwords match
    if new_password != confirm_password:
        return RedirectResponse(url="/setup?step=5&error=Passwords+do+not+match", status_code=302)

    # Validate password strength
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        return RedirectResponse(url=f"/setup?step=5&error={error_msg.replace(' ', '+')}", status_code=302)

    # Update password - MUST check return value!
    new_hash = hash_password(new_password)
    if not update_admin_password(new_hash, must_change=False):
        # Password update failed - do NOT clear initial password
        return RedirectResponse(
            url="/setup?step=5&error=Failed+to+update+password.+Please+try+again.",
            status_code=302
        )

    # Only clear the initial password AFTER successful update
    set_config(AgentConfig.INITIAL_PASSWORD, "")

    add_audit_log(AuditLog.ACTION_PASSWORD_CHANGED, ip_address=get_client_ip(request))

    return RedirectResponse(url="/setup?step=6", status_code=302)


@router.post("/step6")
async def setup_step6(request: Request):
    """Step 6: Connect to Platform"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    client_ip = get_client_ip(request)

    # Get saved configuration
    platform_url = get_config(AgentConfig.PLATFORM_URL)
    registration_token = get_config(AgentConfig.REGISTRATION_TOKEN)
    agent_name = get_config(AgentConfig.AGENT_NAME)

    import json
    networks_json = get_config(AgentConfig.INTERNAL_NETWORKS, "[]")
    try:
        internal_networks = json.loads(networks_json)
    except json.JSONDecodeError:
        internal_networks = []

    if not all([platform_url, registration_token, internal_networks]):
        return RedirectResponse(url="/setup?step=1&error=Missing+configuration.+Please+start+again.", status_code=302)

    # Register with platform
    result = await register_with_platform(
        platform_url=platform_url,
        registration_token=registration_token,
        internal_networks=internal_networks,
        agent_name=agent_name
    )

    if not result.success:
        error_msg = result.error_message or "Registration failed"
        return RedirectResponse(url=f"/setup?step=6&error={error_msg.replace(' ', '+')}", status_code=302)

    # Generate WireGuard config
    config_path = generate_and_write_config()
    if not config_path:
        return RedirectResponse(url="/setup?step=6&error=Failed+to+generate+WireGuard+config", status_code=302)

    # Start WireGuard tunnel
    manager = get_manager()
    tunnel_started = await manager.start()

    if not tunnel_started:
        return RedirectResponse(url="/setup?step=6&error=Failed+to+start+WireGuard+tunnel", status_code=302)

    # Mark setup as completed
    set_config(AgentConfig.SETUP_COMPLETED, "true")

    # Clear the registration token (one-time use)
    set_config(AgentConfig.REGISTRATION_TOKEN, "")

    add_audit_log(
        AuditLog.ACTION_SETUP_COMPLETED,
        f"Agent registered: {result.agent_id}, Overlay IP: {result.overlay_ip}",
        client_ip
    )

    return RedirectResponse(url="/dashboard?message=Setup+completed+successfully!", status_code=302)
