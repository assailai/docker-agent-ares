"""
Ares Docker Agent - Main FastAPI Application
"""
import logging
import ssl
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from agent.config import settings
from agent.database.models import init_database, is_setup_completed
from agent.security.tls import ensure_tls_cert
from agent.security.session import generate_secret_key, validate_session, get_admin_user
from agent.health.checker import get_health_status

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Background task for wake signal polling
_wake_signal_task = None


async def poll_wake_signals():
    """
    Background task that polls for wake signals from Ares.
    If a wake signal is received, refreshes the WireGuard tunnel.
    """
    import httpx
    import asyncio
    from agent.database.models import get_config, AgentConfig
    from agent.wireguard.manager import get_manager

    logger.info("🔔 Wake signal polling started")

    while True:
        try:
            await asyncio.sleep(60)  # Poll every 60 seconds

            # Check if we're registered
            gateway_url = get_config(AgentConfig.GATEWAY_URL)
            auth_token = get_config(AgentConfig.AUTH_TOKEN)

            if not gateway_url or not auth_token:
                logger.debug("Agent not registered, skipping wake signal poll")
                continue

            # Build the wake signal URL
            # Gateway URL is like "https://ares.assailai.com"
            base_url = gateway_url.rstrip('/')
            wake_url = f"{base_url}/api/v1/agent/wake-signal"

            try:
                # SECURITY: Use proper TLS verification for platform communication
                async with httpx.AsyncClient(verify=True, timeout=10.0) as client:
                    response = await client.get(
                        wake_url,
                        headers={"Authorization": f"Bearer {auth_token}"}
                    )

                    if response.status_code == 200:
                        data = response.json()
                        if data.get("wake_requested"):
                            logger.info("🔔 Received wake signal! Refreshing WireGuard tunnel...")
                            manager = get_manager()
                            result = await manager.wake_tunnel()
                            logger.info(f"🔔 Tunnel wake result: {result}")
                    elif response.status_code == 401:
                        logger.warning("Wake signal poll: auth token invalid or expired")
                    else:
                        logger.debug(f"Wake signal poll: {response.status_code}")

            except httpx.TimeoutException:
                logger.debug("Wake signal poll: timeout (server may be unavailable)")
            except httpx.ConnectError:
                logger.debug("Wake signal poll: connection failed")
            except Exception as e:
                logger.debug(f"Wake signal poll error: {e}")

        except asyncio.CancelledError:
            logger.info("Wake signal polling stopped")
            break
        except Exception as e:
            logger.error(f"Wake signal poll loop error: {e}")
            await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    global _wake_signal_task
    import asyncio

    # Startup
    logger.info("Starting Ares Docker Agent...")
    settings.ensure_directories()
    init_database()
    ensure_tls_cert()

    # Start wake signal polling in background
    _wake_signal_task = asyncio.create_task(poll_wake_signals())

    logger.info("Ares Docker Agent started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Ares Docker Agent...")

    # Stop wake signal polling
    if _wake_signal_task:
        _wake_signal_task.cancel()
        try:
            await _wake_signal_task
        except asyncio.CancelledError:
            pass

    # Stop WireGuard if running
    from agent.wireguard.manager import get_manager
    manager = get_manager()
    if manager.is_running():
        await manager.stop()
    logger.info("Shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Ares Docker Agent",
    description="Customer-deployable agent for internal API scanning",
    version=settings.agent_version,
    docs_url=None,  # Disable Swagger UI
    redoc_url=None,  # Disable ReDoc
    lifespan=lifespan
)

# Session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key or generate_secret_key(),
    max_age=settings.session_expire_hours * 3600,
    same_site="strict",
    https_only=True
)

# Mount static files
static_path = Path(__file__).parent.parent / "web" / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Templates
templates_path = Path(__file__).parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(templates_path))


# Include routers
from web.routers import auth, setup, dashboard, proxy

app.include_router(auth.router)
app.include_router(setup.router)
app.include_router(dashboard.router)
app.include_router(proxy.router)  # HTTP proxy for remote scanning


# Health check endpoint (no auth required)
@app.get("/health")
async def health_check():
    """Health check endpoint for Docker HEALTHCHECK"""
    return get_health_status()


# Root redirect
@app.get("/")
async def root(request: Request):
    """Redirect to appropriate page based on state"""
    session_id = request.session.get("session_id")

    # Check if logged in
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    # Check if setup is completed
    if not is_setup_completed():
        return RedirectResponse(url="/setup", status_code=302)

    # Check if password change is required
    admin = get_admin_user()
    if admin and admin.must_change_password:
        return RedirectResponse(url="/change-password", status_code=302)

    return RedirectResponse(url="/dashboard", status_code=302)


def run_server():
    """Run the FastAPI server with HTTPS"""
    import uvicorn

    # Ensure TLS certificate exists
    ensure_tls_cert()

    # SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=str(settings.tls_cert_path),
        keyfile=str(settings.tls_key_path)
    )
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Run server
    uvicorn.run(
        "agent.main:app",
        host=settings.host,
        port=settings.port,
        ssl_certfile=str(settings.tls_cert_path),
        ssl_keyfile=str(settings.tls_key_path),
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    run_server()
