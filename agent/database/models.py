"""
Ares Docker Agent - SQLite Database Models
"""
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool
import json

from agent.config import settings

Base = declarative_base()


class AgentConfig(Base):
    """Key-value store for agent configuration"""
    __tablename__ = "agent_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(255), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    encrypted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Common configuration keys
    PLATFORM_URL = "platform_url"
    REGISTRATION_TOKEN = "registration_token"
    AGENT_ID = "agent_id"
    AGENT_NAME = "agent_name"
    JWT_TOKEN = "jwt_token"
    TENANT_ID = "tenant_id"
    INTERNAL_NETWORKS = "internal_networks"  # JSON list of CIDR strings
    OVERLAY_IP = "overlay_ip"
    GATEWAY_PUBLIC_KEY = "gateway_public_key"
    GATEWAY_ENDPOINT = "gateway_endpoint"
    WIREGUARD_PRIVATE_KEY = "wireguard_private_key"
    WIREGUARD_PUBLIC_KEY = "wireguard_public_key"
    SETUP_COMPLETED = "setup_completed"
    INITIAL_PASSWORD = "initial_password"  # The generated initial password (for display)


class AdminUser(Base):
    """Admin user for web interface"""
    __tablename__ = "admin_user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    password_hash = Column(String(255), nullable=False)
    must_change_password = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def is_locked(self) -> bool:
        """Check if account is currently locked"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def lock_account(self, minutes: int = 30):
        """Lock the account for specified minutes"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)

    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        self.failed_attempts = 0
        self.locked_until = None


class Session(Base):
    """Active sessions for web interface"""
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True)  # UUID
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(String(500), nullable=True)

    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at


class AuditLog(Base):
    """Audit log for security events"""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    action = Column(String(100), nullable=False, index=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    success = Column(Boolean, default=True)

    # Common actions
    ACTION_LOGIN = "login"
    ACTION_LOGOUT = "logout"
    ACTION_LOGIN_FAILED = "login_failed"
    ACTION_PASSWORD_CHANGED = "password_changed"
    ACTION_SETUP_COMPLETED = "setup_completed"
    ACTION_TUNNEL_CONNECTED = "tunnel_connected"
    ACTION_TUNNEL_DISCONNECTED = "tunnel_disconnected"
    ACTION_SETTINGS_UPDATED = "settings_updated"
    ACTION_NETWORKS_UPDATED = "networks_updated"


class TunnelStatus(Base):
    """WireGuard tunnel status tracking"""
    __tablename__ = "tunnel_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    connected = Column(Boolean, default=False)
    overlay_ip = Column(String(45), nullable=True)
    last_handshake = Column(DateTime, nullable=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Database engine and session - singleton pattern
_engine = None
_SessionLocal = None


def get_engine():
    """Get or create SQLite engine (singleton)"""
    global _engine
    if _engine is None:
        settings.ensure_directories()
        _engine = create_engine(
            f"sqlite:///{settings.database_path}",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
    return _engine


def init_database():
    """Initialize database tables"""
    engine = get_engine()
    Base.metadata.create_all(engine)
    return engine


def get_session():
    """Get database session (uses singleton engine)"""
    global _SessionLocal
    if _SessionLocal is None:
        engine = get_engine()
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return _SessionLocal()


# Configuration helper functions
def get_config(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get configuration value by key.
    Automatically decrypts values that were stored with encrypted=True.
    """
    session = get_session()
    try:
        config = session.query(AgentConfig).filter(AgentConfig.key == key).first()
        if config:
            if config.encrypted and config.value:
                # Decrypt the value using the encryption module
                try:
                    from agent.security.encryption import decrypt_value
                    return decrypt_value(config.value, context=key)
                except Exception as e:
                    # If decryption fails, log and return None for security
                    import logging
                    logging.getLogger(__name__).error(f"Failed to decrypt config {key}: {e}")
                    return None
            return config.value
        return default
    finally:
        session.close()


def set_config(key: str, value: str, encrypted: bool = False):
    """
    Set configuration value.
    If encrypted=True, the value will be encrypted before storage.
    """
    session = get_session()
    try:
        # Encrypt value if requested
        store_value = value
        if encrypted and value:
            try:
                from agent.security.encryption import encrypt_value
                store_value = encrypt_value(value, context=key)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to encrypt config {key}: {e}")
                # Don't store sensitive data unencrypted - raise error
                raise ValueError(f"Failed to encrypt sensitive value for {key}") from e

        config = session.query(AgentConfig).filter(AgentConfig.key == key).first()
        if config:
            config.value = store_value
            config.encrypted = encrypted
            config.updated_at = datetime.utcnow()
        else:
            config = AgentConfig(key=key, value=store_value, encrypted=encrypted)
            session.add(config)
        session.commit()
    finally:
        session.close()


def get_config_json(key: str, default: list = None) -> list:
    """Get configuration value as JSON list"""
    value = get_config(key)
    if value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default or []
    return default or []


def set_config_json(key: str, value: list):
    """Set configuration value as JSON"""
    set_config(key, json.dumps(value))


def is_setup_completed() -> bool:
    """Check if initial setup is completed"""
    return get_config(AgentConfig.SETUP_COMPLETED) == "true"


def add_audit_log(action: str, details: str = None, ip_address: str = None, success: bool = True):
    """Add entry to audit log"""
    session = get_session()
    try:
        log = AuditLog(
            action=action,
            details=details,
            ip_address=ip_address,
            success=success
        )
        session.add(log)
        session.commit()
    finally:
        session.close()


def get_recent_audit_logs(limit: int = 50) -> list:
    """Get recent audit log entries"""
    session = get_session()
    try:
        logs = session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return logs
    finally:
        session.close()
