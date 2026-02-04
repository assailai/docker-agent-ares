"""
Ares Docker Agent - Configuration Management
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Data directory for persistence
    data_dir: Path = Field(default=Path("/data"))

    # TLS configuration
    tls_cert_path: Path = Field(default=Path("/data/tls/server.crt"))
    tls_key_path: Path = Field(default=Path("/data/tls/server.key"))

    # Server configuration
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8443)

    # Logging
    log_level: str = Field(default="INFO")

    # Session configuration
    session_secret_key: str = Field(default="")  # Generated on first run
    session_expire_hours: int = Field(default=24)

    # Security
    max_login_attempts: int = Field(default=5)
    lockout_minutes: int = Field(default=30)
    min_password_length: int = Field(default=12)

    # WireGuard
    wireguard_interface: str = Field(default="wg0")
    wireguard_config_path: Path = Field(default=Path("/data/wireguard/wg0.conf"))

    # Agent information
    agent_version: str = Field(default="2.2.1")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @property
    def database_path(self) -> Path:
        """Path to SQLite database"""
        return self.data_dir / "agent.db"

    @property
    def tls_dir(self) -> Path:
        """Directory for TLS certificates"""
        return self.data_dir / "tls"

    @property
    def wireguard_dir(self) -> Path:
        """Directory for WireGuard configuration"""
        return self.data_dir / "wireguard"

    def ensure_directories(self):
        """Create required directories if they don't exist"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tls_dir.mkdir(parents=True, exist_ok=True)
        self.wireguard_dir.mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings()
