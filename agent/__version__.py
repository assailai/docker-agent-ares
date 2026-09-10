"""Single source of truth for the Ares Docker Agent version.

Consumed by agent.config.Settings.agent_version, which reports it to the platform
at registration and in every heartbeat. Bump this on a release; the companion
updater then rolls deployments to the version the server marks current.
"""

__version__ = "3.9.1"
