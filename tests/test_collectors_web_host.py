"""The web (nginx) host collector reads client-facing TLS enforcement and admin-route public exposure
from the server's own config, over the same SSH transport as the other host families. It ABSTAINS on
anything that is not an nginx config or does not declare the surface, so a non-web host is never a
false posture claim."""

from __future__ import annotations

from agent.collectors import web_host

_PLAINTEXT_SERVED = """
http {
  server {
    listen 80;
    server_name app.lab;
    location / { proxy_pass http://127.0.0.1:8080; }
    location /admin { proxy_pass http://127.0.0.1:8080; }
  }
}
"""

_TLS_ENFORCED = """
http {
  server { listen 80; server_name app.lab; return 301 https://$host$request_uri; }
  server {
    listen 443 ssl;
    server_name app.lab;
    location / { proxy_pass http://127.0.0.1:8080; }
    location /admin { allow 10.0.0.0/8; deny all; proxy_pass http://127.0.0.1:8080; }
  }
}
"""


def test_cleartext_served_reads_tls_not_enforced() -> None:
    assert web_host.parse_client_facing_tls_enforced(_PLAINTEXT_SERVED) is False


def test_redirect_only_reads_tls_enforced() -> None:
    assert web_host.parse_client_facing_tls_enforced(_TLS_ENFORCED) is True


def test_tls_only_host_reads_enforced() -> None:
    conf = "http { server { listen 443 ssl; location / { root /srv; } } }"
    assert web_host.parse_client_facing_tls_enforced(conf) is True


def test_unrestricted_admin_reads_public() -> None:
    assert web_host.parse_admin_public_access_allowed(_PLAINTEXT_SERVED) is True


def test_restricted_admin_reads_not_public() -> None:
    assert web_host.parse_admin_public_access_allowed(_TLS_ENFORCED) is False


def test_abstains_on_non_nginx_and_absent_surface() -> None:
    assert web_host.parse_client_facing_tls_enforced("not a config") is None
    assert web_host.parse_admin_public_access_allowed("not a config") is None
    # an nginx config with no admin location abstains on the admin control
    no_admin = "http { server { listen 80; location / { proxy_pass http://x; } } }"
    assert web_host.parse_admin_public_access_allowed(no_admin) is None


def test_serves_and_fields_and_host_tier_routing() -> None:
    from agent.collectors import host_tier

    assert web_host.serves("web.tls.client_facing_not_enforced") is True
    assert web_host.serves("web.admin.public") is True
    assert web_host.serves("server.ssh.password") is False
    assert host_tier.serves("web.tls.client_facing_not_enforced") is True
    fields = host_tier.collect_control_fields(
        {"nginx_conf": _PLAINTEXT_SERVED}, "web.tls.client_facing_not_enforced"
    )
    assert fields == {"client_facing_tls_enforced": False}
