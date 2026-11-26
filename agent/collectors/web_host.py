"""Normalize a web server's (nginx) effective configuration into executable-control facts (the
host-readable slice of the web-application cohort).

Read-only: reads the nginx config over the same SSH transport the other host collectors use, and
parses it into the ``web.*`` fields a proxy's own config proves (the controls' required evidence is an
``authenticated_native_configuration`` read, i.e. the config, not an unauthenticated probe). Like
every host collector it ABSTAINS rather than invents: a directive the config does not carry, or a
host with no nginx at all, is left out so the control stays NOT_ASSESSED rather than a false posture
claim.

Only nginx, and only what a server/location config proves, lives here. Apache/IIS (different config
grammars) are future siblings. The web controls that need app code, a WAF rule set, secret stores, an
RBAC model or request-time telemetry (``web.waf.*``, ``web.secret.*``, ``web.rbac.*``,
``web.audit.*``, ...) are not a single config directive and stay DESIGNED.
"""

from __future__ import annotations

# The evidence source this collector reads, and the ssh_collect reader that produces it.
SOURCE_NGINX = "nginx_conf"

SOURCE_READERS = {SOURCE_NGINX: "collect_nginx_conf"}

# Directives/words that mark the text as a genuine nginx config, so unrelated bytes abstain.
_NGINX_MARKERS = ("server", "listen", "location", "http", "proxy_pass", "server_name")

# Location path prefixes that are administrative by convention. Conservative on purpose: only a
# well-known admin surface is judged, so a bespoke path is abstained on rather than guessed.
_ADMIN_PATHS = ("/admin", "/manager", "/wp-admin", "/phpmyadmin", "/administrator", "/_admin")


def _looks_like_nginx(text: str) -> bool:
    return any(marker in text for marker in _NGINX_MARKERS) and "{" in text


def _blocks(text: str, keyword: str) -> list[tuple[str, str]]:
    """Every top-level ``<keyword> <args> { ... }`` block in ``text`` as ``(args, inner)`` pairs, with
    braces matched so a nested block stays inside its parent's ``inner``. A pragmatic brace scanner,
    not a full nginx grammar: comments (``#`` to end of line) are stripped first so a ``{`` in a
    comment does not unbalance it."""
    # strip line comments
    lines = [raw.split("#", 1)[0] for raw in text.splitlines()]
    stripped = "\n".join(lines)
    out: list[tuple[str, str]] = []
    i = 0
    n = len(stripped)
    kw = keyword
    while True:
        idx = stripped.find(kw, i)
        if idx == -1:
            break
        # the keyword must start a token (preceded by start/space/brace/semicolon/newline)
        if idx > 0 and stripped[idx - 1] not in " \t\n{};":
            i = idx + len(kw)
            continue
        brace = stripped.find("{", idx)
        if brace == -1:
            break
        args = stripped[idx + len(kw) : brace].strip()
        # match braces from `brace`
        depth = 0
        j = brace
        while j < n:
            if stripped[j] == "{":
                depth += 1
            elif stripped[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0:
            break  # unbalanced; stop rather than misread
        out.append((args, stripped[brace + 1 : j]))
        i = j + 1
    return out


def _listens_plaintext(server_inner: str) -> bool:
    """Whether a server block listens on a plaintext (non-TLS) port: a ``listen`` on port 80 (or a
    bare ``listen 80`` / ``listen *:80``) without the ``ssl`` parameter. A ``listen 443 ssl`` is TLS,
    not plaintext."""
    for args, _ in _directives(server_inner, "listen"):
        tokens = args.split()
        if not tokens:
            continue
        if "ssl" in tokens:
            continue
        hostport = tokens[0]
        port = hostport.rsplit(":", 1)[-1] if ":" in hostport else hostport
        if port == "80" or hostport == "80":
            return True
    return False


def _strip_nested_blocks(text: str) -> str:
    """``text`` with every ``{ ... }`` body removed, so only this level's simple directives remain. A
    server block's ``listen`` / ``return`` survive while its nested ``location`` bodies drop out."""
    out: list[str] = []
    depth = 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _directives(inner: str, name: str) -> list[tuple[str, str]]:
    """The ``name <args>`` simple directives directly in ``inner`` (not inside a nested block), as
    ``(args, "")`` pairs. nginx directives are ``;``-terminated and MULTIPLE can share one line
    (``allow 10.0.0.0/8; deny all; proxy_pass ...``), so split on ``;`` not newlines, and drop nested
    block bodies first so a directive inside a ``location`` is not read at the server level."""
    text = _strip_nested_blocks("\n".join(raw.split("#", 1)[0] for raw in inner.splitlines()))
    out: list[tuple[str, str]] = []
    for statement in text.split(";"):
        s = " ".join(statement.split())  # normalize whitespace / newlines within a statement
        if not s:
            continue
        head, _, rest = s.partition(" ")
        if head == name:
            out.append((rest.strip(), ""))
    return out


def _only_redirects_to_https(server_inner: str) -> bool:
    """Whether a plaintext server block does nothing but send clients to HTTPS: a top-level
    ``return 301/302 https://...`` (or a ``rewrite ... https://... permanent``) and no content root /
    proxy_pass that would serve cleartext. The enforced case."""
    text = server_inner
    # simpler: scan return/rewrite directives for an https redirect
    has_https_redirect = False
    for args, _ in _directives(text, "return"):
        toks = args.split()
        if toks and toks[0] in ("301", "302") and "https://" in args:
            has_https_redirect = True
    for args, _ in _directives(text, "rewrite"):
        if "https://" in args and "permanent" in args:
            has_https_redirect = True
    serves_content = bool(_directives(text, "root")) or bool(_directives(text, "proxy_pass")) or any(
        _directives(inner, "root") or _directives(inner, "proxy_pass")
        for _, inner in _blocks(text, "location")
    )
    return has_https_redirect and not serves_content


def parse_client_facing_tls_enforced(nginx_conf: str) -> bool | None:
    """Whether client-facing TLS is enforced, or ``None`` to abstain when the text is not an nginx
    config (no recognizable directive). ``False`` (a finding) when a plaintext (port-80) server block
    serves content rather than only redirecting to HTTPS; ``True`` when every plaintext server block
    only redirects to HTTPS, or the host listens on TLS only."""
    if not _looks_like_nginx(nginx_conf):
        return None
    servers = _blocks(nginx_conf, "server")
    if not servers:
        return None
    plaintext_servers = [inner for _, inner in servers if _listens_plaintext(inner)]
    if not plaintext_servers:
        return True  # TLS-only: enforced
    # enforced only if EVERY plaintext server does nothing but redirect to https
    return all(_only_redirects_to_https(inner) for inner in plaintext_servers)


def _is_admin_location(path_args: str) -> bool:
    """Whether a ``location`` block's path is an administrative surface by convention."""
    # the path is the last token of the location args (e.g. "= /admin", "^~ /admin", "/admin")
    tokens = path_args.split()
    path = tokens[-1] if tokens else ""
    return any(path == p or path.startswith(p + "/") or path == p + "/" for p in _ADMIN_PATHS)


def _location_restricts_clients(location_inner: str) -> bool:
    """Whether a location block restricts the client networks that may reach it: a ``deny all`` (with
    or without preceding ``allow`` rules), or an ``allow`` whitelist followed by ``deny all``. A
    ``satisfy`` / auth directive is NOT counted: this control is about client-network ACLs, not
    credentials."""
    denies = [args for args, _ in _directives(location_inner, "deny")]
    return any(args.strip() == "all" for args in denies)


def parse_admin_public_access_allowed(nginx_conf: str) -> bool | None:
    """Whether an administrative route is reachable from public client networks, or ``None`` to
    abstain when the config declares no recognizable admin location. ``True`` (a finding) when an
    admin location has no client-network restriction (no ``deny all``); ``False`` when every admin
    location restricts its clients."""
    if not _looks_like_nginx(nginx_conf):
        return None
    admin_locations = [
        inner
        for _, server_inner in _blocks(nginx_conf, "server")
        for args, inner in _blocks(server_inner, "location")
        if _is_admin_location(args)
    ]
    # also consider top-level/location blocks not inside a server (rare), to be safe
    admin_locations += [
        inner for args, inner in _blocks(nginx_conf, "location") if _is_admin_location(args)
    ]
    if not admin_locations:
        return None
    return not all(_location_restricts_clients(inner) for inner in admin_locations)


# One entry per (control_id, field): the evidence source it reads and the extractor.
_FIELD_EXTRACTORS = {
    ("web.tls.client_facing_not_enforced", "client_facing_tls_enforced"): (
        SOURCE_NGINX,
        parse_client_facing_tls_enforced,
    ),
    ("web.admin.public", "admin_public_access_allowed"): (
        SOURCE_NGINX,
        parse_admin_public_access_allowed,
    ),
}


def _extractors_for(control_id: str) -> list[tuple[str, str, object]]:
    return [
        (field, source, extractor)
        for (ctrl, field), (source, extractor) in _FIELD_EXTRACTORS.items()
        if ctrl == control_id
    ]


def serves(control_id: str) -> bool:
    """Whether this collector reads the evidence for ``control_id``."""
    return bool(_extractors_for(control_id))


def source_for(control_id: str) -> str | None:
    """The single evidence source ``control_id`` is read from, or ``None`` if not served."""
    extractors = _extractors_for(control_id)
    return extractors[0][1] if extractors else None


def sources_for_control(control_id: str) -> set[str]:
    """The evidence sources ``control_id`` reads (one for this collector), for the host-tier
    aggregation."""
    source = source_for(control_id)
    return {source} if source is not None else set()


def collect_control_fields(sources: dict[str, str], control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from the collected evidence, or
    ``None`` if it does not serve that control. A field whose extractor abstains is left out."""
    supported = _extractors_for(control_id)
    if not supported:
        return None
    fields: dict[str, object] = {}
    for field, source, extractor in supported:
        value = extractor(sources.get(source, ""))
        if value is not None:
            fields[field] = value
    return fields
