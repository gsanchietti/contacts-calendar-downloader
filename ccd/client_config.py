"""OAuth client identifiers and service-level configuration.

Google credentials are **not** shipped with this program. An installed app
cannot keep a secret (RFC 8252 section 8.5), so a client embedded here would
be a public one -- workable, but it also means every copy of the source
carries a live client id/secret pair, which secret scanners flag and which
nobody can rotate without a release. Instead the operator who deploys ccd
registers their own Google client and passes it in, per the "Google Cloud
Setup" section of docs/providers.md.

Microsoft is different: a public client registration has no secret at all,
only a client id, so a default is embedded and users need to configure
nothing.

Every value can be set through the environment, or through a JSON file:

    ~/.config/contacts-calendar-downloader/client_config.json
    {"google": {"client_id": "...", "client_secret": "..."},
     "microsoft": {"client_id": "...", "authority": "..."}}
"""
import json
import os
import secrets
import urllib.parse
from typing import Any, Dict, Tuple

# --- Values baked into the distribution -------------------------------------
# Google: intentionally empty. Set CCD_GOOGLE_CLIENT_ID / CCD_GOOGLE_CLIENT_SECRET
# (or the "google" section of client_config.json) to the Web-application client of
# a Google Cloud project holding the sensitive-scope approval for
# contacts.readonly / calendar.readonly. require("google") fails loudly with
# that hint when they are unset.
_EMBEDDED_GOOGLE_CLIENT_ID = ""
_EMBEDDED_GOOGLE_CLIENT_SECRET = ""

# Microsoft: multi-tenant app registration with "Allow public client flows"
# enabled. Public clients have no secret at all.
_EMBEDDED_MS_CLIENT_ID = "663ca2fe-4616-4340-8958-a2b5a5cd696d"
_EMBEDDED_MS_AUTHORITY = "https://login.microsoftonline.com/common"

DEFAULT_LISTEN = "127.0.0.1:8080"


def _file_overrides() -> Dict[str, Any]:
    """Read optional client_config.json from the config directory."""
    # Imported here to avoid a circular import: store imports nothing from us.
    from .store import config_root

    path = config_root() / "client_config.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _pick(env_var: str, file_section: str, file_key: str, embedded: str) -> str:
    value = os.environ.get(env_var)
    if value:
        return value
    section = _file_overrides().get(file_section) or {}
    if isinstance(section, dict) and section.get(file_key):
        return str(section[file_key])
    return embedded


def google() -> Dict[str, str]:
    """Return the Google client_id / client_secret in use.

    The redirect URI is no longer configurable: the service hosts the
    callback itself, at ``{base_url()}/oauth/callback``. That URL has to be
    registered on an OAuth client of type "Web application" -- Google rejects
    https redirect URIs on "Desktop app" clients.
    """
    return {
        "client_id": _pick("CCD_GOOGLE_CLIENT_ID", "google", "client_id", _EMBEDDED_GOOGLE_CLIENT_ID),
        "client_secret": _pick("CCD_GOOGLE_CLIENT_SECRET", "google", "client_secret", _EMBEDDED_GOOGLE_CLIENT_SECRET),
    }


def microsoft() -> Dict[str, str]:
    """Return the Microsoft client_id and authority in use."""
    return {
        "client_id": _pick("CCD_MS_CLIENT_ID", "microsoft", "client_id", _EMBEDDED_MS_CLIENT_ID),
        "authority": _pick("CCD_MS_AUTHORITY", "microsoft", "authority", _EMBEDDED_MS_AUTHORITY),
    }


def require(provider: str) -> Dict[str, str]:
    """Return a provider's client config, failing loudly when it is unset."""
    from .errors import CcdError

    if provider == "google":
        cfg = google()
        missing = [k for k in ("client_id", "client_secret") if not cfg[k]]
        env_hint = "CCD_GOOGLE_CLIENT_ID / CCD_GOOGLE_CLIENT_SECRET"
    elif provider == "microsoft":
        cfg = microsoft()
        missing = [k for k in ("client_id",) if not cfg[k]]
        env_hint = "CCD_MS_CLIENT_ID"
    else:
        raise CcdError(f"Unknown provider: {provider}")

    if missing:
        raise CcdError(
            f"No {provider} OAuth client configured (missing: {', '.join(missing)}).\n"
            f"Set {env_hint}, or add it to client_config.json in the config directory."
        )
    return cfg


# --------------------------------------------------------------------------- #
# Service configuration
# --------------------------------------------------------------------------- #

def listen_address(override: str = "") -> Tuple[str, int]:
    """Parse CCD_LISTEN (or an explicit override) into (host, port)."""
    from .errors import CcdError

    raw = override or os.environ.get("CCD_LISTEN") or DEFAULT_LISTEN
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise CcdError(f"Invalid listen address '{raw}'; expected HOST:PORT.")
    return host, int(port)


def base_url(port: int = 0) -> str:
    """Return the externally visible base URL, without a trailing slash.

    May carry a path prefix (``https://voice.example.com/ccd``): ccd is
    normally embedded under some other module's hostname, with Traefik
    stripping the prefix before forwarding. Only *generated* URLs -- the
    Google redirect URI and the per-account download links -- need the
    prefix; routing never does, which is why this value is read here and
    nowhere in the router.
    """
    configured = os.environ.get("CCD_BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    return f"http://127.0.0.1:{port or listen_address()[1]}"


def redirect_uri(port: int = 0) -> str:
    """Return the OAuth redirect URI that must be registered with Google."""
    return f"{base_url(port)}/oauth/callback"


def download_urls(download_token: str, port: int = 0) -> Dict[str, str]:
    """Return the three public download URLs for an account's token."""
    base = f"{base_url(port)}/d/{urllib.parse.quote(download_token, safe='')}"
    return {
        "contacts_csv": f"{base}/contacts.csv",
        "contacts_json": f"{base}/contacts.json",
        "calendar_ics": f"{base}/calendar.ics",
    }


def ensure_api_key() -> Tuple[str, bool]:
    """Return the API key protecting /api/*, creating one if needed.

    Returns ``(key, created)``. Precedence is CCD_API_KEY, then a previously
    generated ``api_key`` file in the config root, then a fresh key written
    there with mode 0600.
    """
    from .store import config_root, write_private

    from_env = os.environ.get("CCD_API_KEY", "").strip()
    if from_env:
        return from_env, False

    path = config_root() / "api_key"
    if path.exists():
        existing = path.read_text().strip()
        if existing:
            return existing, False

    key = secrets.token_urlsafe(32)
    write_private(path, key + "\n")
    return key, True
