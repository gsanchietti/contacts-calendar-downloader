"""OAuth client identifiers used by the CLI.

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
    {"google": {"client_id": "...", "client_secret": "...",
                "redirect_uri": "https://example.org/ccd/callback"},
     "microsoft": {"client_id": "...", "authority": "..."}}

``redirect_uri`` is optional and empty by default; see ``google()`` below.
"""
import json
import os
from typing import Any, Dict

# --- Values baked into the distribution -------------------------------------
# Google: intentionally empty. Set CCD_GOOGLE_CLIENT_ID / CCD_GOOGLE_CLIENT_SECRET
# (or the "google" section of client_config.json) to the Desktop-app client of
# a Google Cloud project holding the sensitive-scope approval for
# contacts.readonly / calendar.readonly. require("google") fails loudly with
# that hint when they are unset.
_EMBEDDED_GOOGLE_CLIENT_ID = ""
_EMBEDDED_GOOGLE_CLIENT_SECRET = ""

# Microsoft: multi-tenant app registration with "Allow public client flows"
# enabled. Public clients have no secret at all.
_EMBEDDED_MS_CLIENT_ID = "663ca2fe-4616-4340-8958-a2b5a5cd696d"
_EMBEDDED_MS_AUTHORITY = "https://login.microsoftonline.com/common"


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
    """Return the Google client_id / client_secret / redirect_uri in use.

    ``redirect_uri`` is empty unless an operator sets it. Empty means "use a
    loopback redirect" (the default installed-app flow). Setting it to the
    https URL of a hosted static callback page switches ``ccd login`` to that
    page instead, which is friendlier for users who run ccd in a container or
    over SSH, where the browser cannot reach the CLI's loopback address. Such
    a URL requires an OAuth client of type "Web application"; Google rejects
    https redirect URIs on "Desktop app" clients.
    """
    return {
        "client_id": _pick("CCD_GOOGLE_CLIENT_ID", "google", "client_id", _EMBEDDED_GOOGLE_CLIENT_ID),
        "client_secret": _pick("CCD_GOOGLE_CLIENT_SECRET", "google", "client_secret", _EMBEDDED_GOOGLE_CLIENT_SECRET),
        "redirect_uri": _pick("CCD_GOOGLE_REDIRECT_URI", "google", "redirect_uri", ""),
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
