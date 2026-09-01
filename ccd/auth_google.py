"""Google OAuth: authorization-code + PKCE against the service's own callback.

Google's device-code flow does not support the ``contacts.readonly`` /
``calendar.readonly`` scopes (it only allows a short allowlist such as
email/openid/profile/drive.appdata/drive.file/youtube*), so we cannot use it
here. The authorization-code flow is what is left, and now that ccd is an
HTTP service there is somewhere for the browser to land: the service's own
``/oauth/callback``. The redirect URI is derived from ``CCD_BASE_URL`` and
must be registered on an OAuth client of type "Web application"; Google
rejects https redirect URIs on "Desktop app" clients.

``login()`` is deliberately absent -- the flow spans two HTTP requests, so it
is exposed as ``start()`` (build the consent URL) and ``complete()`` (redeem
the code Google sent back). ``ccd/service.py`` owns the state in between.
"""
import base64
import hashlib
import secrets
import time
import urllib.parse
from typing import Any, Dict, Tuple

from .errors import AuthExpiredError, CcdError

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"

SCOPES = [
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]


def _code_verifier() -> str:
    # 43-128 URL-safe characters, per RFC 7636.
    return secrets.token_urlsafe(64)


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_jwt_payload(id_token: str) -> Dict[str, Any]:
    """Decode the payload of a JWT without verifying its signature.

    This is safe here because the token arrived directly from Google's token
    endpoint over TLS (not from a third party or a redirect), so there is
    nothing to authenticate against -- we already trust the channel it came
    over. We only use it to read the ``email`` claim.
    """
    import json

    parts = id_token.split(".")
    if len(parts) != 3:
        raise CcdError("Malformed id_token returned by Google.")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload + padding)
    return json.loads(decoded)


def start(redirect_uri: str, state: str) -> Tuple[str, Dict[str, Any]]:
    """Build the consent URL. Returns ``(authorization_url, pending)``.

    ``pending`` carries the PKCE verifier and the redirect URI, both of which
    the token exchange in ``complete()`` needs; the caller keeps it until the
    browser comes back.
    """
    from . import client_config

    cfg = client_config.require("google")

    verifier = _code_verifier()
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
        "code_challenge": _code_challenge(verifier),
        "code_challenge_method": "S256",
    }
    auth_url = "{0}?{1}".format(AUTH_ENDPOINT, urllib.parse.urlencode(params))
    return auth_url, {"verifier": verifier, "redirect_uri": redirect_uri}


def complete(pending: Dict[str, Any], code: str) -> Dict[str, Any]:
    """Redeem an authorization code and save the resulting account record."""
    import requests

    from . import client_config

    cfg = client_config.require("google")

    token_resp = requests.post(
        TOKEN_ENDPOINT,
        data={
            "code": code,
            "code_verifier": pending["verifier"],
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "redirect_uri": pending["redirect_uri"],
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    if token_resp.status_code != 200:
        raise CcdError("Google token exchange failed: {0}".format(token_resp.text))
    token = token_resp.json()

    access_token = token["access_token"]
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        raise CcdError(
            "Google did not return a refresh token. This usually means the "
            "account already granted consent previously without "
            "'prompt=consent'; try again (this should not happen with ccd)."
        )
    expires_at = time.time() + float(token.get("expires_in", 3600))

    email = None
    id_token = token.get("id_token")
    if id_token:
        try:
            email = _decode_jwt_payload(id_token).get("email")
        except (CcdError, ValueError):
            email = None
    if not email:
        resp = requests.get(
            USERINFO_ENDPOINT,
            headers={"Authorization": "Bearer {0}".format(access_token)},
            timeout=15,
        )
        if resp.status_code == 200:
            email = resp.json().get("email")
    if not email:
        raise CcdError("Could not determine the Google account's email address.")

    from . import store

    now = time.time()
    record = {
        "provider": "google",
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "scopes": SCOPES,
        "download_token": store.new_download_token(),
        "created_at": now,
        "updated_at": now,
    }

    # Re-linking an account keeps its download token, so URLs already handed
    # out to other applications survive a re-consent.
    existing = store.load("google", email)
    if existing and existing.get("download_token"):
        record["download_token"] = existing["download_token"]
        record["created_at"] = existing.get("created_at", now)

    store.save(record)
    return record


def refresh(record: Dict[str, Any]) -> Dict[str, Any]:
    """Exchange the stored refresh token for a new access token."""
    import requests

    from . import client_config

    cfg = client_config.require("google")

    resp = requests.post(
        TOKEN_ENDPOINT,
        data={
            "refresh_token": record["refresh_token"],
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    if resp.status_code == 400 and "invalid_grant" in resp.text:
        raise AuthExpiredError(
            f"Google refresh token for {record.get('email')} is no longer "
            "valid. Link the account again."
        )
    if resp.status_code != 200:
        raise AuthExpiredError(f"Failed to refresh Google token: {resp.text}")

    token = resp.json()
    updated = dict(record)
    updated["access_token"] = token["access_token"]
    # Google usually omits refresh_token on refresh responses; keep the
    # existing one unless a new one was actually issued.
    updated["refresh_token"] = token.get("refresh_token", record["refresh_token"])
    updated["expires_at"] = time.time() + float(token.get("expires_in", 3600))
    updated["updated_at"] = time.time()
    return updated


def revoke(record: Dict[str, Any]) -> bool:
    """Revoke the stored grant with Google. Returns True on success."""
    import requests

    token = record.get("refresh_token") or record.get("access_token")
    if not token:
        return False
    resp = requests.post(REVOKE_ENDPOINT, params={"token": token}, timeout=15)
    return resp.status_code == 200


def credentials(record: Dict[str, Any]) -> Any:
    """Build a google.oauth2.credentials.Credentials for API calls."""
    from datetime import datetime

    from google.oauth2.credentials import Credentials

    from . import client_config, store

    cfg = client_config.require("google")
    access_token = store.get_access_token(record)
    # Re-read in case store.get_access_token() refreshed and persisted it.
    current = store.load("google", record["email"]) or record

    return Credentials(
        token=access_token,
        refresh_token=current.get("refresh_token"),
        token_uri=TOKEN_ENDPOINT,
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"],
        scopes=current.get("scopes", SCOPES),
        # google-auth compares against naive UTC and raises on tz-aware
        # datetimes, so this must not carry a tzinfo.
        expiry=datetime.utcfromtimestamp(current.get("expires_at", time.time())),
    )
