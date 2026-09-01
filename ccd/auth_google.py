"""Google OAuth: authorization-code + PKCE, without a local web server.

Google's device-code flow does not support the ``contacts.readonly`` /
``calendar.readonly`` scopes (it only allows a short allowlist such as
email/openid/profile/drive.appdata/drive.file/youtube*), so we cannot use it
here. What is left is the authorization-code flow -- but ccd runs on a
server, where the browser is always on some other machine and can never
reach a redirect URI this process listens on. So nothing is listened for:
the user completes consent in their own browser and pastes the resulting
URL into the terminal. Where that URL comes from is the only variable --
either an operator-hosted static callback page (``redirect_uri`` in the
client config) or, by default, the connection-refused page of a
``http://127.0.0.1:<port>`` address nothing is bound to.
"""
import base64
import hashlib
import hmac
import random
import secrets
import time
import urllib.parse
from typing import Any, Dict

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


def login() -> Dict[str, Any]:
    """Run the interactive PKCE flow and return the saved record.

    The user always pastes the post-consent URL back; see the module
    docstring for why there is no listener to catch the redirect.
    """
    import requests

    from . import client_config

    cfg = client_config.require("google")

    verifier = _code_verifier()
    challenge = _code_challenge(verifier)
    state = secrets.token_urlsafe(24)

    # An operator-hosted callback page, when configured; otherwise a loopback
    # address with nothing bound to it, whose browser error page still carries
    # the code in its address bar.
    redirect_uri = cfg.get("redirect_uri") or "http://127.0.0.1:{0}".format(
        random.randint(20000, 60000)
    )

    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = "{0}?{1}".format(AUTH_ENDPOINT, urllib.parse.urlencode(params))

    code, returned_state = _authorize(auth_url, redirect_uri)

    if returned_state is not None and not hmac.compare_digest(returned_state, state):
        raise CcdError(
            "State mismatch on the returned URL -- this can indicate a "
            "hijacked or stale authorization response. Aborting."
        )

    token_resp = requests.post(
        TOKEN_ENDPOINT,
        data={
            "code": code,
            "code_verifier": verifier,
        "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
        "redirect_uri": redirect_uri,
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

    now = time.time()
    record = {
        "provider": "google",
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "scopes": SCOPES,
        "created_at": now,
        "updated_at": now,
    }

    from . import store

    store.save(record)
    return record


def _authorize(auth_url, redirect_uri):
    """Get the user through consent. Returns ``(code, state_or_None)``."""
    print("Open this URL in a browser and sign in / grant access:\n")
    print("  {0}\n".format(auth_url))
    if redirect_uri.startswith("https://"):
        print(
            "After you approve, the browser lands on {0}, which shows the "
            "authorization result and a button to copy the full URL. Paste "
            "it below.\n".format(redirect_uri),
            flush=True,
        )
    else:
        print(
            "After you approve, the browser will redirect to "
            "{0}/... and show a \"This site can't be reached\" (or similar "
            "connection-refused) error page. That is expected -- nothing is "
            "listening on that port. Copy the full URL from the address bar "
            "and paste it below.\n".format(redirect_uri),
            flush=True,
        )

    pasted = input("Paste the redirected URL (or just the 'code' value): ").strip()
    if not pasted:
        raise CcdError("No input received; aborting login.")

    if pasted.startswith("http://") or pasted.startswith("https://"):
        parsed = urllib.parse.urlparse(pasted)
        qs = urllib.parse.parse_qs(parsed.query)
        if "error" in qs:
            raise CcdError("Google returned an error: {0}".format(qs["error"][0]))
        if "code" not in qs:
            raise CcdError("No 'code' parameter found in the pasted URL.")
        return qs["code"][0], qs.get("state", [None])[0]
    return pasted, None


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
            "valid. Run 'ccd login --provider google' again."
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
