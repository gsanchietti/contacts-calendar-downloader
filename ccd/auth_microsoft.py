"""Microsoft OAuth: RFC 8628 device authorization grant via MSAL.

Unlike Google, Microsoft Graph's ``Contacts.Read`` / ``Calendars.Read``
scopes work fine with the device-code flow, so we use it as-is: no loopback
redirect, no browser dance -- the user visits a short URL on any device and
types a code.
"""
import time
from typing import Any, Dict

from .errors import AuthExpiredError, CcdError

# Full scope list persisted in the account record.
STORED_SCOPES = [
    "offline_access",
    "openid",
    "profile",
    "User.Read",
    "Contacts.Read",
    "Calendars.Read",
]

# MSAL's flow builders reject the OIDC reserved scopes (openid, profile,
# offline_access) -- it adds them itself. Only pass the resource scopes.
_MSAL_SCOPES = ["User.Read", "Contacts.Read", "Calendars.Read"]

GRAPH_ME_ENDPOINT = "https://graph.microsoft.com/v1.0/me"


def login() -> Dict[str, Any]:
    """Run the interactive device-code flow and return the saved record."""
    import msal

    from . import client_config

    cfg = client_config.require("microsoft")
    app = msal.PublicClientApplication(cfg["client_id"], authority=cfg["authority"])

    flow = app.initiate_device_flow(scopes=_MSAL_SCOPES)
    if "user_code" not in flow:
        raise CcdError(f"Could not start Microsoft device flow: {flow.get('error_description', flow)}")

    # flow["message"] already contains the full "go to https://microsoft.com/devicelogin
    # and enter code XXXX-XXXX" instructions.
    #
    # flush=True is load-bearing: acquire_token_by_device_flow() then blocks for
    # up to 15 minutes, and when stdout is a pipe rather than a terminal Python
    # buffers this line until the process exits. Without the flush the user
    # never sees the code they are supposed to type.
    print(flow["message"], flush=True)

    result = app.acquire_token_by_device_flow(flow)  # blocks, MSAL handles polling
    if "access_token" not in result:
        raise CcdError(
            f"Microsoft sign-in failed: {result.get('error_description', result.get('error', result))}"
        )

    access_token = result["access_token"]
    refresh_token = result.get("refresh_token")
    if not refresh_token:
        raise CcdError("Microsoft did not return a refresh token; cannot proceed.")
    expires_at = time.time() + float(result.get("expires_in", 3600))

    claims = result.get("id_token_claims") or {}
    email = claims.get("preferred_username") or claims.get("upn") or claims.get("email")
    if not email:
        try:
            import requests

            resp = requests.get(
                GRAPH_ME_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=15,
            )
            if resp.status_code == 200:
                me = resp.json()
                email = me.get("userPrincipalName") or me.get("mail")
        except Exception:
            email = None
    if not email:
        raise CcdError("Could not determine the Microsoft account's email address.")

    now = time.time()
    record = {
        "provider": "microsoft",
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "scopes": STORED_SCOPES,
        "created_at": now,
        "updated_at": now,
    }

    from . import store

    store.save(record)
    return record


def refresh(record: Dict[str, Any]) -> Dict[str, Any]:
    """Exchange the stored refresh token for a new access token.

    Entra rotates refresh tokens on public clients, so the response's
    refresh_token (when present) replaces the stored one.
    """
    import requests

    from . import client_config

    cfg = client_config.require("microsoft")
    token_url = f"{cfg['authority']}/oauth2/v2.0/token"

    resp = requests.post(
        token_url,
        data={
            "client_id": cfg["client_id"],
            "grant_type": "refresh_token",
            "refresh_token": record["refresh_token"],
            "scope": " ".join(record.get("scopes", STORED_SCOPES)),
        },
        timeout=15,
    )
    if resp.status_code == 400 and "invalid_grant" in resp.text:
        raise AuthExpiredError(
            f"Microsoft refresh token for {record.get('email')} is no longer "
            "valid. Run 'ccd login --provider microsoft' again."
        )
    if resp.status_code != 200:
        raise AuthExpiredError(f"Failed to refresh Microsoft token: {resp.text}")

    token = resp.json()
    updated = dict(record)
    updated["access_token"] = token["access_token"]
    updated["refresh_token"] = token.get("refresh_token", record["refresh_token"])
    updated["expires_at"] = time.time() + float(token.get("expires_in", 3600))
    updated["updated_at"] = time.time()
    return updated


def revoke(record: Dict[str, Any]) -> bool:
    """Entra has no programmatic per-app revoke for public clients."""
    return False
