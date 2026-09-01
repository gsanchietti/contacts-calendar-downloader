"""Everything the HTTP service does, with no knowledge of HTTP.

``ccd/server.py`` is routing and serialization only; the work lives here, so
the two provider auth flows, the account store and the download rendering can
be reasoned about (and called) without a request object.

The one piece of mutable process state is the pending-login registry. OAuth
logins span two requests -- start, then either a browser redirect (Google) or
a background device-code poll (Microsoft) -- and the bit in between (a PKCE
verifier, an MSAL flow) is short-lived and worthless after a restart, so it
is kept in memory rather than on disk. A restart cancels in-flight logins and
loses nothing that was persisted.
"""
import contextlib
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from . import client_config, serialize, store
from .errors import AuthExpiredError, CcdError, NoAccountsError, ProviderApiError

PROVIDERS = ("google", "microsoft")

# How long a login may sit unfinished before it is swept. Google's consent
# screen and Microsoft's device code both give the user well under 15 minutes.
LOGIN_TTL = 20 * 60

_logins: Dict[str, Dict[str, Any]] = {}
_logins_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Account views
# --------------------------------------------------------------------------- #

def public_view(record: Dict[str, Any], port: int = 0) -> Dict[str, Any]:
    """Render an account record for the API.

    Strips the OAuth tokens -- they must never leave this process -- and adds
    the derived fields callers actually want: whether the access token has
    expired, and the three download URLs.
    """
    record = store.ensure_download_token(record)
    view = {
        k: v
        for k, v in record.items()
        if k not in ("access_token", "refresh_token", "download_token")
    }
    seconds_left = record.get("expires_at", 0) - time.time()
    view["expired"] = seconds_left <= 0
    view["expires_in"] = None if seconds_left <= 0 else int(seconds_left)
    view["download"] = client_config.download_urls(record["download_token"], port)
    return view


def list_accounts(port: int = 0) -> List[Dict[str, Any]]:
    return [public_view(r, port) for r in store.list_accounts()]


def get_record(provider: str, email: str) -> Dict[str, Any]:
    """Load one account record, or raise NoAccountsError."""
    if provider not in PROVIDERS:
        raise CcdError(f"Unknown provider: {provider}")
    record = store.load(provider, email)
    if record is None:
        raise NoAccountsError(f"No linked {provider} account for '{email}'.")
    return store.ensure_download_token(record)


def get_account(provider: str, email: str, port: int = 0) -> Dict[str, Any]:
    return public_view(get_record(provider, email), port)


def rotate_token(provider: str, email: str, port: int = 0) -> Dict[str, Any]:
    """Issue a fresh download token, invalidating the account's old URLs."""
    return public_view(store.rotate_download_token(get_record(provider, email)), port)


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

def _sweep_logins() -> None:
    cutoff = time.time() - LOGIN_TTL
    for login_id, entry in list(_logins.items()):
        if entry["created_at"] < cutoff:
            del _logins[login_id]


def start_login(provider: str, port: int = 0) -> Dict[str, Any]:
    """Begin a login. Returns what the caller must show the user.

    The two providers answer differently on purpose -- Google hands back a
    consent URL to open, Microsoft a short URL plus a code to type -- so the
    response carries a ``kind`` telling the caller which it got. Both are then
    polled the same way, through ``login_status()``.
    """
    import secrets

    if provider not in PROVIDERS:
        raise CcdError(f"Unknown provider: {provider}")

    login_id = secrets.token_urlsafe(24)
    now = time.time()

    if provider == "google":
        from . import auth_google

        # The login id doubles as the OAuth 'state' parameter: it is
        # unguessable, it is what the callback looks the login up by, and
        # comparing it is exactly the CSRF check state exists for.
        auth_url, pending = auth_google.start(client_config.redirect_uri(port), login_id)
        entry = {
            "provider": "google",
            "status": "pending",
            "created_at": now,
            "pending": pending,
            "port": port,
        }
        response = {
            "login_id": login_id,
            "provider": "google",
            "kind": "redirect",
            "authorization_url": auth_url,
            "expires_in": LOGIN_TTL,
        }
    else:
        from . import auth_microsoft

        flow = auth_microsoft.start()
        entry = {
            "provider": "microsoft",
            "status": "pending",
            "created_at": now,
            "port": port,
        }
        response = {
            "login_id": login_id,
            "provider": "microsoft",
            "kind": "device",
            "verification_uri": flow.get("verification_uri"),
            "user_code": flow.get("user_code"),
            "message": flow.get("message"),
            "expires_in": int(flow.get("expires_in", LOGIN_TTL)),
        }

    with _logins_lock:
        _sweep_logins()
        _logins[login_id] = entry

    if provider == "microsoft":
        # MSAL's device-flow call blocks until the user finishes or the code
        # expires, so it cannot run on the request thread.
        thread = threading.Thread(
            target=_await_device_flow, args=(login_id, flow, port), daemon=True
        )
        thread.start()

    return response


def _await_device_flow(login_id: str, flow: Dict[str, Any], port: int) -> None:
    from . import auth_microsoft

    try:
        record = auth_microsoft.wait(flow)
    except CcdError as exc:
        _finish_login(login_id, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - a stuck thread would hang the login forever
        _finish_login(login_id, error=f"Microsoft sign-in failed: {exc}")
    else:
        _finish_login(login_id, record=record, port=port)


def _finish_login(
    login_id: str,
    record: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    port: int = 0,
) -> None:
    with _logins_lock:
        entry = _logins.get(login_id)
        if entry is None or entry["status"] != "pending":
            return
        if record is not None:
            entry["status"] = "done"
            entry["account"] = public_view(record, port)
        else:
            entry["status"] = "error"
            entry["error"] = error
        entry.pop("pending", None)


def login_status(login_id: str) -> Dict[str, Any]:
    """Return the state of a login, or raise NoAccountsError if unknown."""
    with _logins_lock:
        _sweep_logins()
        entry = _logins.get(login_id)
        if entry is None:
            raise NoAccountsError("Unknown or expired login id.")
        if entry["status"] == "done":
            return {"status": "done", "provider": entry["provider"], "account": entry["account"]}
        if entry["status"] == "error":
            return {"status": "error", "provider": entry["provider"], "error": entry["error"]}
        return {"status": "pending", "provider": entry["provider"]}


def complete_google_callback(state: str, code: str, error: str = "") -> Dict[str, Any]:
    """Handle the browser landing on /oauth/callback.

    Returns ``{"ok": bool, "message": str}`` for the page the browser is
    about to see; the authoritative result is what ``login_status()`` will
    report to whoever started the login.
    """
    with _logins_lock:
        _sweep_logins()
        entry = _logins.get(state or "")
        # An unknown state is the case CSRF protection exists for: someone
        # replayed or forged a callback. There is nothing to compare in
        # constant time here -- the lookup key *is* the secret, and a dict
        # miss reveals only that this particular value is not a live login.
        if entry is None or entry["provider"] != "google":
            return {"ok": False, "message": "Unknown or expired sign-in request."}
        if entry["status"] != "pending":
            return {"ok": False, "message": "This sign-in request was already completed."}
        pending = entry["pending"]
        port = entry.get("port", 0)

    if error:
        _finish_login(state, error=f"Google returned an error: {error}")
        return {"ok": False, "message": f"Google returned an error: {error}"}
    if not code:
        _finish_login(state, error="Google did not return an authorization code.")
        return {"ok": False, "message": "Google did not return an authorization code."}

    from . import auth_google

    try:
        record = auth_google.complete(pending, code)
    except CcdError as exc:
        _finish_login(state, error=str(exc))
        return {"ok": False, "message": str(exc)}

    _finish_login(state, record=record, port=port)
    return {"ok": True, "message": f"Linked google account: {record['email']}"}


# --------------------------------------------------------------------------- #
# Provider data
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def _google_errors():
    """Map google client exceptions onto ccd's error classes.

    ``RefreshError`` matters as much as ``HttpError`` here: google-auth
    refreshes the access token *inside* googleapiclient, bypassing
    ``store.get_access_token``, so a grant the user revoked provider-side
    surfaces here rather than at our own refresh. It means the same thing --
    the account has to be linked again -- and must not be reported as an
    internal error.
    """
    from google.auth.exceptions import RefreshError
    from googleapiclient.errors import HttpError

    try:
        yield
    except RefreshError as exc:
        raise AuthExpiredError(
            f"Google refused to refresh this account's token ({exc.args[0] if exc.args else exc}). "
            "Link the account again."
        ) from exc
    except HttpError as exc:
        raise ProviderApiError(f"Google API error: {exc}") from exc


def _contacts_rows(record: Dict[str, Any], page_size: int = 1000) -> List[Dict[str, str]]:
    provider = record["provider"]
    if provider == "google":
        from googleapiclient.discovery import build

        from providers import google as google_provider

        from . import auth_google

        with _google_errors():
            creds = auth_google.credentials(record)
            service = build("people", "v1", credentials=creds, cache_discovery=False)
            raw = google_provider.download_contacts(service, page_size=page_size)
        return [google_provider.extract_contact_row(p) for p in raw]

    if provider == "microsoft":
        import requests

        from providers import microsoft as ms_provider

        token = store.get_access_token(record)
        try:
            raw = ms_provider.fetch_contacts({"access_token": token}, page_size=page_size)
        except requests.HTTPError as exc:
            raise ProviderApiError(f"Microsoft Graph error: {exc}") from exc
        return [ms_provider.extract_contact_row(c) for c in raw]

    raise CcdError(f"Unknown provider: {provider}")


def _calendar_ics(record: Dict[str, Any]) -> str:
    provider = record["provider"]
    if provider == "google":
        from providers import google as google_provider

        from . import auth_google

        with _google_errors():
            creds = auth_google.credentials(record)
            return google_provider.fetch_google_calendar(creds)

    if provider == "microsoft":
        import requests

        from providers import microsoft as ms_provider

        token = store.get_access_token(record)
        try:
            return ms_provider.fetch_microsoft_calendar({"access_token": token})
        except requests.HTTPError as exc:
            raise ProviderApiError(f"Microsoft Graph error: {exc}") from exc

    raise CcdError(f"Unknown provider: {provider}")


def live_check(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Do one cheap authenticated call.

    Returns None when the token works, otherwise a dict with the error
    message and whether the cause was an unrecoverable auth failure.
    """
    provider = record["provider"]
    try:
        if provider == "google":
            from googleapiclient.discovery import build

            from . import auth_google

            with _google_errors():
                creds = auth_google.credentials(record)
                service = build("people", "v1", credentials=creds, cache_discovery=False)
                # people.get(people/me) reads *profile* data and would demand
                # the 'profile' scope, which ccd deliberately does not request.
                # Listing a single connection is the cheapest call covered by
                # the scopes we actually hold (contacts.readonly).
                (
                    service.people()
                    .connections()
                    .list(resourceName="people/me", pageSize=1, personFields="names")
                    .execute()
                )
        elif provider == "microsoft":
            from providers import microsoft as ms_provider

            ms_provider.get_profile(store.get_access_token(record))
        else:
            return {"message": f"unknown provider '{provider}'", "auth_expired": False}
    except AuthExpiredError as exc:
        return {"message": str(exc), "auth_expired": True}
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller, not swallowed
        return {"message": str(exc), "auth_expired": False}
    return None


def account_status(provider: str, email: str, port: int = 0) -> Dict[str, Any]:
    record = get_record(provider, email)
    error = live_check(record)

    # Re-read: a successful live check may have refreshed and persisted a new
    # access token, so the stored expiry is newer than what we started with.
    current = store.load(provider, email) or record
    seconds_left = current.get("expires_at", 0) - time.time()
    expired = seconds_left <= 0

    return {
        "provider": provider,
        "email": email,
        "expired": expired,
        "expires_in": None if expired else int(seconds_left),
        "live_check": "failed" if error else "ok",
        "error": error["message"] if error else None,
        "auth_expired": bool(error and error["auth_expired"]),
    }


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #

ARTIFACTS = {
    "contacts.csv": ("text/csv; charset=utf-8", "csv"),
    "contacts.json": ("application/json; charset=utf-8", "json"),
    "calendar.ics": ("text/calendar; charset=utf-8", "ics"),
}


def download(download_token: str, artifact: str) -> Tuple[str, str, str]:
    """Render one artifact for the account a download token belongs to.

    Returns ``(body, content_type, filename)``. An unknown token raises
    ``NoAccountsError`` with a deliberately blank message: the caller turns
    that into a flat 404 that says nothing about whether the token was wrong
    or the account simply has no data.
    """
    if artifact not in ARTIFACTS:
        raise NoAccountsError("Not found.")

    record = store.find_by_download_token(download_token)
    if record is None:
        raise NoAccountsError("Not found.")

    content_type, fmt = ARTIFACTS[artifact]
    email = record["email"]

    if fmt == "ics":
        return _calendar_ics(record), content_type, f"calendar_{email}.ics"

    rows = _contacts_rows(record)
    body = serialize.contacts_to_csv(rows) if fmt == "csv" else serialize.contacts_to_json(rows)
    return body, content_type, f"contacts_{email}.{fmt}"


# --------------------------------------------------------------------------- #
# Logout
# --------------------------------------------------------------------------- #

def logout(provider: str, email: str, revoke: bool = False) -> Dict[str, Any]:
    record = get_record(provider, email)
    revoked = False
    note = None

    if revoke:
        try:
            if provider == "google":
                from . import auth_google

                revoked = auth_google.revoke(record)
            elif provider == "microsoft":
                from . import auth_microsoft

                revoked = auth_microsoft.revoke(record)
        except Exception as exc:  # noqa: BLE001 - never let a revoke failure block local cleanup
            note = f"Could not revoke server-side: {exc}"

    removed = store.delete(provider, email)

    if not revoke:
        note = note or (
            "Local credentials removed. The grant likely still exists provider-side; "
            "pass revoke=true to also revoke it."
        )
    elif revoked:
        note = note or "Revoked with the provider and removed locally."
    elif provider == "microsoft":
        note = note or (
            "Local credentials removed. Microsoft has no programmatic per-app revoke for "
            "public clients -- remove access manually at https://myaccount.microsoft.com/privacy "
            "or https://account.live.com/consent/Manage."
        )
    else:
        note = note or "Local credentials removed; server-side revoke was not confirmed."

    return {"removed": removed, "revoked": revoked, "note": note}


def account_id(provider: str, email: str) -> str:
    """Return the API path segment pair identifying an account."""
    return f"{provider}/{urllib.parse.quote(email, safe='')}"
