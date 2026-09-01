# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A local, single-user CLI named `ccd` that downloads **your own** contacts and calendar events from Google or Microsoft (OAuth 2.0) and writes them as CSV/JSON/ICS. It runs entirely on the machine you invoke it from -- no server, no shared database, no multi-tenant anything. OAuth tokens live in one `0600` JSON file per linked account under a local config directory and are never sent anywhere except directly to the provider's own token/API endpoints.

This used to be a Flask HTTP service with a shared PostgreSQL database of every user's tokens. That design is gone entirely -- do not reintroduce Flask, Postgres, Prometheus, Traefik, or server-rendered templates. If you're looking at old commit history and see references to those, they describe a deleted implementation, not something to restore or interoperate with.

## Running locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

ccd login --provider google       # or microsoft
ccd list
ccd status --account you@example.com
ccd download --type contacts --account you@example.com
ccd download --type calendar --account you@example.com
ccd logout --account you@example.com
```

There is no test suite. To sanity check changes: `python3 -m py_compile ccd/*.py providers/*.py`. Full command reference and sample terminal output: `README.md`. OAuth client registration (operator-side, one-time): `docs/providers.md`. Dev setup details: `docs/local_development.md`.

## Architecture

The `ccd` package is a thin argparse CLI over a small set of single-purpose modules; `providers/*` stay pure API clients with no knowledge of how they got their credentials.

- **`ccd/cli.py`** -- `argparse` subcommands (`login`, `list`, `status`, `download`, `logout`) and `main(argv) -> int`. Owns account selection (`--account` / `--all` / `--provider` disambiguation), output-path handling for `download`, and translates `CcdError` subclasses into process exit codes at the top level. Calls into `providers/*` for actual API calls and `ccd/serialize.py` to render contact rows.
- **`ccd/store.py`** -- the local file store. `config_root()` resolves `$CCD_CONFIG_DIR` → `$XDG_CONFIG_HOME/contacts-calendar-downloader` → (Windows) `%APPDATA%\contacts-calendar-downloader` → `~/.config/contacts-calendar-downloader`. `accounts_dir()` under it holds one file per account, named `{provider}_{urlencoded email}.json`. `save()` writes atomically via a same-directory temp file opened with `os.O_EXCL, 0o600` then `os.replace()` -- **never** `open()` followed by `chmod()`, which would leave a window where the file is world-readable. `get_access_token(record)` is the single place that decides whether a cached token is still fresh (with a 120s safety margin) or needs a provider refresh; it dispatches to `auth_google.refresh()` / `auth_microsoft.refresh()` (imported inside the function to dodge a circular import) and persists the result.
- **`ccd/auth_google.py`** / **`ccd/auth_microsoft.py`** -- one module per provider, each exposing `login() -> dict`, `refresh(record) -> dict`, `revoke(record) -> bool`. These two flows are deliberately different, and that difference is load-bearing, not accidental:
  - **Google** cannot use the device-code flow here: Google's device flow only allows a short allowlist of scopes (email/openid/profile/drive.appdata/drive.file/youtube*), and refuses `contacts.readonly` / `calendar.readonly`. So Google login is authorization-code + PKCE with **nothing listening on the redirect URI** -- ccd runs on a server, the browser is always on another machine, so no listener could ever be reached. The user copies the post-consent URL out of the browser and pastes it into the CLI. `client_config`'s `redirect_uri` (`CCD_GOOGLE_REDIRECT_URI`) decides where that URL comes from: an operator-hosted **static** page (`docs/oauth_callback.html` -- it must stay static, since a page that POSTs the code anywhere recreates the deleted server-side token store, and a hosted https redirect URI additionally requires a Google client of type "Web application") or, unset, a `http://127.0.0.1:<random port>` address whose connection-refused page carries the code in its address bar. `auth_google.credentials(record)` builds a `google.oauth2.credentials.Credentials` with a **naive UTC** `expiry` (`datetime.utcfromtimestamp`, no tzinfo) because google-auth's internal comparisons assume naive UTC and raise on tz-aware datetimes.
  - **Microsoft** Graph's `Contacts.Read`/`Calendars.Read` scopes work fine over the device-code flow (RFC 8628), so `auth_microsoft.login()` just uses `msal.PublicClientApplication.initiate_device_flow()` / `acquire_token_by_device_flow()` directly -- no loopback trick needed. MSAL rejects the OIDC reserved scopes (`openid`, `profile`, `offline_access`) in its flow builders, so only `["User.Read", "Contacts.Read", "Calendars.Read"]` is passed to MSAL even though the full scope list is what gets persisted in the account record. Entra rotates refresh tokens on every use, so `refresh()` always persists whatever refresh token comes back, when one comes back. There's no programmatic per-app revoke for Microsoft public clients, so `revoke()` always returns `False` and `ccd logout --revoke` prints where the user can remove access by hand.
  - `errors.AuthExpiredError` is a refresh-time failure only -- `login()` failures raise plain `CcdError`. Both `refresh()` functions raise `AuthExpiredError` specifically on an `invalid_grant` response, which `ccd/cli.py`'s top-level handler turns into exit code 3 with a message telling the user which `ccd login --provider X` to re-run.
- **`ccd/client_config.py`** -- where OAuth client identifiers live: no Google client at all (embedding one puts an unrotatable credential in the source tree and trips GitHub push protection -- `require("google")` fails loudly instead) and an embedded Microsoft public client id (public clients have no secret), overridable via `CCD_GOOGLE_CLIENT_ID`/`CCD_GOOGLE_CLIENT_SECRET`/`CCD_MS_CLIENT_ID`/`CCD_MS_AUTHORITY` env vars or a `client_config.json` in the config root. `require(provider)` is what `auth_google.py`/`auth_microsoft.py` call to fail loudly (as `CcdError`) if nothing is configured.
- **`ccd/serialize.py`** -- `CONTACT_HEADERS`, `contacts_to_csv()`, `contacts_to_json()`. The only place that knows the on-disk contact schema; provider modules just need to return dicts keyed by those header names via their `extract_contact_row()`.
- **`ccd/errors.py`** -- `CcdError` (exit 1) and three subclasses with fixed exit codes the CLI relies on: `NoAccountsError` (2, no/ambiguous account selection), `AuthExpiredError` (3, refresh failed, re-login needed), `ProviderApiError` (4, the provider's data API itself rejected/failed a request, as opposed to an auth problem).
- **`providers/google.py`** / **`providers/microsoft.py`** -- pure API clients, no auth logic and no knowledge of `ccd/store.py`. Given an already-valid `Credentials` object (Google) or access-token dict (Microsoft), they fetch/paginate contacts, build an ICS calendar via `icalendar`, and map the provider's native contact shape to the common `CONTACT_HEADERS` row via `extract_contact_row()`. Kept separate from `ccd/auth_*.py` so the API-calling code has zero dependency on how a token was obtained -- `ccd/cli.py` is the only place that wires the two together.

**Adding a third provider**: add `ccd/auth_<name>.py` (with `login`/`refresh`/`revoke`, matching the other two by convention -- there's no abstract base class), a `providers/<name>.py` API client, a client-config section in `ccd/client_config.py`, and wire the provider name into `ccd/cli.py`'s `PROVIDERS` tuple and the `_fetch_contacts_rows`/`_fetch_calendar_ics`/`_live_check` dispatch branches.

**Account record schema** (one JSON file per account, `0600`, under `accounts_dir()`):

```json
{"provider": "google", "email": "a@b.c", "access_token": "...", "refresh_token": "...",
 "expires_at": 1717192800.0, "scopes": ["..."], "created_at": 1717100000.0, "updated_at": 1717100000.0}
```

Never print `access_token` or `refresh_token` anywhere -- not in `--json` output, not in error messages. `ccd/cli.py`'s `_public_view()` is what strips them for `list --json`.

## Deployment

`Containerfile` builds a minimal non-root image (`ENV CCD_CONFIG_DIR=/data`, `VOLUME /data`, `ENTRYPOINT ["python", "-m", "ccd"]`) with no WSGI server, no Postgres container, no Traefik -- `podman run --rm -it -v ccd-data:/data ccd login --provider google` is the whole deployment story. See `README.md` for the Podman and cron usage patterns.

## Constraints for this codebase

- Python 3.9+ compatible: use `typing.Optional`/`List`/`Dict`, not the `X | None` syntax.
- No dependencies beyond `requirements.txt` (`google-api-python-client`, `google-auth`, `google-auth-httplib2`, `msal`, `requests`, `icalendar`, `python-dateutil`).
- Import `google.*`/`msal` lazily, inside the functions that need them, not at module top level -- `ccd --help` / `ccd list` / `ccd status` (with zero accounts) must work even if those packages aren't installed yet.
- Plain `print()` for user-facing output; no logging framework.
