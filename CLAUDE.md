# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-host HTTP service named `ccd` that links **your own** Google or Microsoft accounts over OAuth 2.0 and publishes each linked account's contacts and calendar at a stable secret URL (CSV/JSON/ICS). A `ccd` CLI drives the same API and is a pure client of it -- it holds no tokens, reads no account files and talks to no provider.

It is deliberately **not multi-tenant**. There are no user accounts, no sign-up, no shared database: OAuth tokens live in one `0600` JSON file per linked account under a local config directory and are never sent anywhere except the provider's own token/API endpoints. It has been a Flask service with a shared PostgreSQL token store in the past -- that is what "not multi-tenant" is guarding against. Do not reintroduce Flask, Postgres, Prometheus, Traefik config, or server-rendered templates; old commits referencing those describe a deleted implementation.

It is also not an NS8 module and must not grow an `imageroot/`. It is embedded as a container inside other modules (NethVoice, WebTop), each running its own instance with its own volume and its own OAuth clients; `docs/nethserver8.md` is the runbook for that and is the deliverable NS8 gets from this repo.

## Running locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

export CCD_CONFIG_DIR=$(pwd)/.ccd-config
export CCD_GOOGLE_CLIENT_ID=... CCD_GOOGLE_CLIENT_SECRET=...
ccd serve                                    # prints the API key on first start

export CCD_API_KEY=$(cat "$CCD_CONFIG_DIR/api_key")
ccd login --provider google                  # or microsoft
ccd list && ccd urls --all
ccd download --type contacts --account you@example.com
ccd logout --account you@example.com
```

There is no test suite. Two checks, both run by `.github/workflows/checks.yml`:

```bash
python3 -m py_compile ccd/*.py providers/*.py tools/*.py
python3 tools/check_openapi.py     # needs PyYAML (dev-only dependency)
```

The API contract is `docs/openapi.yaml` (see below). Command reference and API summary: `README.md`. OAuth client registration (operator-side, per installation): `docs/providers.md`. Dev workflow: `docs/local_development.md`.

## Architecture

Routing, business logic and provider API calls are three separate layers, and the seams are load-bearing: `ccd/server.py` knows HTTP but not OAuth, `ccd/service.py` knows OAuth but not HTTP, `providers/*` know neither.

- **`ccd/server.py`** -- `ThreadingHTTPServer` plus a regex router. Every route is declared once in the module-level **`ROUTES`** tuple (`method`, `path_template`, compiled pattern, handler, `auth`) and nothing is dispatched outside it; `tools/check_openapi.py` reads that table and diffs it against `docs/openapi.yaml`. Owns API-key checking (`hmac.compare_digest`), JSON rendering, and turning `CcdError` subclasses into status codes. `log_message()` rewrites `/d/<token>/` out of every access-log line -- a download path *is* a credential and must never reach the journal. `serve()` sets the module-global `_PORT`, which exists only so outbound URLs can be built; **routing never consults it**. It also installs a SIGTERM handler -- as PID 1 in a container a process gets no default signal disposition, so without it podman/systemd wait out the stop timeout and SIGKILL.
- **`ccd/service.py`** -- all the work, with no request object in sight. Holds the one piece of mutable process state: `_logins`, the pending-login registry. OAuth spans two requests and the bit in between (a PKCE verifier, an MSAL flow) is worthless after a restart, so it is in memory with a 20-minute TTL, not on disk. `public_view()` is the only place an account becomes API output, and it strips `access_token`/`refresh_token`/`download_token`.
- **`ccd/store.py`** -- the file store. `config_root()` resolves `$CCD_CONFIG_DIR` → `$XDG_CONFIG_HOME/contacts-calendar-downloader` → (Windows) `%APPDATA%\...` → `~/.config/...`. `write_private()` writes atomically via a same-directory temp file opened with `os.O_EXCL, 0o600` then `os.replace()` -- **never** `open()` followed by `chmod()`, which leaves a window where the file is world-readable. `get_access_token()` decides whether a cached token is fresh (120s margin) or needs a refresh; it takes a **per-account lock and re-reads the record from disk inside it**, because Entra rotates the refresh token on every use and two concurrent refreshes would leave the loser holding a retired token. `find_by_download_token()` compares with `hmac.compare_digest`.
- **`ccd/auth_google.py`** / **`ccd/auth_microsoft.py`** -- one module per provider, each exposing `start()`, `refresh(record)`, `revoke(record)` and a second-half function. There is no `login()`: the flow spans two HTTP requests, so it is split, and the two splits differ because the providers do:
  - **Google**: `start(redirect_uri, state) -> (auth_url, pending)` then `complete(pending, code) -> record`. Authorization-code + PKCE against the service's own `/oauth/callback`. Google's device flow only allows a short scope allowlist (email/openid/profile/drive.appdata/drive.file/youtube*) and refuses `contacts.readonly` / `calendar.readonly`, so device flow is not an option. The redirect URI is always `{CCD_BASE_URL}/oauth/callback` and is not separately configurable -- one value that can disagree with Google instead of two. It requires a Google client of type **Web application**. `credentials(record)` builds a `google.oauth2.credentials.Credentials` with a **naive UTC** `expiry` (`datetime.utcfromtimestamp`, no tzinfo) because google-auth's internal comparisons assume naive UTC and raise on tz-aware datetimes.
  - **Microsoft**: `start() -> flow` then `wait(flow) -> record`. Graph's `Contacts.Read`/`Calendars.Read` work fine over device-code (RFC 8628), which needs no redirect URI and therefore no per-installation app registration -- worth keeping for that reason alone. `wait()` blocks up to 15 minutes inside MSAL, so `service.start_login()` runs it on a daemon thread. MSAL rejects the OIDC reserved scopes (`openid`, `profile`, `offline_access`) in its flow builders, so only `["User.Read", "Contacts.Read", "Calendars.Read"]` reaches MSAL even though the full list is persisted. Entra rotates refresh tokens, so `refresh()` always persists whatever comes back. There is no programmatic per-app revoke for public clients, so `revoke()` always returns `False`.
  - Both `complete()`/`wait()` **preserve an existing `download_token`** when re-linking an account, so URLs already handed to other applications survive a re-consent.
  - `errors.AuthExpiredError` is a refresh-time failure only; `start()`/`complete()` failures raise plain `CcdError`. Both `refresh()` functions raise `AuthExpiredError` specifically on `invalid_grant`.
- **`ccd/client_config.py`** -- OAuth client identifiers *and* service configuration. No Google client is embedded (a committed one is unrotatable and trips GitHub push protection -- `require("google")` fails loudly instead); the Microsoft public client id is embedded, since public clients have no secret. `base_url()` normalises `CCD_BASE_URL`, **which may carry a path prefix** (`https://voice.example.com/ccd`) because the service is normally mounted under another module's hostname with the proxy stripping the prefix. It is the only place outbound URLs are built. `ensure_api_key()` returns `(key, created)`, generating one into a `0600` `api_key` file on first start.
- **`ccd/cli.py`** -- argparse over the HTTP API. `_api()` decodes `{"error", "code"}` bodies back into the matching exception class via `errors.from_wire`, which is what keeps exit codes identical to the pre-service CLI. `_resolve_accounts()` does `--account` / `--all` / `--provider` disambiguation against `GET /api/accounts`. `ccd download` fetches the account's published download URL, falling back to the same path on `--url` when the published host is unreachable from here. Only `ccd serve` may import `google.*` / `msal`.
- **`docs/openapi.yaml`** -- the published API contract. Static, hand-written, never served. See the section above.
- **`ccd/serialize.py`** -- `CONTACT_HEADERS`, `contacts_to_csv()`, `contacts_to_json()`. The only place that knows the on-disk contact schema.
- **`ccd/errors.py`** -- `CcdError` and three subclasses, each carrying **both** an `exit_code` and an `http_status`/`wire_code`: `NoAccountsError` (2 / 404 `no_accounts`), `AuthExpiredError` (3 / 409 `auth_expired`), `ProviderApiError` (4 / 502 `provider_api`), `CcdError` (1 / 400 `error`). Keeping both on the class is what lets the CLI round-trip a server error into the right exit code.
- **`providers/google.py`** / **`providers/microsoft.py`** -- pure API clients, no auth logic and no knowledge of the store. Given an already-valid `Credentials` object (Google) or access-token dict (Microsoft), they fetch/paginate contacts, build an ICS calendar via `icalendar`, and map the provider's native shape to a `CONTACT_HEADERS` row via `extract_contact_row()`.

**Adding a third provider**: add `ccd/auth_<name>.py` (matching the other two by convention -- there is no abstract base class), a `providers/<name>.py` API client, a client-config section, and wire the name into `service.PROVIDERS` plus the `_contacts_rows` / `_calendar_ics` / `live_check` / `start_login` dispatch branches.

**Account record schema** (one JSON file per account, `0600`, under `accounts_dir()`):

```json
{"provider": "google", "email": "a@b.c", "access_token": "...", "refresh_token": "...",
 "expires_at": 1717192800.0, "scopes": ["..."], "download_token": "...",
 "created_at": 1717100000.0, "updated_at": 1717100000.0}
```

Records written before the service existed have no `download_token`; `store.ensure_download_token()` backfills one on first read rather than forcing a re-login.

Never emit `access_token` or `refresh_token` anywhere -- not in a response body, not in a log line, not in an error message. `download_token` is equally secret but does appear, by design, inside the URLs in an account's `download` object.

## The API contract lives in `docs/openapi.yaml`

**Read `docs/openapi.yaml` before answering anything about the HTTP API** -- request and response shapes, status codes, which endpoints need the API key, what each error `code` means. It is hand-written OpenAPI 3.1 and it is the source of truth for the contract; do not reconstruct the API by reading handlers when the spec already states it.

It is a **static document**, deliberately: the service does not serve it, there is no `/openapi.json` endpoint, and it is not shipped inside the container image. That is why the runtime needs no YAML parser -- `requirements.txt` has no PyYAML, and adding one for the service would be a regression. PyYAML is a development dependency, used only by `tools/check_openapi.py`.

**Adding, renaming or removing a route**: change `ROUTES` in `ccd/server.py` **and** `docs/openapi.yaml` in the same commit. `tools/check_openapi.py` compares the two sets of `(method, path)` in both directions and checks that `auth=True` routes require `bearerAuth` while public ones carry `security: []`. CI fails otherwise.

## Deployment

`Containerfile` builds a minimal non-root image (`CCD_CONFIG_DIR=/data`, `CCD_LISTEN=0.0.0.0:8080`, `VOLUME /data`, `EXPOSE 8080`, `ENTRYPOINT ["python", "-m", "ccd"]`, `CMD ["serve"]`). Binding `0.0.0.0` inside the container is correct; restricting exposure is the host's job (`-p 127.0.0.1:8080:8080`). See `README.md` for Podman usage and `docs/nethserver8.md` for the NS8 runbook.

## Constraints for this codebase

- Python 3.9+ compatible: use `typing.Optional`/`List`/`Dict`, not the `X | None` syntax.
- No dependencies beyond `requirements.txt` (`google-api-python-client`, `google-auth`, `google-auth-httplib2`, `msal`, `requests`, `icalendar`, `python-dateutil`). The HTTP layer is stdlib on purpose -- the load is a handful of requests, and a framework plus a WSGI server would be more moving parts than the job needs.
- Import `google.*`/`msal` lazily, inside the functions that need them, not at module top level -- `ccd --help` / `ccd list` / `ccd status` must work on a machine where only `requests` is installed.
- Plain `print()` for user-facing output and `print(..., file=sys.stderr)` for service logs (journald reads stderr); no logging framework.
