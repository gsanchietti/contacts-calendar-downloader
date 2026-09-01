# Contacts & Calendar Downloader (ccd)

A small self-hosted service that links **your own** Google and Microsoft
(Outlook/Office 365) accounts over OAuth 2.0 and publishes each linked
account's contacts and calendar at a stable, secret URL -- CSV, JSON or ICS.
A `ccd` command-line client drives the same API.

It is a single-host service, not a multi-tenant one: there is no shared
database, no user accounts and no sign-up. OAuth tokens are written to one
`0600` JSON file per linked account under the config directory and go nowhere
except Google's and Microsoft's own endpoints. Several accounts on either
provider can be linked side by side.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

Python 3.9+ is required. This installs a `ccd` console script.

## Run the service

No OAuth client of either provider is shipped in the source tree, so register
your own first ([docs/providers.md](docs/providers.md)) and keep the values
outside the repo:

```bash
export CCD_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
export CCD_GOOGLE_CLIENT_SECRET=GOCSPX-...
export CCD_MS_CLIENT_ID=00000000-0000-0000-0000-000000000000
ccd serve
```

```
ccd listening on http://127.0.0.1:8080
base URL: http://127.0.0.1:8080
Google redirect URI (register this): http://127.0.0.1:8080/oauth/callback
generated API key: 5yMtUvGxdoAK5Z0aPtap7mzKvW2K5d6LnPN2Ka3aKFg
```

The API key protects `/api/*`. It is generated on first start into `api_key`
in the config directory (mode `0600`); set `CCD_API_KEY` to supply your own.

| Variable | Default | What it does |
|---|---|---|
| `CCD_LISTEN` | `127.0.0.1:8080` | Address to bind. |
| `CCD_BASE_URL` | `http://127.0.0.1:<port>` | Externally visible base, **including any path prefix**. Every URL the service hands out is built from it, and it must match the redirect URI registered with Google. |
| `CCD_API_KEY` | generated | Bearer key for `/api/*`. |
| `CCD_CONFIG_DIR` | `~/.config/contacts-calendar-downloader` | Where accounts and the API key live. |
| `CCD_GOOGLE_CLIENT_ID` / `CCD_GOOGLE_CLIENT_SECRET` | — | Required to link a Google account. |
| `CCD_MS_CLIENT_ID` | — | Required to link a Microsoft account. Public client, so there is no secret. |
| `CCD_MS_AUTHORITY` | `https://login.microsoftonline.com/common` | Override only for a single-tenant Entra app. |

## The API

Full contract: [`docs/openapi.yaml`](docs/openapi.yaml). It is documentation,
not a runtime artifact -- the service does not serve it and the image does not
ship it.

```
POST   /api/login                                     start linking an account
GET    /api/login/{login_id}                          poll until done or error
GET    /api/accounts                                  list linked accounts
GET    /api/accounts/{provider}/{email}               one account
GET    /api/accounts/{provider}/{email}/status        live check against the provider
POST   /api/accounts/{provider}/{email}/rotate-token  new download URLs, old ones die
DELETE /api/accounts/{provider}/{email}[?revoke=true] unlink

GET    /oauth/callback?code=&state=                   where Google sends the browser
GET    /d/{download_token}/contacts.csv               public by secret URL
GET    /d/{download_token}/contacts.json
GET    /d/{download_token}/calendar.ics
GET    /healthz
```

Linking an account is start-then-poll, and the two providers answer the start
differently on purpose:

```console
$ curl -s -X POST localhost:8080/api/login -H "Authorization: Bearer $KEY" \
       -H 'Content-Type: application/json' -d '{"provider":"google"}'
{
  "login_id": "us4AdAmCCaAHVm1cT6iXbx5nk2LNeeQf",
  "provider": "google",
  "kind": "redirect",
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "expires_in": 1200
}
```

Google returns `kind: "redirect"` -- open `authorization_url` in a browser.
Microsoft returns `kind: "device"` with a `verification_uri` and a `user_code`
for the user to type. Either way, poll `GET /api/login/{login_id}` until it
reports `done` (with the linked `account`) or `error`.

Errors are `{"error": "...", "code": "..."}` where `code` is one of
`error`, `no_accounts`, `auth_expired` (the refresh token is dead -- link the
account again), `provider_api` (Google or Microsoft failed the request) or
`internal`.

### Download URLs are credentials

Each linked account gets a 256-bit `download_token` that stays the same for
the life of the account, and three URLs built from it. They take **no API
key** -- the token in the path is the credential, which is what makes them
usable as a plain link from another application, a cron job or a calendar
subscription. Anyone holding one can read that account's entire address book
and calendar. Treat them like passwords: do not log them, do not put them in
a ticket, and rotate one with `POST .../rotate-token` if it leaks.

## The CLI

Every command except `serve` is a client of the API above, so `--url`
(`CCD_URL`, default `http://127.0.0.1:8080`) and `--api-key` (`CCD_API_KEY`)
apply to all of them.

```
ccd serve        [--listen HOST:PORT]
ccd login        --provider {google,microsoft}
ccd list         [--json]
ccd status       [--account EMAIL] [--provider P] [--json]
ccd urls         [--account EMAIL | --all] [--json]
ccd rotate-token [--account EMAIL | --all]
ccd download     --type {contacts,calendar} [--format {csv,json}]
                 [--account EMAIL | --all] [--output PATH]
ccd logout       (--account EMAIL | --all) [--revoke] [--yes]
```

```console
$ ccd login --provider google
Open this URL in a browser and sign in / grant access:

  https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=...

Waiting for you to finish...

Linked google account: alice@gmail.com

Download URLs (secret -- anyone holding one can read this account's data):
  contacts_csv   http://127.0.0.1:8080/d/PAe38pUdlPOsKpV.../contacts.csv
  contacts_json  http://127.0.0.1:8080/d/PAe38pUdlPOsKpV.../contacts.json
  calendar_ics   http://127.0.0.1:8080/d/PAe38pUdlPOsKpV.../calendar.ics

$ ccd status
google     alice@gmail.com                  expires in 3599s     live-check: ok

$ ccd download --type contacts --account alice@gmail.com
Wrote /home/alice/contacts_alice@gmail.com.csv
```

`ccd login --provider microsoft` prints a short URL and a code instead; the
service polls Microsoft in the background until you finish.

Exit codes: `0` success, `1` general failure, `2` no such (or ambiguous)
account, `3` credentials can no longer be refreshed -- link the account
again, `4` the provider's API failed the request.

## Running under Podman

```bash
podman build -t ccd -f Containerfile .
podman volume create ccd-data

podman run -d --name ccd \
  -p 127.0.0.1:8080:8080 \
  -v ccd-data:/data \
  -e CCD_BASE_URL=https://example.org/ccd \
  -e CCD_GOOGLE_CLIENT_ID=... \
  -e CCD_GOOGLE_CLIENT_SECRET=... \
  ccd
```

The image runs as a non-root user and stores everything under `/data`. It
binds `0.0.0.0:8080` *inside* the container; restricting exposure is the
host's job, which is what `-p 127.0.0.1:8080:8080` above does.

Put TLS in front of it before exposing it beyond loopback -- OAuth
authorization codes and download tokens travel over these URLs.

## Automating downloads

Once an account is linked, its download URLs are stable and need no
interaction, so anything that can fetch a URL will do:

```cron
15 2 * * * curl -fsS -o ~/backups/contacts.csv "https://example.org/ccd/d/<token>/contacts.csv"
20 2 * * * curl -fsS -o ~/backups/calendar.ics "https://example.org/ccd/d/<token>/calendar.ics"
```

A URL that starts returning `409` means that account's refresh token is gone
and someone has to link it again -- worth alerting on.

## Documentation

- **[Provider Setup](docs/providers.md)** -- registering the Google and
  Microsoft OAuth clients (operator-side, one-time)
- **[NethServer 8 deployment](docs/nethserver8.md)** -- embedding the
  container in a NethVoice or WebTop module
- **[Local Development](docs/local_development.md)** -- building and testing
  from source

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.
