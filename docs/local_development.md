# Local Development Setup

## Prerequisites

- Python 3.9 or newer
- Nothing else -- no database, no reverse proxy, no container runtime needed
  to develop or run the service
- A Google OAuth client and a Microsoft OAuth client of your own. Neither is
  shipped in the source tree. See [providers.md](providers.md)

## Setup

```bash
# 1. Clone and install in editable mode (gives you a `ccd` command on PATH
#    that re-reads the source tree on every run)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. Point config/token storage at this checkout, so it doesn't touch your
#    real ~/.config
export CCD_CONFIG_DIR=$(pwd)/.ccd-config

# 3. Your OAuth clients. Put them in the untracked `env` file at the repo
#    root (.gitignore has /env) and source it -- never in ccd/client_config.py.
cat > env <<'ENVEOF'
export CCD_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
export CCD_GOOGLE_CLIENT_SECRET=GOCSPX-...
export CCD_MS_CLIENT_ID=00000000-0000-0000-0000-000000000000
ENVEOF

set -a; . ./env; set +a
```

`env` is deliberately untracked and holds a live client secret. Back it up
somewhere you can restore it from -- nothing in the repo can regenerate it.

## Running the service

```bash
ccd serve                       # 127.0.0.1:8080
ccd serve --listen 0.0.0.0:9000 # or set CCD_LISTEN
```

It prints its base URL, the Google redirect URI to register, and -- on the
very first start -- the generated API key. After that the key lives in
`$CCD_CONFIG_DIR/api_key`:

```bash
export CCD_API_KEY=$(cat "$CCD_CONFIG_DIR/api_key")
```

For local Google logins, register `http://127.0.0.1:8080/oauth/callback` as
an authorized redirect URI on your Web-application client. Google accepts
`http` on loopback addresses, so no TLS is needed to develop.

To reproduce the embedded-behind-a-prefix shape without a proxy, set
`CCD_BASE_URL=https://voice.example.test/ccd` and watch the generated URLs
change -- routing is unaffected, which is the point.

## Sanity-checking changes

There is no test suite. Two checks, both of which CI also runs:

```bash
python3 -m py_compile ccd/*.py providers/*.py tools/*.py
pip install pyyaml                  # development dependency, check script only
python3 tools/check_openapi.py
```

The second compares `docs/openapi.yaml` against the `ROUTES` table in
`ccd/server.py` in both directions. **Adding, renaming or removing a route
means editing `docs/openapi.yaml` in the same commit** -- the spec is
hand-written, the service does not serve it, and this check is the only thing
keeping it true.

## Exercising the API

```bash
KEY=$(cat "$CCD_CONFIG_DIR/api_key")
A="Authorization: Bearer $KEY"

curl -s localhost:8080/healthz
curl -s -H "$A" localhost:8080/api/accounts

# Start a login; poll until it finishes.
curl -s -H "$A" -H 'Content-Type: application/json' \
     -d '{"provider":"google"}' localhost:8080/api/login
curl -s -H "$A" localhost:8080/api/login/<login_id>

# Downloads need no key -- the token in the path is the credential.
curl -sO localhost:8080/d/<token>/contacts.csv
```

Negative cases worth re-checking after touching the router: no key and a
wrong key both give `401`; an unknown download token gives a flat `404` with
no hint about why; an unknown account gives `404` with `"code":"no_accounts"`.

## Exercising the CLI

Every command except `serve` is an HTTP client, so point it at your running
service and go:

```bash
export CCD_URL=http://127.0.0.1:8080
export CCD_API_KEY=$(cat "$CCD_CONFIG_DIR/api_key")

ccd list
ccd status                              # exits 2 with nothing linked
ccd login --provider google             # prints a URL, then polls
ccd login --provider microsoft          # prints a device code, then polls
ccd urls --all
ccd download --type contacts --account you@example.com
ccd download --type contacts --all --output ./exports/
ccd download --type calendar --account you@example.com --output -
ccd rotate-token --account you@example.com
ccd logout --account you@example.com --revoke
```

Exit codes are part of the contract: `2` no/ambiguous account, `3` the
refresh token is dead, `4` the provider's API failed. Force a `3` by editing
a stored `refresh_token` to garbage and running `ccd status`.

## Testing the two OAuth flows without real user data

Both flows need a real Google or Microsoft account to complete end to end --
there is no sandbox or mock mode. A throwaway personal account is enough.

- **Google:** `ccd login --provider google` (or `POST /api/login`), open the
  URL, approve. The browser lands on the service's own `/oauth/callback`,
  which shows a short result page; the CLI's poll flips to `done` a moment
  later. If consent fails with `redirect_uri_mismatch`, the URI the service
  printed at startup is not the one registered in Google Cloud.
- **Microsoft:** `ccd login --provider microsoft`, open
  <https://microsoft.com/devicelogin> on any device, type the printed code.
  The service polls Microsoft on a background thread; the flow is bounded by
  the code's own ~15 minute expiry.

Pending logins live only in the service's memory. Restarting `ccd serve`
mid-login cancels it -- the poll then returns `404`, which is the expected
behaviour, not a bug to fix.

Every stored account file lives under `$CCD_CONFIG_DIR/accounts/` as
`0600`-permission JSON (see `ccd/store.py`); inspect it directly while
debugging, but never commit or paste its contents anywhere. The
`refresh_token` field is equivalent to a password for that account's
contacts and calendar, and `download_token` is a password for its downloads.
