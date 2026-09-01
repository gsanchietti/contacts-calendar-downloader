# Local Development Setup

## Prerequisites

- Python 3.9 or newer
- Nothing else -- there's no database, no server, no Docker required to
  develop or run `ccd`
- If you need to point at your own OAuth clients instead of the ones baked
  into `ccd/client_config.py`, see [providers.md](providers.md)

## Setup

```bash
# 1. Clone and install in editable mode (gives you a `ccd` command on PATH
#    that re-reads the source tree on every run)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. (optional) point ccd's config/token storage somewhere scoped to this
#    checkout, so it doesn't touch your real ~/.config
export CCD_CONFIG_DIR=$(pwd)/.ccd-config

# 3. (optional) override the embedded OAuth client, e.g. while testing a
#    fresh Entra ID registration
export CCD_MS_CLIENT_ID=your-app-registration-client-id
```

## Sanity-checking changes

There is no test suite. To sanity check changes:

```bash
python3 -m py_compile ccd/*.py providers/*.py
```

## Exercising each command

```bash
# No accounts linked yet: everything reports that clearly.
ccd list
ccd status                              # exits 2 (NoAccountsError)
ccd download --type contacts            # exits 2 (NoAccountsError)

# Link an account. This is interactive -- see the two flows below.
ccd login --provider google
ccd login --provider microsoft

ccd list
ccd list --json

# Confirm the stored token actually works against the provider.
ccd status --account you@example.com

# Download.
ccd download --type contacts --account you@example.com            # -> contacts_you@example.com.csv
ccd download --type contacts --account you@example.com --format json
ccd download --type calendar --account you@example.com            # -> calendar_you@example.com.ics
ccd download --type contacts --all --output ./exports/            # one file per linked account
ccd download --type contacts --account you@example.com --output -  # to stdout

# Remove a linked account.
ccd logout --account you@example.com          # deletes the local file only
ccd logout --account you@example.com --revoke  # also revokes the grant with the provider
```

## Testing the two OAuth flows without real user data

Both flows require a real Google or Microsoft account to complete end to
end (there's no sandbox/mock mode). A throwaway personal Google or
Microsoft account is enough:

- **Google:** export `CCD_GOOGLE_CLIENT_ID` / `CCD_GOOGLE_CLIENT_SECRET`
  first -- no client is shipped in the source tree (see
  `docs/providers.md`). Then run `ccd login --provider google`, open the
  printed URL, sign in, approve consent, and watch the browser fail to load
  `http://127.0.0.1:<port>/...`. That failure is expected -- copy the full
  address-bar URL and paste it back into the terminal prompt. Set
  `CCD_GOOGLE_REDIRECT_URI` to test the hosted-callback variant, which needs
  a Web-application client (again, `docs/providers.md`).
- **Microsoft:** run `ccd login --provider microsoft`, open
  <https://microsoft.com/devicelogin> (or the URL MSAL prints) on any
  device, and type the printed code. `acquire_token_by_device_flow` blocks
  until you finish (or the code expires).

Every stored account file lives under `$CCD_CONFIG_DIR/accounts/` as
`0600`-permission JSON (see `ccd/store.py`); inspect it directly while
debugging, but never commit or paste its contents anywhere -- the
`refresh_token` field is equivalent to a password for that account's
contacts and calendar.
