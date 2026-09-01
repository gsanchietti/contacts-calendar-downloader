# Contacts & Calendar Downloader (ccd)

A local command-line tool that downloads **your own** contacts and calendar
events from **Google** and **Microsoft** (Outlook/Office 365) via OAuth 2.0,
and writes them out as CSV, JSON, or ICS.

There is no server and no shared database. `ccd` runs entirely on your own
machine (typically a headless box you control via SSH); OAuth tokens are
written to a local, `0600`-permission file under your config directory and
never transmitted anywhere except directly to Google/Microsoft's own APIs.
Multiple Google and/or Microsoft accounts can be linked side by side.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

This installs a `ccd` console script. Python 3.9+ is required.

## Commands

```
ccd login    --provider {google,microsoft}
ccd list     [--json]
ccd status   [--account EMAIL] [--json]
ccd download --type {contacts,calendar} [--format {csv,json}]
             [--account EMAIL | --all] [--output PATH] [--page-size N]
ccd logout   (--account EMAIL | --all) [--revoke] [--yes]
```

- **`login`** links a Google or Microsoft account interactively (see below).
- **`list`** shows every linked account and its token expiry.
- **`status`** shows expiry *and* makes one live, cheap API call to prove
  the stored token still actually works.
- **`download`** fetches contacts (CSV or JSON) or calendar events (always
  ICS) for one account, or every linked account with `--all`. Default
  output filenames are written to the current directory:
  `contacts_<email>.csv`, `contacts_<email>.json`, `calendar_<email>.ics`.
  Pass `--output -` to write to stdout instead.
- **`logout`** deletes the local credential file for an account. Add
  `--revoke` to also ask the provider to revoke the grant (Google supports
  this directly; Microsoft public clients don't expose a programmatic
  revoke, so `ccd` prints where to remove access manually).

## Logging in

### Google

Google's device-code flow doesn't support the contacts/calendar scopes this
tool needs, so Google login uses an authorization-code + PKCE flow with a
redirect. Nothing listens on that redirect: `ccd` runs on a server and your
browser does not, so after consent you copy the resulting URL and paste it
into the terminal.

First set the OAuth client -- none is shipped with the tool, see
[docs/providers.md](docs/providers.md):

```bash
export CCD_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
export CCD_GOOGLE_CLIENT_SECRET=GOCSPX-...
```

```
$ ccd login --provider google
Open this URL in a browser and sign in / grant access:

  https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=http%3A%2F%2F127.0.0.1%3A43217&response_type=code&...

After you approve, the browser will redirect to
http://127.0.0.1:43217/... and show a "This site can't be reached" (or
similar connection-refused) error page. That is expected -- nothing is
listening on that port. Copy the full URL from the address bar and paste it
below.

Paste the redirected URL (or just the 'code' value): http://127.0.0.1:43217/?state=xyz&code=4/0AVGz...

Linked google account: alice@gmail.com
```

If whoever deployed this also set `CCD_GOOGLE_REDIRECT_URI` (or `redirect_uri`
in `client_config.json`), the browser lands on their callback page instead of
that error page, with a button to copy the same value. Same paste, friendlier
landing. Operators: see
[docs/providers.md](docs/providers.md#optional-host-a-callback-page).

### Microsoft

Microsoft's device-code flow works fine with the scopes needed here, so
this one is the classic "go to a URL, type a code" flow -- run it on your
headless machine, complete it on your phone or any other browser.

```
$ ccd login --provider microsoft
To sign in, use a web browser to open the page https://microsoft.com/devicelogin
and enter the code ABCD1234 to authenticate.

Linked microsoft account: alice@outlook.com
```

## Example session

```bash
$ ccd list
No accounts are linked. Run 'ccd login --provider google' or 'ccd login --provider microsoft' first.

$ ccd login --provider google
...

$ ccd status --account alice@gmail.com
google     alice@gmail.com                 expires in 3599s            live-check: ok

$ ccd download --type contacts --account alice@gmail.com
Wrote /home/alice/contacts_alice@gmail.com.csv

$ ccd download --type calendar --account alice@gmail.com --output -
BEGIN:VCALENDAR
...
```

## Running under Podman

`Containerfile` builds a minimal, non-root image that runs `ccd` directly
(no HTTP server). Mount a volume at `/data` so linked accounts survive
container recreation:

```bash
podman build -t ccd -f Containerfile .

podman volume create ccd-data

# Interactive: login needs to read your pasted URL / device code from stdin
podman run --rm -it -v ccd-data:/data ccd login --provider google
podman run --rm -it -v ccd-data:/data ccd login --provider microsoft

# Non-interactive: everything else
podman run --rm -v ccd-data:/data -v "$PWD/out:/out" ccd \
  download --type contacts --all --output /out
```

## Automating with cron

Once an account is linked, downloads are non-interactive (tokens refresh
automatically), so a cron entry works fine:

```cron
# Every night at 02:15, export contacts and calendar for every linked
# account into ~/backups, using the podman volume created above.
15 2 * * * podman run --rm -v ccd-data:/data -v /home/alice/backups:/out ccd download --type contacts --all --output /out >> /home/alice/backups/ccd.log 2>&1
20 2 * * * podman run --rm -v ccd-data:/data -v /home/alice/backups:/out ccd download --type calendar --all --output /out >> /home/alice/backups/ccd.log 2>&1
```

If a refresh token has been revoked or expired, `download` exits with code
3 (`AuthExpiredError`) and prints which account needs `ccd login` run again
-- worth alerting on in whatever wraps the cron job.

## Documentation

- **[Provider Setup](docs/providers.md)** -- registering the Google and
  Microsoft OAuth clients (operator-side, one-time)
- **[Local Development](docs/local_development.md)** -- building and
  testing `ccd` from source

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.
