# Provider Setup (operator guide)

`ccd` ships with a built-in Google OAuth client and expects you to supply
your own Microsoft (Entra ID) client. This is a one-time, per-deployment
setup done by whoever builds/distributes the CLI, not by each end user --
end users only ever run `ccd login`.

If you're just building `ccd` for yourself from this repo with the values
already in `ccd/client_config.py`, you can skip straight to
[local_development.md](local_development.md). Read this doc if you need to
register your own OAuth clients (e.g. you forked the project, or the
embedded Google client is unavailable to you).

## Why native-app OAuth, and why the two providers differ

`ccd` runs on a headless machine with no browser and no way to receive an
inbound HTTP redirect. Both providers support "installed app" flows for
exactly this case, but Google and Microsoft diverge in one important way:

- **Google's device-code flow (RFC 8628) does not support the scopes this
  tool needs.** Google only allows a short allowlist of scopes over device
  flow (`email`, `openid`, `profile`, `drive.appdata`, `drive.file`, and a
  couple of YouTube scopes) -- `contacts.readonly` and `calendar.readonly`
  are refused. So Google logins use the authorization-code + PKCE flow with
  a redirect URI instead. Nothing listens on it: `ccd` runs on a server, so
  the browser is always on some other machine and could never reach a port
  this process opened. After consent the user copies the URL out of their
  browser and pastes it into the terminal. By default that URL is a
  `http://127.0.0.1:<port>` address whose connection-refused page still
  carries the code in the address bar; registering a hosted callback page
  (see below) replaces that browser error with a real page. This is the same
  approach used by `gcloud auth login` and other CLI tools that need Google
  scopes device flow can't grant.
- **Microsoft Graph's `Contacts.Read` / `Calendars.Read` scopes work fine
  over the device-code flow**, so Microsoft logins use RFC 8628 directly via
  MSAL: `ccd` prints a URL and a short code, the user enters them on any
  device, and MSAL polls in the background until they finish.

## Google Cloud Setup

### Prerequisites

- A Google Cloud project (billing not required for these APIs' quotas at
  small scale, but Google may still ask you to enable billing on the
  project)

### Step-by-step

1. **Create or choose a project** at the
   [Google Cloud Console](https://console.cloud.google.com/).

2. **Enable APIs:** *APIs & Services → Library* -- enable **Google People
   API** and **Google Calendar API**.

3. **Configure the OAuth consent screen:** *APIs & Services → OAuth consent
   screen*. Choose **External** audience, fill in the app name and support
   email.

4. **Request the sensitive scopes:** *Data access → Add or remove scopes*,
   add:
   - `https://www.googleapis.com/auth/contacts.readonly`
   - `https://www.googleapis.com/auth/calendar.readonly`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `openid`

   `contacts.readonly` and `calendar.readonly` are **sensitive scopes**.
   While the app is in "Testing" mode you can use them with accounts you
   explicitly add under **Audience → Test users**, with no review needed.
   To let arbitrary users run `ccd login` against your client, Google
   requires you to submit the app for **verification** (including the
   sensitive-scope justification and, likely, a demo video) before moving
   it to "In production". Budget real time for this if you're distributing
   `ccd` publicly.

5. **Create the OAuth client:** *APIs & Services → Credentials → Create
   Credentials → OAuth client ID*. Application type: **Desktop app** (not
   "Web application" -- there is no web server here, and a Desktop client is
   the type Google issues for exactly this native-app + loopback pattern).
   Name it however you like.

6. **Hand the client ID and secret to the CLI.** They are deliberately not
   checked into this repository, so `ccd login --provider google` fails with
   a hint until you supply them, either through the environment:

   ```bash
   export CCD_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
   export CCD_GOOGLE_CLIENT_SECRET=GOCSPX-...
   ```

   or through `client_config.json` in the config directory (see that file's
   docstring for the exact shape). In a container, pass them with `-e`, or
   mount a config directory that contains the JSON file.

   No redirect URI needs to be registered: Desktop-app clients accept any
   `http://127.0.0.1:<port>/*` loopback redirect automatically.

### Optional: host a callback page

By default users land on a browser connection-error page after consent and
copy the URL out of it. It works, but it looks like a failure. You can
replace that with a page you host. The paste step stays either way -- the
CLI is on a server and the browser is not, so nothing can hand the code over
automatically.

1. Publish [`oauth_callback.html`](oauth_callback.html) from this repository
   at a stable https URL on a domain you own -- static hosting only
   (GitHub Pages, Cloudflare Pages, an Nginx `root`). No backend, no
   database, nothing to keep running.

2. In the Google Cloud console, create a **second** OAuth client of type
   **Web application** in the same project, with that URL as an authorized
   redirect URI. Google rejects https redirect URIs on Desktop-app clients,
   which is why this cannot reuse the client from step 5 above. Add the
   domain to the project's authorized domains.

3. Ship the new client and the URL to your users, via environment:

   ```bash
   export CCD_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
   export CCD_GOOGLE_CLIENT_SECRET=GOCSPX-...
   export CCD_GOOGLE_REDIRECT_URI=https://example.org/ccd/callback
   ```

   or in `client_config.json` in each user's config directory:

   ```json
   {"google": {"client_id": "...", "client_secret": "...",
               "redirect_uri": "https://example.org/ccd/callback"}}
   ```

Setting `redirect_uri` changes nothing about how a user completes a login;
it only changes what page they copy from.

**What this does and does not change about the trust model.** The page is
static and makes no network calls: the authorization code reaches only the
user's browser and, from there, their own terminal. It never becomes a
service holding anyone's tokens -- do not "improve" it into one by having it
POST the code somewhere to complete the exchange, which is exactly the
multi-tenant token database this tool was rewritten to remove. Two real
caveats remain:

- The code appears in the query string of a request to *your* web server, so
  it lands in its access log. Turn off query-string logging for that path.
  Exposure is limited by design: `ccd` uses PKCE, so a code is unusable
  without the verifier that never leaves the user's machine, and codes are
  single-use with a short lifetime.
- A Web-application client secret is confidential in Google's model, but it
  is shipped to users here and therefore is not. PKCE is what actually
  protects the exchange. See the next section.

### About that client secret

Desktop OAuth clients still receive a "client secret" from Google, but it
is **not confidential** once you distribute the program: there is no way for
a program running on someone else's machine to keep an embedded secret. This
is documented behavior, not an oversight -- see
[RFC 8252 §8.5](https://www.rfc-editor.org/rfc/rfc8252#section-8.5)
("Native apps... are classified as public clients... the client
`client_secret` cannot be treated as confidential"). Google's protections
here are the consent screen and per-app rate limits, not secrecy of this
value; PKCE is what protects an individual authorization.

So treat it as low-sensitivity, but still do not commit it: a value in a
public source tree is one nobody can rotate without a release, and it trips
secret scanning on every push. Keep it in the environment or in
`client_config.json`, which `.gitignore` already excludes.

## Microsoft Entra ID (Azure AD) Setup

### Prerequisites

- Access to the [Entra admin center](https://entra.microsoft.com/) (or the
  classic [Azure Portal](https://portal.azure.com/) → App registrations)

### Step-by-step

1. **Register an application:** *App registrations → New registration*.
   - **Supported account types:** choose **"Accounts in any organizational
     directory and personal Microsoft accounts"** (multi-tenant + personal)
     so `ccd login --provider microsoft` works for any user's own
     account, not just one tenant.
   - **Redirect URI:** leave it blank, or add a **Mobile and desktop
     applications** platform entry using the default MSAL redirect
     (`https://login.microsoftonline.com/common/oauth2/nativeclient`). The
     device-code flow does not use a redirect URI at all, but MSAL's
     platform configuration expects one of the native platforms to be
     present.
   - Click **Register**.

2. **Allow public client flows:** *Authentication* page → under **Advanced
   settings**, set **"Allow public client flows"** to **Yes**, then Save.
   This is required for the device-code grant; without it Entra rejects
   `initiate_device_flow`.

3. **Add API permissions:** *API permissions → Add a permission → Microsoft
   Graph → Delegated permissions*:
   - `User.Read`
   - `Contacts.Read`
   - `Calendars.Read`
   - `offline_access` (needed for refresh tokens; usually pre-granted)

   No admin consent is required for these -- they're all standard delegated
   permissions a user can consent to for themselves during `ccd login`.

4. **Do not create a client secret.** This is a **public client**: it has
   no secret, by design (that's what "Allow public client flows" means).
   `ccd`'s device-code and refresh-token requests never send one.

5. **Copy the Application (client) ID** into `ccd/client_config.py`
   (`_EMBEDDED_MS_CLIENT_ID`), or set `CCD_MS_CLIENT_ID`, or put it in
   `client_config.json`. The authority defaults to
   `https://login.microsoftonline.com/common` (works for both
   organizational and personal accounts); override with `CCD_MS_AUTHORITY`
   if you registered a single-tenant app instead.
