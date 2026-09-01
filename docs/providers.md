# Provider Setup (operator guide)

Registering the OAuth clients `ccd` uses is a one-time job for whoever
deploys the service. End users never see it -- they only ever click through
a consent screen.

Two things are needed: a **Google** client (none is shipped -- see below) and,
optionally, your own **Microsoft** client (a working public one is embedded,
so you can skip that section entirely unless you forked the project or need
a single-tenant app).

## Why the two providers use different flows

- **Google's device-code flow (RFC 8628) does not support the scopes this
  tool needs.** Google only allows a short allowlist of scopes over device
  flow (`email`, `openid`, `profile`, `drive.appdata`, `drive.file`, and a
  couple of YouTube scopes) -- `contacts.readonly` and `calendar.readonly`
  are refused. So Google logins use authorization-code + PKCE with a real
  redirect: the browser lands on the service's own `/oauth/callback`, which
  exchanges the code. This is why the Google client must be registered as a
  **Web application**.
- **Microsoft Graph's `Contacts.Read` / `Calendars.Read` scopes work fine
  over the device-code flow**, so Microsoft logins use RFC 8628 directly via
  MSAL: the service hands back a short URL and a code, the user enters them
  on any device, and MSAL polls in the background until they finish. No
  redirect URI is involved, which means nothing about the Microsoft
  registration changes from one installation to the next.

## Google Cloud Setup

### Prerequisites

- A Google Cloud project (billing not required for these APIs' quotas at
  small scale, but Google may still ask you to enable billing on the
  project)
- The externally visible base URL the service will run on, decided in
  advance -- it is baked into the redirect URI you register.

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
   To let arbitrary users link accounts against your client, Google requires
   you to submit the app for **verification** (including the
   sensitive-scope justification and, likely, a demo video) before moving it
   to "In production". Budget real time for this if the service is going to
   serve people outside your own organisation.

5. **Create the OAuth client:** *APIs & Services → Credentials → Create
   Credentials → OAuth client ID*. Application type: **Web application**
   (not "Desktop app" -- Google rejects https redirect URIs on desktop
   clients, and there is a real web server here now).

6. **Register the redirect URI.** Under *Authorized redirect URIs*, add
   exactly what the service prints at startup:

   ```
   {CCD_BASE_URL}/oauth/callback
   ```

   So `https://voice.example.com/ccd/oauth/callback` for a service embedded
   behind a `/ccd` path prefix, or `http://127.0.0.1:8080/oauth/callback`
   for a plain local one. Google matches this string exactly -- a missing
   path prefix, a stray trailing slash or `http` where you registered
   `https` all produce `redirect_uri_mismatch` at consent time. Add the
   domain under the project's authorized domains as well.

7. **Hand the client id and secret to the service.** They are deliberately
   not checked into this repository, so linking a Google account fails with
   a hint until you supply them:

   ```bash
   export CCD_GOOGLE_CLIENT_ID=...apps.googleusercontent.com
   export CCD_GOOGLE_CLIENT_SECRET=GOCSPX-...
   export CCD_BASE_URL=https://voice.example.com/ccd
   ```

   or through `client_config.json` in the config directory:

   ```json
   {"google": {"client_id": "...", "client_secret": "..."}}
   ```

   In a container, pass them with `-e` or mount a config directory holding
   that file. The redirect URI is **not** configurable separately -- it is
   always `{CCD_BASE_URL}/oauth/callback`, so there is only one value that
   can disagree with Google instead of two.

### About the client secret

The secret is confidential in Google's model for a Web-application client,
and here it genuinely is one: it lives on the server, in the environment or
in a `0600` file, and is never sent to a browser. That is a real improvement
over the previous CLI shape, where the same value shipped to every user and
[RFC 8252 §8.5](https://www.rfc-editor.org/rfc/rfc8252#section-8.5) applied.

It still must not be committed: a value in a public source tree is one nobody
can rotate without a release, and it trips secret scanning on every push.
Keep it in the environment or in `client_config.json`, which `.gitignore`
already excludes. PKCE is used regardless, so an intercepted authorization
code is unusable without the verifier that never leaves the service.

## Microsoft Entra ID (Azure AD) Setup

A working multi-tenant public client is embedded in
`ccd/client_config.py`, so **this section is optional**. Follow it only if
you forked the project, need a single-tenant app, or want the consent screen
to carry your own name.

### Prerequisites

- Access to the [Entra admin center](https://entra.microsoft.com/) (or the
  classic [Azure Portal](https://portal.azure.com/) → App registrations)

### Step-by-step

1. **Register an application:** *App registrations → New registration*.
   - **Supported account types:** choose **"Accounts in any organizational
     directory and personal Microsoft accounts"** (multi-tenant + personal)
     so any user can link their own account, not just one tenant's.
   - **Redirect URI:** leave it blank, or add a **Mobile and desktop
     applications** platform entry using the default MSAL redirect
     (`https://login.microsoftonline.com/common/oauth2/nativeclient`). The
     device-code flow does not use a redirect URI at all, but MSAL's
     platform configuration expects one of the native platforms to be
     present. Nothing here depends on where the service is deployed.
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
   permissions a user can consent to for themselves.

4. **Do not create a client secret.** This is a **public client**: it has
   no secret, by design (that's what "Allow public client flows" means).
   `ccd`'s device-code and refresh-token requests never send one.

5. **Copy the Application (client) ID** into `ccd/client_config.py`
   (`_EMBEDDED_MS_CLIENT_ID`), or set `CCD_MS_CLIENT_ID`, or put it in
   `client_config.json`. The authority defaults to
   `https://login.microsoftonline.com/common` (works for both
   organizational and personal accounts); override with `CCD_MS_AUTHORITY`
   if you registered a single-tenant app instead.

## Checking your work

Start the service and read the second and third lines it prints:

```
base URL: https://voice.example.com/ccd
Google redirect URI (register this): https://voice.example.com/ccd/oauth/callback
```

The second must be byte-identical to an authorized redirect URI on the Google
client. If consent fails with `redirect_uri_mismatch`, that is the pair to
compare -- nothing else is involved.
