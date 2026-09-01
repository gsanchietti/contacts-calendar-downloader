# Who Holds the Key

OAuth account-linking — comparison of 3CX, Wildix, and ccd's current and previous architectures.

Every approach still needs an OAuth client (Google) or app registration (Microsoft) set up somewhere by someone with console access. Nobody eliminates that step — they only move **who** does it and **where** the secret ends up.

## The four approaches (Google)

### 3CX — per-install client
Admin creates a Web-application OAuth client in their own Google Cloud Console, pastes client ID + secret into the 3CX admin UI. A wizard walks through the click-through. Also offers domain-wide delegation for bulk org authorization.

- **Strength:** no shared vendor secret; guided wizard lowers friction.
- **Limitation:** still needs GCP console literacy and per-install redirect-URI upkeep.

### Wildix — vendor-central
Wildix pre-registers one service account. Customer admin just pastes Wildix's client ID into their own Workspace Admin console's domain-wide delegation page, plus admin email + domain. No Google Cloud Console step for the customer at all.

- **Strength:** near-zero setup; customer never creates a client or handles a secret.
- **Limitation:** Workspace-only; one vendor-held key can impersonate any user in any customer's domain.

### ccd — HTTP service (current)
Runs as its own container per install (inside NethVoice/WebTop). Operator registers a Google Web-app client once per install; each end user does personal OAuth consent. Microsoft path needs no redirect URI at all — device-code, one shareable client (see below).

- **Strength:** no shared multi-tenant secret; supports personal accounts, not just Workspace.
- **Limitation:** Google path still needs an operator with GCP console access; no wizard yet.

### ccd — CLI-only (previous)
Earlier architecture: no server, no HTTP endpoint. Ran directly on a user's own machine; tokens stayed local to that machine.

- **Strength:** smallest possible attack surface — nothing listening, nothing shared.
- **Limitation:** can't publish a stable URL or serve NethVoice/WebTop as a shared service; still needed the same Google client per user, just moved where it ran.

## Side by side (Google)

| Approach | Registers Google client | Customer touches GCP console | Account scope | Secret lives |
|---|---|---|---|---|
| 3CX | Customer, per install | Yes | Personal or Workspace | 3CX admin UI, per install |
| Wildix | Wildix, once | No | Workspace only | Wildix infra, shared across all customers |
| ccd — HTTP | Operator, per install | Yes (Google only) | Personal or Workspace | Local `0600` file, per install |
| ccd — CLI-only | User, per machine | Yes | Personal or Workspace | Local file, per machine — no server at all |

## Microsoft flows

Microsoft is where the four approaches diverge most, because Graph offers two very different auth shapes: **app-only** (tenant-wide, certificate-based, needs an Azure app registration + admin consent) and **delegated device-code** (per-user, no redirect URI, no secret at all).

### 3CX — Azure app registration + certificate, app-only
Customer's Global Administrator registers an Azure AD app (single-tenant), generates a key pair in 3CX, uploads the public certificate to the Azure app, grants **Application permissions** (`Calendars.Read`, `Contacts.Read`, `Directory.Read.All`) and clicks **Grant admin consent**. This is **app-only, tenant-wide** access — 3CX can read every mailbox/calendar in the org without per-user consent, but the app registration and certificate are the customer's own, not shared with other 3CX customers.

- **Strength:** customer-isolated (own app registration, own cert); no vendor-shared credential.
- **Limitation:** heaviest setup of any flow here — Azure app registration, certificate generation/upload, application-level Graph permissions, admin consent. Tenant-wide read access is a bigger blast radius than per-user consent even though it's customer-held.

### Wildix — Microsoft 365 / Teams / Outlook integration
Public docs confirm calendar sync, Outlook, and Teams integration exist, but the auth model (app-only vs delegated, customer-registered vs vendor-shared) isn't detailed in what's publicly indexed. Given the domain-wide-delegation pattern Wildix uses for Google, a similar tenant-wide Azure app-only model is plausible but **unconfirmed** — worth a direct check against their guide before relying on it.

### ccd — device-code (current)
No Azure app registration by the operator or the customer at all. MSAL's device-code flow (RFC 8628) needs no redirect URI, so **one client id, registered once by Nethesis, works for every deployment**. Permissions are **delegated** (`User.Read`, `Contacts.Read`, `Calendars.Read`) — standard scopes a user consents to for themselves, no admin consent required. The end user just visits a short URL, types a code, and signs in.

- **Strength:** the simplest of all four Microsoft flows — zero admin setup, zero redirect URI, zero certificate, no tenant-wide privilege. Already close to "self-installer friendly" without needing a broker.
- **Limitation:** delegated + per-user only — there's no bulk/admin-side authorization option for an org that wants to onboard many mailboxes at once (which is what app-only buys 3CX and, presumably, Wildix).

Net: for Microsoft, ccd's existing device-code model is already the lightest-touch option on this list — the Google-side friction discussed above doesn't have a Microsoft equivalent today.

## Bottom line

- the customer, per install — **3CX** (Google and Microsoft both)
- the vendor, once, centrally — **Wildix** (Google): trades customer effort for one concentrated, cross-customer credential and Workspace-only reach
- nobody, because there's no server — **ccd (CLI-only)**: trades away the shared-service functionality ccd actually needs
- nobody, because the flow doesn't need it — **ccd (Microsoft, both architectures)**: device-code sidesteps the whole registration question
