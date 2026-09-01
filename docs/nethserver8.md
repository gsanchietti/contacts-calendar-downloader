# Deploying ccd inside NethServer 8

This is a runbook for a module author -- NethVoice, WebTop, or anything else
on NS8 -- who wants contacts and calendar downloading inside their own module.

`ccd` is **not** an NS8 module and is not installed from the software centre.
It is a container image your module runs, the way it might run a database or
a cache. Everything below happens in *your* module's repository.

Every step has been walked on a real node; if one of them stops matching
reality, fix it here rather than working around it locally.

---

## 1. What you are embedding

One rootless container per instance of your module, holding:

- **one data volume** (`/data`) with one `0600` JSON file per linked account
  and the generated API key,
- **one loopback TCP port**, published only on `127.0.0.1`,
- **one Traefik route**, a path prefix on the hostname your module already has.

Nothing is shared. `nethvoice1` and `webtop1` each get their own container,
their own accounts and their own OAuth clients; neither can see the other's.
There is no cluster-wide ccd, and adding one is not on the table -- the design
deliberately has no multi-tenant token store.

Rough shape of what you end up with:

```
your-module1 pod
├── your-app.service        (already yours)
└── ccd-app.service         ← this runbook
        ↑ 127.0.0.1:${CCD_PORT}
        ↑ Traefik: https://<your fqdn>/ccd  → stripPrefix → :8080
```

---

## 2. One-time operator setup, per installation

The Google redirect URI contains the installation's own hostname, so it
**cannot be registered ahead of time and shipped**. Each deployment needs its
own Google Cloud project (or at least its own OAuth client) with:

```
https://<your module's fqdn>/ccd/oauth/callback
```

as an authorized redirect URI on a client of type **Web application**. Full
walk-through, including the sensitive-scope review Google requires:
[providers.md](providers.md).

Microsoft needs nothing per installation -- ccd's device-code flow uses an
embedded multi-tenant public client and involves no redirect URI. Register
your own only if you want your name on the consent screen.

Plan for this in your module's UI: the fields for the Google client id and
secret belong in your settings page, and the redirect URI to paste into
Google Cloud should be displayed there too, since only your module knows the
final hostname.

---

## 3. Declare the image

In your module's `build-images.sh`, add ccd to the `org.nethserver.images`
label so the platform pulls it when your module is installed:

```bash
buildah config \
    --label="org.nethserver.images=ghcr.io/gsanchietti/ccd:3.0.0 <your other images>" \
    ...
```

**Pin the exact version.** Renovate reads this label to open update PRs and
has nothing to compare against a floating `latest` or `3`; a floating tag
means the image silently stops being tracked.

---

## 4. Allocate a port

ccd listens on `8080` inside its container and must be published on loopback
only. Your module needs one more TCP port than it has today.

If you are adding ports to a module that is already installed in the field,
allocate them at runtime rather than by editing the label -- add
`node:portsadm` to `org.nethserver.authorizations` and, in
`create-module` (and an `update-module.d/` step for existing installs):

Without that role the call fails with a bare `403 Forbidden` from
`/api/node/1/tasks`, which does not mention authorizations at all -- if you
see that, the label is what is missing.

```python
import agent
# one more port, keeping the ones the module already holds
agent.allocate_ports(1, "tcp", keep_existing=True)
```

If you are writing a new module, bumping
`org.nethserver.tcp-ports-demand` is simpler. Either way the ports arrive as
environment variables: `TCP_PORT` is always the first, `TCP_PORTS` a
comma-separated list when there are between 2 and 8, `TCP_PORTS_RANGE` a
`20001-20002` style range. Pick the one for ccd and pin it under a name of
your own so later port changes cannot silently reshuffle it:

```python
import os, agent
agent.set_env("CCD_PORT", os.environ["TCP_PORTS"].split(",")[1])
```

---

## 5. Secrets

Two values are secrets: the **ccd API key** and the **Google client secret**.

> **Never put either through `agent.set_env()`.** That writes to Redis in
> plain text, where every module on the node can read it. Use the NS8 secret
> pattern: a `0600` file in the module's state directory, injected into the
> container with `--env-file`.

In `imageroot/actions/create-module/10genpasswords` (or wherever your module
already generates secrets), add the API key to `state/secrets.env`:

```python
#!/usr/bin/env python3
import os, secrets

path = os.path.join(os.environ["AGENT_STATE_DIR"], "secrets.env")
existing = open(path).read() if os.path.exists(path) else ""

if "CCD_API_KEY=" not in existing:
    with open(path, "a") as f:
        f.write(f"CCD_API_KEY={secrets.token_urlsafe(32)}\n")
    os.chmod(path, 0o600)
```

Generating it only when absent matters: the key is a long-lived credential
your own actions hold, so regenerating it on every install step would break
an upgrade.

`configure-module` writes the Google client secret to the same file (rewriting
it rather than appending, so a changed secret actually replaces the old one),
and everything non-secret through `agent.set_env()` as usual:

```python
agent.set_env("CCD_BASE_URL", f"https://{host}/ccd")
agent.set_env("CCD_GOOGLE_CLIENT_ID", request["google_client_id"])
agent.set_env("CCD_MS_CLIENT_ID", request.get("ms_client_id", ""))
```

Do not echo `CCD_API_KEY` or `CCD_GOOGLE_CLIENT_SECRET` back from
`get-configuration`. Return a boolean saying whether one is set.

---

## 6. The systemd unit

ccd goes in your module's pod as one more child container, following the same
shape as any other NS8 multi-service module (ns8-mattermost is the reference).
Two edits: the pod publishes ccd's port, and a new unit runs the container.

**In your pod unit** (`<your-module>.service`), add ccd to the children and
publish its port on the `podman pod create` line:

```ini
[Unit]
Requires=<your-app>.service ccd-app.service
Before=<your-app>.service ccd-app.service
```

```
ExecStartPre=/usr/bin/podman pod create ... \
    --publish 127.0.0.1:${TCP_PORT}:8065 \
    --publish 127.0.0.1:${CCD_PORT}:8080 \
    ...
```

Ports belong to the pod, not to the containers inside it -- a `--publish` on
`podman run` for a container that joins a pod is rejected.

**New unit**, `imageroot/systemd/user/ccd-app.service`:

```ini
[Unit]
Description=Contacts and calendar downloader
BindsTo=<your-module>.service
After=<your-module>.service

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
EnvironmentFile=%S/state/environment
EnvironmentFile=-%S/state/secrets.env
WorkingDirectory=%S/state
Restart=always
ExecStartPre=/bin/rm -f %t/ccd-app.pid %t/ccd-app.ctr-id
ExecStart=/usr/bin/podman run --conmon-pidfile %t/ccd-app.pid \
    --cidfile %t/ccd-app.ctr-id --cgroups=no-conmon \
    --pod-id-file %t/<your-module>.pod-id --replace -d --name ccd-app \
    --volume ccd-data:/data:Z \
    --env-file=%S/state/secrets.env \
    --env CCD_BASE_URL=${CCD_BASE_URL} \
    --env CCD_GOOGLE_CLIENT_ID=${CCD_GOOGLE_CLIENT_ID} \
    --env CCD_MS_CLIENT_ID=${CCD_MS_CLIENT_ID} \
    ${CCD_IMAGE}
ExecStop=/usr/bin/podman stop --ignore --cidfile %t/ccd-app.ctr-id -t 10
ExecStopPost=/usr/bin/podman rm --ignore -f --cidfile %t/ccd-app.ctr-id
PIDFile=%t/ccd-app.pid
SyslogIdentifier=%u
Type=forking

[Install]
WantedBy=default.target
```

`CCD_LISTEN` is already `0.0.0.0:8080` in the image, which is correct inside a
pod: the pod's `--publish` is what keeps it on loopback.

`${CCD_IMAGE}` comes from the environment the platform builds out of
`org.nethserver.images`.

**Match your module's own conventions**, and do not mix them within one
module. The two you will hit:

- **`%E` vs `%S`.** Both are in use in the field: ns8-kickstart writes
  `%E/state/environment`, ns8-mattermost writes `%S/state/environment`. Copy
  whichever your existing units already use.
- **Pod vs single container.** The unit above assumes your module runs a pod
  (ns8-mattermost shape). A kickstart-derived single-container module has no
  pod, so ccd becomes a *sibling* unit that publishes its own port: drop
  `--pod-id-file` and add `--publish 127.0.0.1:${CCD_PORT}:8080` to the
  `podman run` above, leaving `BindsTo=`/`After=` pointing at your main unit.
  Nothing else changes.

Then, in `configure-module/80start_services`:

```bash
systemctl --user enable ccd-app.service
systemctl --user try-restart <your-module>.service <your-app>.service ccd-app.service
```

> **Name every unit explicitly.** `systemctl --user restart <pod>.service`
> does **not** cascade to the pod's children. Restarting only the pod leaves
> ccd running the old image with the old configuration, which looks exactly
> like a configuration that did not take effect.

---

## 7. The Traefik route

ccd is reached at a path prefix on the hostname your module already owns.
Traefik strips the prefix before forwarding, so ccd keeps serving `/api/...`,
`/d/...` and `/oauth/callback` at its root and needs no notion of where it is
mounted -- except for the URLs it generates, which is what `CCD_BASE_URL` is
for.

```python
import os, agent, agent.tasks

response = agent.tasks.run(
    agent_id=agent.resolve_agent_id('traefik@node'),
    action='set-route',
    data={
        'instance': os.environ['MODULE_ID'] + '-ccd',
        'url': 'http://127.0.0.1:' + os.environ['CCD_PORT'],
        'host': host,
        'path': '/ccd',
        'strip_prefix': True,
        'lets_encrypt': lets_encrypt,
        'http2https': True,
    },
)
agent.assert_exp(response['exit_code'] == 0)
```

Use a distinct `instance` (`<module_id>-ccd`) so this route does not collide
with your module's own, and remove it in `destroy-module` with
`delete-route` on the same name.

### The three values that must agree

This is the single most common thing to get wrong. If a Google sign-in fails
with `redirect_uri_mismatch`, compare exactly these:

| Where | Value |
|---|---|
| `set-route` | `host` + `path` → `https://voice.example.com/ccd` |
| `CCD_BASE_URL` env | `https://voice.example.com/ccd` |
| Google Cloud → Authorized redirect URIs | `https://voice.example.com/ccd/oauth/callback` |

No trailing slash on `CCD_BASE_URL`; scheme must be `https` in all three;
the path prefix must appear in all three. ccd prints its computed redirect
URI on every start -- `journalctl --user -u ccd-app.service | head` is the
fastest way to see what it actually thinks it is.

---

## 8. Backup

Add both to your module's `imageroot/etc/state-include.conf`:

```
state/secrets.env
volumes/ccd-data
```

Neither is optional:

- Without `volumes/ccd-data`, a restore comes back with **zero linked
  accounts** and every user has to go through OAuth consent again.
- Without `state/secrets.env`, the restored container generates a **new API
  key**, and your module's stored key stops working -- every `/api/*` call
  returns 401 until someone notices.

ccd needs no dump/restore hook: the account files are small JSON written
atomically, so Restic can copy them straight from the volume.

---

## 9. Calling the API

Your backend actions call `http://127.0.0.1:${CCD_PORT}` with the API key
from `state/secrets.env`. Full contract: [`openapi.yaml`](openapi.yaml) in
this directory. The container does not serve it -- read it from the ccd
repository, at the tag you pinned in step 3.

> **The browser must never hold the API key.** Your Vue UI talks to your
> module's actions; the actions talk to ccd. Proxy `login-start`,
> `login-poll`, `list-accounts` and `logout-account` the way you would any
> other backend call.

```python
import os, requests

CCD = "http://127.0.0.1:" + os.environ["CCD_PORT"]
AUTH = {"Authorization": "Bearer " + os.environ["CCD_API_KEY"]}

# 1. start -- the two providers answer differently, and both shapes matter
started = requests.post(f"{CCD}/api/login", headers=AUTH,
                        json={"provider": "google"}, timeout=30).json()

if started["kind"] == "redirect":
    show_link(started["authorization_url"])          # Google: open in a browser
else:
    show_code(started["verification_uri"],           # Microsoft: type this code
              started["user_code"])

# 2. poll until the user finishes (or gives up)
state = requests.get(f"{CCD}/api/login/{started['login_id']}",
                     headers=AUTH, timeout=30).json()
# state["status"] is "pending" | "done" | "error"

# 3. on "done", keep the URLs -- they are stable for the life of the account
account = state["account"]
account["download"]["contacts_csv"]   # https://.../ccd/d/<token>/contacts.csv
account["download"]["calendar_ics"]
```

Poll on a timer from your UI, not in a blocking loop inside an action: a
Google consent can take a minute, a Microsoft device code up to fifteen.
Pending logins live in ccd's memory and expire after 20 minutes; if the
container restarts mid-login the poll returns 404 and the user starts over.

Listing and unlinking:

```python
accounts = requests.get(f"{CCD}/api/accounts", headers=AUTH).json()

requests.delete(f"{CCD}/api/accounts/google/{quote(email, safe='')}"
                "?revoke=true", headers=AUTH)
```

Errors come back as `{"error": ..., "code": ...}`. The two your UI should
handle specially are `auth_expired` (HTTP 409 -- that account's refresh token
is dead, prompt the user to link it again) and `provider_api` (HTTP 502 --
Google or Microsoft failed, retrying later is reasonable).

---

## 10. Update, uninstall, troubleshooting

**Update:** bump the pinned tag in `org.nethserver.images`, then in
`update-module.d/30restart`:

```bash
systemctl --user try-restart <your-module>.service <your-app>.service ccd-app.service
```

Account records are forward-compatible; nothing needs migrating.

**Uninstall:** `destroy-module` should call `delete-route` for the
`<module_id>-ccd` instance. The `ccd-data` volume goes with your module's
home, so uninstalling destroys every linked account -- which is the right
behaviour, but say so in your UI's confirmation dialog.

**When something is wrong:**

| Symptom | Cause |
|---|---|
| `redirect_uri_mismatch` at consent | The three values in §7 disagree. |
| 401 from every `/api/*` call | Stale `CCD_API_KEY` -- most often a restore that did not include `state/secrets.env`. |
| 404 on a download URL | The token was rotated, or the account was unlinked. |
| Config change had no effect | Only the pod was restarted; see §6. |
| Login poll returns 404 | The container restarted mid-login, or 20 minutes passed. |
| `No google OAuth client configured` | `CCD_GOOGLE_CLIENT_ID`/`_SECRET` never reached the container. Check the `--env`/`--env-file` lines. |

`journalctl --user -u ccd-app.service` for everything else. ccd logs one line
per request, and redacts download tokens from those lines.

---

## 11. Security handoff

**The `/d/<token>/...` URLs are unauthenticated capability URLs.** They carry
no API key on purpose -- that is what makes them usable as a plain link, a
cron `curl`, or a calendar subscription. It also means anyone who obtains one
can read that account's entire address book and calendar, from anywhere, until
it is rotated.

Once your module receives those URLs, they are your responsibility:

- Treat them as credentials, not as links. Do not write them to your module's
  logs, do not put them in a task payload that gets logged, do not show them
  in a page anyone but the account's own owner can see.
- Anywhere you store them, store them the way you would a password.
- Give the user a way to rotate: `POST /api/accounts/{provider}/{email}/rotate-token`
  invalidates the old URLs immediately and returns new ones.
- They will appear in Traefik's access log. If that log is shipped anywhere,
  suppress the `/ccd/d/` path or accept that the log now holds credentials.

The OAuth tokens themselves never leave the ccd container: they are written
`0600` inside its volume and sent only to Google's and Microsoft's own
endpoints. Nothing in the API can read them back out.
