# Google Contacts Downloader

Download all contacts from your Google account using the People API and export them to a CSV or JSON file. This project provides a ready-to-run Python script plus guidance for obtaining OAuth credentials and automating the export.

## How it works

The `downloader.py` script authenticates with Google using OAuth 2.0, fetches all contacts from your Google account via the People API, processes the contact data into a structured format, and exports it to CSV or JSON. The script handles pagination automatically to retrieve all contacts, even for large address books.
First time you run it, the script will print a URL to the console. Open this URL in your browser to authorize access to your Google account. After authorization, it saves a token for future runs, allowing automated exports without further user interaction.

## Prerequisites

- Python 3.9 or newer
- A Google Cloud project with the **Google People API** enabled
- OAuth 2.0 client credentials (`credentials.json`)

Install the Python dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Google Cloud setup (obtain credentials)

1. Visit the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project (or choose an existing project) dedicated to this integration.
3. **Enable the Google People API**:
   - Navigate to **APIs & Services → Library**.
   - Search for “Google People API” and click **Enable**.
4. Configure the OAuth consent screen (required even for internal use):
   - Go to **APIs & Services → OAuth consent screen**.
   - Choose **Internal** (same workspace) or **External** depending on your account type.
   - Provide the application name, support email, and developer contact information.
   - Add `https://www.googleapis.com/auth/contacts.readonly` (or `https://www.googleapis.com/auth/contacts`) to the list of scopes.
   - Add yourself (or intended users) as test users if using the External type and you have not published the app.
   - Save the consent screen configuration.
5. Create OAuth client credentials:
   - Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
   - Choose **Desktop app** (recommended for command-line usage).
   - Name the client (e.g., "Contacts CSV Exporter") and click **Create**.
   - **Important**: Click on the newly created OAuth client to edit it.
   - Under **Authorized redirect URIs**, click **+ ADD URI** and add: `http://localhost:8080`
   - Click **Save**.
   6. Since the consent screen is External and the app is in "Testing", add test users so they can authorize the app.
      - Console path: APIs & Services → OAuth consent screen → Test users → ADD USERS.
      - Enter full Google account emails (must be valid) and click Save.
      - Only listed test users can complete OAuth while the app is in Testing; others will see an unverified/access error.


### Command-line options

```text
--credentials PATH      Path to the OAuth client JSON file (default: credentials.json)
--token PATH            Path to store the OAuth token pickle (default: token.pickle)
--output PATH           Destination file (default: google_contacts.csv, use '-' for stdout)
--output-format FORMAT  Output format: csv or json (default: csv)
--person-fields FIELDS  Comma-separated list of personFields to request.
--page-size N           Number of contacts per API call (max 1000).
```

You can also set environment variables instead of flags:

- `GOOGLE_CREDENTIALS`
- `GOOGLE_TOKEN`
- `GOOGLE_CONTACTS_OUTPUT`

Example with custom paths:

```bash
GOOGLE_CREDENTIALS=/secure/credentials.json \
GOOGLE_TOKEN=/secure/token.pickle \
python downloader.py --output export.csv
```

## CSV output

The generated CSV contains the following columns:

- Full Name, Given Name, Family Name, Nickname
- Primary Email, Other Emails
- Mobile Phone, Work Phone, Home Phone, Other Phones
- Organization, Job Title
- Birthday
- Street Address, City, Region, Postal Code, Country
- Resource Name (Google internal identifier)

Missing information is left blank. Multi-value fields are concatenated with `; `.

## JSON output

When using `--output-format json`, the script outputs a JSON array of contact objects. Each object contains the same fields as the CSV columns, with field names as keys and contact data as string values.

Example JSON structure:

```json
[
  {
    "Full Name": "John Doe",
    "Primary Email": "john@example.com",
    "Mobile Phone": "+1-555-0123",
    ...
  },
  ...
]
```

## Running with Podman or Docker (containerized alternative)

You can run the script in a rootless Podman container for isolation and portability. The container approach is particularly useful for:
- Running on systems without Python installed
- Isolating dependencies
- Scheduled/automated executions in container environments


**First run (interactive authorization):**

```bash
podman run --rm -it --network=host \
  -v ./credentials.json:/home/downloader/credentials.json:z \
  -v downloader-data:/home/downloader:z \
  google-contacts-downloader \
  --credentials /home/downloader/credentials.json \
  --token /home/downloader/token.pickle \
  --output -
```

**Subsequent runs (automated):**

```bash
podman run --rm \
  -v downloader-data:/home/downloader:z \
  google-contacts-downloader \
  --credentials /home/downloader/credentials.json \
  --token /home/downloader/token.pickle \
  --output - > contacts.csv
```

### Running on a schedule with Podman

Create a systemd user unit for scheduled execution using named volumes:

**File: `~/.config/systemd/user/google-contacts-export.service`**

```ini
[Unit]
Description=Google Contacts Export
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/podman run --rm \
  -v downloader-data:/home/downloader:z \
  google-contacts-downloader \
  --credentials /home/downloader/credentials.json \
  --token /home/downloader/token.pickle \
  --output - > %h/google-contacts-export.csv

[Install]
WantedBy=default.target
```

**File: `~/.config/systemd/user/google-contacts-export.timer`**

```ini
[Unit]
Description=Daily Google Contacts Export

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
systemctl --user daemon-reload
systemctl --user enable --now google-contacts-export.timer
systemctl --user list-timers  # Verify it's scheduled
```


### Container security notes

- The container runs as a non-root user (`downloader`) for security
- No privileged access required
- Credentials and tokens are only accessible via the mounted volume
- Use read-only mounts if you want to prevent the container from modifying `credentials.json`:
  ```bash
  -v ./credentials.json:/home/downloader/credentials.json:ro,z
  -v downloader-data:/home/downloader:z
  ```

### Troubleshooting container issues

- **"Permission denied" on volume**: 
  - For named volumes: Ensure proper SELinux labeling with `:z`
- **Port already in use**: Use `--network=host` instead of port mapping, or change the host port: `-p 8081:8080`
- **Token not persisting**: 
  - For named volumes: Ensure the volume was created and mounted correctly
  - For bind mounts: Ensure the volume mount includes the directory, not just the file
- **SELinux blocks access**: Use `:Z` for private volumes or `:z` for shared volumes
- **Network issues**: If `--network=host` doesn't work, fall back to `-p 8080:8080`
- **Named volume not found**: Run `podman volume create downloader-data` first

## Deployment and automation

- **Service account vs OAuth**: The People API requires delegated access through OAuth 2.0. Plan how you will securely store `credentials.json` and `token.pickle` on the target machine (e.g., using an encrypted filesystem or a secret manager).
- **Non-interactive refresh**: After the initial console authorization, the refresh token inside `token.pickle` allows automated runs without further user input.
- **Scheduling**: Use cron (Linux) or systemd timers to run the script periodically. Example cron entry for a daily export at 02:00:
  ```cron
  0 2 * * * /path/to/venv/bin/python /path/to/downloader.py --output /backups/google_contacts.csv >> /var/log/google-contacts.log 2>&1
  ```
- **Monitoring**: Capture stderr/stdout (e.g., cron logs, Cloud Logging) so failures are detected quickly. Rotate or redact logs if they include paths to credentials.
- **Revocation and rotation**: If credentials are compromised or need refreshing, delete `token.pickle` and rerun the script to trigger a new consent flow. Replace `credentials.json` with a newly generated OAuth client when required.

For production deployments, review your organization's security policies—store secrets in a vault, restrict machine access, and ensure the OAuth consent screen is fully configured and published if external users need access.