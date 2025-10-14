# Contacts & Calendar Downloader

A **multi-tenant** Flask-based HTTP service that allows multiple users to authenticate and download their contacts and calendar events from **Google** and **Microsoft** providers. Each user gets their own secure token storage, and the service can serve multiple clients simultaneously.

## Key Features

✅ **Multi-Provider Support** - Google and Microsoft (Outlook/Office 365) authentication  
✅ **Multi-Tenant Architecture** - Multiple users can authenticate independently  
✅ **SQLite Database Storage** - Secure token and credentials storage in SQLite database  
✅ **Contacts Export** - Download contacts from Google People API or Microsoft Graph in CSV or JSON format  
✅ **Calendar Export** - Download calendar events from Google Calendar or Microsoft Graph in ICS format  
✅ **Bearer Token Authentication** - JWT-like access token system for API security  
✅ **Concurrent OAuth Flows** - Multiple users can authenticate simultaneously with different providers  
✅ **Auto Token Refresh** - Tokens are automatically refreshed when expired  
✅ **RESTful API** - Simple HTTP endpoints for all operations  
✅ **User-Friendly OAuth** - Browser-optimized OAuth flow with copy-paste token interface
✅ **Beautiful Web Interface** - Professional index page with service overview and quick start guide
✅ **Privacy Policy & Terms of Service** - Built-in legal documentation for transparency and compliance  

## How it works

The service authenticates users with **Google** or **Microsoft** using OAuth 2.0, stores their credentials securely in an SQLite database, and provides REST endpoints to download contacts and calendar events. Each user receives a Bearer access token for API authentication, and the service handles pagination automatically to retrieve all data.

**Architecture:**
1. User visits `/auth?provider=google` or `/auth?provider=microsoft` → Gets personalized OAuth URL
2. User authorizes via chosen provider → Service identifies user by email
3. Provider-specific credentials saved to SQLite database
4. User receives Bearer access token (provider-aware)
5. User downloads contacts/calendar via `/download/contacts` or `/download/calendar` with Authorization header
6. Service automatically uses the correct provider based on the access token

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the service
python downloader.py

# 3. Visit the web interface (optional)
# Open http://localhost:5000/ in your browser for a user-friendly interface

# 4. Get auth URL (choose your provider)
# For Google:
curl http://localhost:5000/auth?provider=google | jq -r '.authorization_url'
# For Microsoft:
curl http://localhost:5000/auth?provider=microsoft | jq -r '.authorization_url'

# 5. Open the URL in a browser and authorize with your chosen provider

# 6. Download contacts using the access token from step 5
curl -H "Authorization: Bearer <access_token>" "http://localhost:5000/download/contacts?format=json" > contacts.json

# 7. Download calendar using the access token from step 5
curl -H "Authorization: Bearer <access_token>" "http://localhost:5000/download/calendar" > calendar.ics

# 8. View privacy policy (optional)
curl http://localhost:5000/privacy_policy
```

## Multi-Tenant Usage Examples

### Example: Corporate IT Department

```bash
# IT admin sets up the service
./deploy.sh

# Employee 1 authenticates
curl http://localhost:8000/auth | jq -r '.authorization_url'
# Opens URL, completes OAuth → gets access_token_1

# Employee 2 authenticates simultaneously
curl http://localhost:8000/auth | jq -r '.authorization_url'
# Opens URL, completes OAuth → gets access_token_2

# Both download their contacts independently
curl -H "Authorization: Bearer $access_token_1" "http://localhost:8000/download/contacts?format=csv" > employee1_contacts.csv
curl -H "Authorization: Bearer $access_token_2" "http://localhost:8000/download/contacts?format=json" > employee2_contacts.json

# Admin monitors all users
curl http://localhost:8000/metrics | grep gcd_registered_users_total
```

### Example: SaaS Integration

```bash
# Customer A's app authenticates on their behalf
POST /oauth2callback → access_token_A

# Customer B's app authenticates independently
POST /oauth2callback → access_token_B

# Each customer downloads only their own data
curl -H "Authorization: Bearer $access_token_A" /download/contacts → Customer A's contacts
curl -H "Authorization: Bearer $access_token_B" /download/contacts → Customer B's contacts

# Tokens are isolated - Customer A cannot access Customer B's data
```

## Prerequisites

- Python 3.9 or newer
- A Google Cloud project with the **Google People API** enabled
- OAuth 2.0 client credentials for Google and/or Microsoft (see setup below)

Install the Python dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Documentation

📚 **Complete Documentation:**

- **[API Reference](docs/api.md)** - Comprehensive API documentation, endpoints, authentication, and data formats
- **[Provider Setup](docs/providers.md)** - Step-by-step Google Cloud and Microsoft Azure configuration
- **[Deployment Guide](docs/deployment.md)** - Production deployment, security, monitoring, and operations
- **[Advanced Configuration](docs/advanced.md)** - Environment variables, database details, and technical implementation

## Running the Service

### Starting the service

```bash
# Set environment variables
export GOOGLE_CREDENTIALS=/path/to/credentials.json

# Run the service (runs on http://localhost:5000 by default)
python downloader.py
```

**Note for local development:** The service automatically allows HTTP connections for local development by setting `OAUTHLIB_INSECURE_TRANSPORT=1`. This is necessary because Google's OAuth library requires HTTPS by default. **Never use HTTP in production** - always configure HTTPS with proper SSL/TLS certificates.

For production deployment, configure your web server (nginx, Apache) to proxy requests to the Flask service with HTTPS.

### Environment Variables

The service supports the following environment variables for configuration:

#### Core Configuration
- `GOOGLE_CREDENTIALS`: Path to Google OAuth credentials.json file (default: `credentials/google.json`)
- `MICROSOFT_CREDENTIALS`: Path to Microsoft OAuth credentials.json file (default: `credentials/microsoft.json`)
- `DATABASE`: Path to SQLite database file (default: `downloader.db`)
- `ENCRYPTION_KEY`: AES-256 encryption key for database security (default: `"secret"` with warning - **REQUIRED for production**)

#### Server Configuration
- `HOST`: Server bind address for redirect URI generation (default: `localhost`)
- `PORT`: Server port for redirect URI generation (default: `5000`)
- `PROTOCOL`: Protocol for redirect URI generation - `http` or `https` (default: `http` for local, `https` for production)
- `FLASK_SECRET_KEY`: Flask session secret key (auto-generated if not set)

#### OAuth Configuration
- `GOOGLE_OAUTH_REDIRECT_URI`: Override the Google OAuth redirect URI specifically (optional - useful for production deployments)
- `MICROSOFT_OAUTH_REDIRECT_URI`: Override the Microsoft OAuth redirect URI specifically (optional - useful for production deployments)

#### API Configuration
- `PERSON_FIELDS`: Comma-separated list of Google People API fields to request (default: `names,emailAddresses,phoneNumbers,addresses,organizations,birthdays`)
- `PAGE_SIZE`: Number of contacts per API request, max 1000 (default: `1000`)

**Note:** The service automatically sets `OAUTHLIB_INSECURE_TRANSPORT=0` for security. This is hardcoded and not user-configurable.

## Files Reference

This repository includes several supporting files:

- **`compose.yml`** - Podman Compose configuration with Traefik using static file configuration
- **`Containerfile`** - Production container image with Gunicorn WSGI
- **`deploy.sh`** - Automated deployment script with Traefik config generation
- **`traefik.yml`** - Traefik static configuration file (no Docker socket dependency)
- **`traefik-dynamic.yml`** - Dynamic Traefik routing rules (generated from template)
- **`generate-traefik-config.sh`** - Script to generate Traefik config with environment variables
- **`.env.example`** - Environment configuration template
- **`requirements.txt`** - Python dependencies including Gunicorn and monitoring
- **`.gitignore`** - Excludes sensitive files from version control

### Development vs Production

**Development:**
```bash
python downloader.py  # Development server on :5000
```

**Production:**
```bash
./deploy.sh  # Podman Compose with Gunicorn on :8000/8443
```

## Security & Compliance

🔐 **Security Features:**
- AES-256 encryption for all stored tokens and credentials
- Bearer token authentication with configurable expiry
- HTTPS enforcement in production
- Rate limiting and request validation
- Comprehensive audit logging

📋 **Compliance:**
- Built-in privacy policy and terms of service
- GDPR-compliant data handling
- OAuth 2.0 security best practices
- No data retention beyond authentication tokens

## Contributing

Contributions are welcome! Please see the [API documentation](docs/api.md) for technical details and the [deployment guide](docs/deployment.md) for development setup.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Prerequisites

- Python 3.9 or newer
- A Google Cloud project with the **Google People API** enabled
- OAuth 2.0 client credentials for Google and/or Microsoft (see setup below)

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
   - **Add these required scopes:**
     - `https://www.googleapis.com/auth/contacts.readonly` (for reading contacts)
     - `https://www.googleapis.com/auth/calendar.readonly` (for reading calendar)
     - `https://www.googleapis.com/auth/userinfo.email` (for user identification)
     - `openid` (automatically included with userinfo.email)
   - Add yourself (or intended users) as test users if using the External type and you have not published the app.
   - Save the consent screen configuration.
5. Create OAuth client credentials:
   - Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
   - Choose **Web application**.
   - Name the client (e.g., "Contacts API Service") and click **Create**.
   - **Important**: Click on the newly created OAuth client to edit it.
   - Under **Authorized redirect URIs**, click **+ ADD URI** and add these URIs:
     - For local development: `http://localhost:5000/oauth2callback`
     - For production: `https://your-domain.com/oauth2callback` (replace with your actual domain)
   - Click **Save**.
   
6. **Configure redirect URIs based on your deployment:**
   
   **Local development (default):**
   ```
   http://localhost:5000/oauth2callback
   ```
   
   **Custom port or host:**
   ```bash
   export HOST="your-host"
   export PORT="8000"
   # Redirect URI will be: http://your-host:8000/oauth2callback
   ```
   
   **Production with HTTPS:**
   ```bash
   export OAUTH_REDIRECT_URI="https://your-production-domain.com/oauth2callback"
   ```
   
   **Behind a reverse proxy:**
   - Set `OAUTH_REDIRECT_URI` to match your public URL
   - Example: `https://api.example.com/oauth2callback`

7. Since the consent screen is External and the app is in "Testing", add test users so they can authorize the app.
   - Console path: APIs & Services → OAuth consent screen → Test users → ADD USERS.
   - Enter full Google account emails (must be valid) and click Save.
   - Only listed test users can complete OAuth while the app is in Testing; others will see an unverified/access error.

## Microsoft Azure / Microsoft 365 setup (optional)

The application can also authenticate Microsoft (Outlook / Microsoft 365) accounts using Microsoft Graph. To enable Microsoft support, register an app in the Azure Portal and provide the credentials to the service.

1. Visit the [Azure Portal](https://portal.azure.com/) and open **Azure Active Directory** → **App registrations** → **New registration**.
2. Give your app a name (e.g., "Contacts Downloader - Microsoft") and choose the supported account types (single-tenant or multitenant depending on your needs).
3. After registration, go to **Authentication** and add a platform: **Web**. Add the redirect URI used by the application (e.g., `https://your-domain.com/oauth2callback` or `http://localhost:5000/oauth2callback`).
4. Under **Certificates & secrets**, create a new **Client secret** and copy it. You'll need the Client ID and Client Secret.
5. Under **API permissions**, add Microsoft Graph permissions:
   - Delegated: `User.Read` (for user info)
   - Delegated: `Contacts.Read` (for contacts export)
   - Delegated: `Calendars.Read` (for calendar export)
   - Add `offline_access` to allow refresh tokens
6. If your tenant requires admin consent for these permissions, grant admin consent or add test users as needed.

Configuration in this project:

- Place a JSON file with Microsoft credentials at `credentials/microsoft.json` with the following shape:

```json
{
  "client_id": "<your-client-id>",
  "client_secret": "<your-client-secret>",
  "tenant": "common"
}
```

- Install additional Python deps:

```bash
pip install msal requests
```

- Start the service and use `GET /auth?provider=microsoft` to begin a Microsoft OAuth flow.

Notes:
- The Microsoft provider uses Microsoft Graph endpoints and issues access/refresh tokens which are stored encrypted in the database just like Google credentials.
- The flow is web-based and behaves similarly to Google: the user will receive an access token on the success page to use with API endpoints.


## Running the Service

### Starting the service

```bash
# Set environment variables
export GOOGLE_CREDENTIALS=/path/to/credentials.json

# Run the service (runs on http://localhost:5000 by default)
python downloader.py
```

**Note for local development:** The service automatically allows HTTP connections for local development by setting `OAUTHLIB_INSECURE_TRANSPORT=1`. This is necessary because Google's OAuth library requires HTTPS by default. **Never use HTTP in production** - always configure HTTPS with proper SSL/TLS certificates.

For production deployment, configure your web server (nginx, Apqache) to proxy requests to the Flask service with HTTPS.

### Environment Variables

- `GOOGLE_CREDENTIALS`: Path to credentials.json (default: credentials/google.json)
- `MICROSOFT_CREDENTIALS`: Path to Microsoft credentials.json (default: credentials/microsoft.json)
- `DATABASE`: Path to SQLite database file (default: google_contacts.db)
- `ENCRYPTION_KEY`: Encryption key for database security (default: "secret" with warning)
- `FLASK_SECRET_KEY`: Flask session secret (auto-generated if not set)
- `PERSON_FIELDS`: Comma-separated list of person fields to request
- `PAGE_SIZE`: Number of contacts per API request (max 1000)
- `OAUTH_REDIRECT_URI`: Override the OAuth redirect URI (useful for production deployments)
- `HOST`: Server host for redirect URI generation (default: localhost)
- `PORT`: Server port for redirect URI generation (default: 5000)
- `PROTOCOL`: Protocol for redirect URI generation (default: http for local, https for production)

### Database Storage

The service uses **SQLite database** with **AES encryption** to store:
- **User OAuth credentials** (OAuth tokens for Google API access) - `token_data` column encrypted
- **Access tokens** (Bearer tokens for API authentication) - `access_token` column encrypted

**Database file:** `downloader.db` (configurable via `DATABASE` env var)
**Encryption:** AES-256 via Fernet (configurable via `ENCRYPTION_KEY` env var)

#### Encryption Security

**🔐 Encrypted Columns:**
- `user_tokens.token_data` - Contains pickled OAuth credentials
- `access_tokens.access_token` - Contains Bearer tokens for API access

**🔓 Unencrypted Columns:**
- `user_tokens.user_email` - For efficient queries and user management
- `user_tokens.user_hash` - For legacy compatibility
- `access_tokens.user_email` - For efficient token-to-user lookups

**Production Security:**
```bash
# Set a strong encryption key (required for production)
export ENCRYPTION_KEY="your-very-secure-random-key-here"

# Start the service - no warnings will appear
python downloader.py
```

**Development/Testing:**
```bash
# If no key is set, warnings will be displayed
python downloader.py
# ⚠️  WARNING: ENCRYPTION_KEY not set, using default 'secret' key.
# ⚠️  WARNING: This is NOT secure for production use!
```

### API Endpoints

#### GET /
Home page with service overview and quick start guide. **Not authenticated** - publicly accessible.

**Content-Type:** `text/html`

**Description:** 
Displays a beautiful landing page with:
- 📇 **Service Overview** - Multi-tenant architecture and security features
- 🚀 **Quick Start Guide** - Step-by-step instructions for new users  
- 📊 **Live Statistics** - Current authenticated user count and service status
- 🔗 **Navigation Links** - Easy access to all endpoints and documentation
- ⚠️ **Service Notices** - Real-time status alerts and configuration warnings

**Features:**
- **Responsive design** - Works perfectly on mobile and desktop
- **Service health monitoring** - Shows current status and user statistics
- **Feature showcase** - Highlights security and multi-tenant capabilities
- **Quick access buttons** - Direct links to start OAuth or view policies

**Example:**
```bash
curl http://localhost:5000/

# Or visit in browser for full experience:
# http://localhost:5000/
```

---

#### GET /auth
Initiates OAuth flow for a new user and returns authorization URL.

**Response:**
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/auth?...",
  "state": "unique-state-token",
  "message": "Visit this URL to authorize the application. Each user will get their own token."
}
```

**Action:** Open the authorization_url in a browser to complete OAuth.

---

#### GET /oauth2callback
Handles the OAuth callback after user authorization. Saves user-specific token.

**Content Negotiation:** Returns JSON for API clients or HTML for browser requests based on the `Accept` header.

**API Client Response (Accept: application/json):**
```json
{
  "status": "success",
  "user_email": "user@gmail.com",
  "access_token": "AbCdEf123...",
  "next_steps": "Use the access_token in Authorization header: 'Bearer <token>' to call /download/contacts"
}
```

**Browser Response (Accept: text/html):** 
Returns a user-friendly HTML page with:
- ✅ Success confirmation with user email
- 🔑 Copy-paste access token with one-click copy button  
- 📋 Ready-to-use curl command examples
- 🔗 Step-by-step instructions for API usage
- ⚠️ Security warnings about token handling

**Error Responses:**
Both JSON and HTML error responses are provided for various OAuth failures:
- Invalid or expired authorization flows
- Redirect URI mismatches with troubleshooting steps
- Invalid client credentials with configuration guidance

---

#### GET /download/contacts?format=<csv|json>
Downloads contacts for the authenticated user. **Requires authentication.**

**Headers:**
- `Authorization: Bearer <access_token>` (required)

**Parameters:**
- `format` (optional): Either `csv` or `json` (default: `csv`)

**Example:**
```bash
curl -H "Authorization: Bearer your_access_token" "http://localhost:5000/download/contacts?format=json"
```

**CSV Response:** Returns CSV data with `Content-Type: text/csv`  
**JSON Response:** Returns JSON with user_email, total_contacts, and contacts array

---

#### GET /download/calendar
Downloads calendar events for the authenticated user in ICS format. **Requires authentication and calendar scope.**

**Headers:**
- `Authorization: Bearer <access_token>` (required)

**Example:**
```bash
curl -H "Authorization: Bearer your_access_token" "http://localhost:5000/download/calendar" -o calendar.ics
```

**Response:** Returns ICS calendar file with `Content-Type: text/calendar`

**Use Cases:**
- Export calendar for backup purposes
- Import events into other calendar applications (Outlook, Apple Calendar, etc.)
- Integrate with calendar management tools
- Create calendar snapshots for record keeping

---

#### POST /token/revoke
Revoke the current access token. **Requires authentication.**

**Headers:**
- `Authorization: Bearer <access_token>` (required)

**Example:**
```bash
curl -X POST -H "Authorization: Bearer your_access_token" http://localhost:5000/token/revoke
```

**Response:**
```json
{
  "status": "success",
  "message": "Access token revoked for user: john@gmail.com"
}
```

---

#### GET /health
Health check endpoint showing service status and user count.

**Response:**
```json
{
  "status": "healthy",
  "credentials_path": "True",
  "tokens_dir": "tokens",
  "authenticated_users": 2
}
```

---

#### GET /metrics
Prometheus metrics endpoint for monitoring. **Not authenticated** - provides operational metrics.

**Content-Type:** `text/plain; version=0.0.4; charset=utf-8`

**Custom Metrics:**
- `gcd_registered_users_total` - Number of registered users in database
- `gcd_active_tokens_total` - Number of active access tokens 
- `gcd_downloads_total{format,status}` - Total downloads by format (csv/json) and status (success/error)
- `gcd_contacts_downloaded_total` - Total number of contacts downloaded across all users
- `gcd_oauth_flows_total{status}` - Total OAuth flows by status (success/error)
- `gcd_database_size_bytes` - Size of SQLite database file in bytes
- `gcd_encryption_warnings_total` - Number of encryption key warnings shown
- `gcd_http_requests_total{method,endpoint,status_code}` - HTTP request counters
- `gcd_http_request_duration_seconds{method,endpoint}` - HTTP request latency histogram

**Example:**
```bash
curl http://localhost:5000/metrics

# Sample output:
# gcd_registered_users_total 3.0
# gcd_active_tokens_total 2.0  
# gcd_downloads_total{format="json",status="success"} 15.0
# gcd_contacts_downloaded_total 450.0
# gcd_oauth_flows_total{status="success"} 3.0
# gcd_database_size_bytes 32768.0
```

**Prometheus Configuration:**
```yaml
scrape_configs:
  - job_name: 'google-contacts-downloader'
    static_configs:
      - targets: ['localhost:5000']
    scrape_interval: 30s
    metrics_path: /metrics
```

---

#### GET /privacy_policy
Returns the privacy policy and terms of service page as HTML. **Not authenticated** - publicly accessible.

**Content-Type:** `text/html`

**Description:** 
Displays a comprehensive privacy policy and terms of service document explaining how the service handles user data, Google OAuth permissions, and legal terms. The document includes:

**Privacy Policy:**
- Only read-only access to Google Contacts, email, and profile information
- No contact data is stored on servers
- Only encrypted authentication tokens are stored
- Users can revoke access at any time through Google Security settings

**Terms of Service:**
- Acceptance and legal agreement requirements
- Permitted and prohibited uses of the service
- Intellectual property rights protection
- Google API terms compliance
- Limitation of liability and user responsibilities
- Service availability and termination policies

**Example:**
```bash
curl http://localhost:5000/privacy_policy

# Or visit in browser:
# http://localhost:5000/privacy_policy
```

**Use Cases:**
- Legal compliance for data privacy and terms of service requirements
- User transparency about data handling practices and usage rules
- OAuth app verification requirements
- Building trust with users before authentication
- Meeting Google API integration compliance requirements

### OAuth Flow Experience

The service provides different experiences based on how OAuth is accessed:

**Browser Users (Human-Friendly):**
1. Visit authorization URL in browser → Google OAuth consent screen
2. After authorization → Beautiful success page with:
   - ✅ Clear success confirmation
   - 🔑 Copy-paste access token (click to select, button to copy)
   - 📋 Ready-to-use curl examples with your actual token
   - 🔗 Step-by-step API usage instructions

**API Clients (Machine-Friendly):**
```bash
# Request with JSON Accept header gets JSON response
curl -H "Accept: application/json" http://localhost:5000/oauth2callback?code=...
# {"status": "success", "access_token": "...", "user_email": "..."}
```

**Error Handling:**
Both browser and API clients get appropriate error responses with troubleshooting guidance for common OAuth issues like redirect URI mismatches.

### Testing with curl

```bash
# Start the service in one terminal
python downloader.py

# In another terminal, check service health
curl -s http://localhost:5000/health | jq .

# Get authorization URL and check redirect URI
curl -s http://localhost:5000/auth | jq .

# The response will show you the exact redirect URI being used:
# {
#   "authorization_url": "https://accounts.google.com/o/oauth2/auth?...",
#   "redirect_uri_used": "http://localhost:5000/oauth2callback",
#   "message": "Visit this URL to authorize the application...",
#   "instructions": "Add the redirect_uri_used value to 'Authorized redirect URIs'...",
#   "troubleshooting": { ... }
# }

# After completing OAuth in browser, you'll get an access token
# Use the access token to download contacts

# Set your access token (replace with actual token from OAuth response)
ACCESS_TOKEN="your_access_token_here"

# Get current user info
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:5000/me | jq .

# Get contacts as JSON
curl -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:5000/download/contacts?format=json" | jq '.contacts[0]'

# Get contacts as CSV
curl -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:5000/download/contacts?format=csv" | head -5

# Save to file
curl -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:5000/download/contacts?format=json" > contacts.json
curl -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:5000/download/contacts?format=csv" > contacts.csv

# Revoke token when done
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:5000/token/revoke
```

## Troubleshooting

### redirect_uri_mismatch Error

This error occurs when the redirect URI used by the application doesn't match what's configured in Google Cloud Console.

**Error message:**
```
Error 400: redirect_uri_mismatch
Request details: redirect_uri=http://localhost:5000/oauth2callback
```

**Solution:**

1. **Check which redirect URI the app is using:**
   ```bash
   curl -s http://localhost:5000/auth | jq -r '.redirect_uri_used'
   ```
   
   Or start the service and look at the response:
   ```bash
   python downloader.py
   # In another terminal:
   curl http://localhost:5000/auth
   ```

2. **Add the URI to Google Cloud Console:**
   - Go to [Google Cloud Console - Credentials](https://console.cloud.google.com/apis/credentials)
   - Find your **OAuth 2.0 Client ID** and click to edit it
   - In the **"Authorized redirect URIs"** section, click **"+ ADD URI"**
   - Paste exactly: `http://localhost:5000/oauth2callback` (or the URI from step 1)
   - Click **"SAVE"**
   - Wait a few minutes for changes to propagate

3. **For production deployments:**
   ```bash
   export OAUTH_REDIRECT_URI="https://your-production-domain.com/oauth2callback"
   ```
   Then add this exact URI to your Google Cloud Console OAuth client.

4. **Quick test script:**
   ```bash
   chmod +x test_oauth.sh
   ./test_oauth.sh
   ```

**Common scenarios:**

- **Local development:** Add `http://localhost:5000/oauth2callback`
- **Custom port:** Add `http://localhost:8000/oauth2callback` and set `export PORT=8000`
- **Production with domain:** Add `https://your-domain.com/oauth2callback` and set `export OAUTH_REDIRECT_URI="https://your-domain.com/oauth2callback"`
- **Behind reverse proxy:** Add your public URL, e.g., `https://api.example.com/oauth2callback`

### Other Common Issues

- **"Credentials file not found"**: Ensure `credentials.json` exists and `GOOGLE_CREDENTIALS` is set correctly
- **"No authorization flow in progress"**: Visit `/auth` first before accessing the callback URL
- **"Invalid format"**: Use `format=json` or `format=csv` for the download endpoint

## Data Formats

### CSV Output

The `/download/contacts?format=csv` endpoint returns CSV data with the following columns:

- Full Name, Given Name, Family Name, Nickname
- Primary Email, Other Emails
- Mobile Phone, Work Phone, Home Phone, Other Phones
- Organization, Job Title
- Birthday
- Street Address, City, Region, Postal Code, Country
- Resource Name (Google internal identifier)

Missing information is left blank. Multi-value fields are concatenated with `; `.

### JSON Output

The `/download/contacts?format=json` endpoint returns a JSON array of contact objects. Each object contains the same fields as the CSV columns, with field names as keys and contact data as string values.

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

## Production Deployment

### Podman Compose (Rootless) - Recommended

Deploy with rootless Podman using the included compose configuration:

**Prerequisites:**
```bash
# Install Podman and Podman Compose on RhRHELel/Rocky Linux
dnf install epel-release
dnf install podman podman-compose

# Configure rootless Podman
useradd downloader -s /bin/bash -m
loginctl enable-linger downloader
```

```bash
# Allow unprivileged ports (80, 443) for rootless Podman
echo "net.ipv4.ip_unprivileged_port_start=80" | tee /etc/sysctl.d/user_priv_ports.conf
sysctl -p /etc/sysctl.d/user_priv_ports.conf
```

**Quick Deploy:**
```bash
# 1. Clone repository
sudo - downloader
git clone https://github.com/gsanchietti/google-contacts-downloader.git
cd google-contacts-downloader
```

```bash
# 1. Configure environment
cp .env.example .env
# Generate a random encryption key
uuidgen | sha256sum | awk '{print $1}'
vi .env  # Edit ENCRYPTION_KEY, DOMAIN and ACME_EMAIL

# 2. Deploy services
./deploy.sh

# 3. Access application
curl http://localhost:8000/health
```

**Service URLs (Rootless Ports):**
- **Application**: http://localhost:8000
- **Traefik Dashboard**: http://localhost:8081
- **Health/Metrics**: http://localhost:8000/health, /metrics


### Container Features

- ✅ **Rootless Security** - No root privileges required
- ✅ **Traefik Proxy** - Automatic SSL with Let's Encrypt
- ✅ **Health Checks** - Built-in monitoring and healthchecks
- ✅ **Prometheus Metrics** - Complete observability
- ✅ **Persistent Storage** - Database survives container restarts
- ✅ **Production WSGI** - Gunicorn server for performance

### Manual Container Deployment

Make sure the `credentials.json` file is in the current directory.

```bash
# Build image
podman build -t google-contacts-downloader .

# Create data volume
podman volume create contacts-data

# Run service
podman run --rm --name contacts-service \
  -p 8000:8000 \
  -v contacts-data:/app/data:z \
  -v ./credentials.json:/app/credentials.json:ro,z \
  -e GOOGLE_CREDENTIALS=/app/credentials.json \
  -e DATABASE_PATH=/app/data/credentials.db \
  -e ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  google-contacts-downloader
```

### Backup & Recovery

```bash
# Database backup
podman exec google-contacts-downloader cp /app/data/credentials.db /app/data/backup-$(date +%Y%m%d).db
podman cp google-contacts-downloader:/app/data/backup-$(date +%Y%m%d).db ./

# Complete backup
podman volume export google-contacts-downloader_app-data > app-data-backup.tar

# Recovery
podman volume import google-contacts-downloader_app-data app-data-backup.tar
```

## Security & Monitoring

### Security Features

- ✅ **AES-256 Encryption** - Database tokens and credentials encrypted with Fernet
- ✅ **Rootless containers** - No privileged execution required  
- ✅ **Bearer token authentication** - Secure API access with JWT-like tokens
- ✅ **HTTPS enforcement** - Automatic SSL with Let's Encrypt in production
- ✅ **Non-root execution** - Service runs as unprivileged user (UID 1000)

### Production Security Checklist

```bash
# 1. Set strong encryption key (REQUIRED)
export ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

# 2. Use HTTPS in production
export OAUTH_REDIRECT_URI="https://your-domain.com/oauth2callback"

# 3. Secure database file permissions
chmod 600 credentials.db

# 4. Configure firewall
sudo ufw allow 80,443/tcp

# 5. Monitor encryption warnings (should be 0)
curl http://localhost:8000/metrics | grep gcd_encryption_warnings_total
```

### Monitoring & Observability

**Health Check:**
```bash
curl http://localhost:8000/health
# {"status": "healthy", "authenticated_users": 3}
```

**Prometheus Metrics:**
```bash
curl http://localhost:8000/metrics
```

**Key Metrics:**
- `gcd_registered_users_total` - Total registered users
- `gcd_downloads_total{format,status}` - Downloads by format/status  
- `gcd_http_request_duration_seconds` - Response time histogram
- `gcd_oauth_flows_total{status}` - OAuth success/failure rates
- `gcd_database_size_bytes` - Database growth monitoring
- `gcd_encryption_warnings_total` - Security configuration alerts

**Grafana Dashboard Query Examples:**
```promql
# Success rate
rate(gcd_http_requests_total{status_code=~"2.."}[5m]) / rate(gcd_http_requests_total[5m])

# 95th percentile response time  
histogram_quantile(0.95, rate(gcd_http_request_duration_seconds_bucket[5m]))

# OAuth failure rate
rate(gcd_oauth_flows_total{status="error"}[5m])
```

### Recommended Production Setup

**External Reverse Proxy (Alternative to Traefik):**
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Files Reference

This repository includes several supporting files:

- **`compose.yml`** - Podman Compose configuration with Traefik using static file configuration
- **`Containerfile`** - Production container image with Gunicorn WSGI
- **`deploy.sh`** - Automated deployment script with Traefik config generation
- **`traefik.yml`** - Traefik static configuration file (no Docker socket dependency)
- **`traefik-dynamic.yml`** - Dynamic Traefik routing rules (generated from template)
- **`generate-traefik-config.sh`** - Script to generate Traefik config with environment variables
- **`.env.example`** - Environment configuration template
- **`requirements.txt`** - Python dependencies including Gunicorn and monitoring
- **`.gitignore`** - Excludes sensitive files from version control

### Development vs Production

**Development:**
```bash
python downloader.py  # Development server on :5000
```

**Production:**
```bash
./deploy.sh  # Podman Compose with Gunicorn on :8000/8443
```

### Troubleshooting Commands

```bash
# Check service status
podman-compose ps

# View logs  
podman-compose logs -f google-contacts-downloader

# Test connectivity
curl http://localhost:8000/health

# Check metrics
curl http://localhost:8000/metrics | grep gcd_

# Restart services
podman-compose restart

# Complete reset
podman-compose down && podman-compose up -d --build
```