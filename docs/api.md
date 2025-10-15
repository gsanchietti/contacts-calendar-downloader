# API Reference

This document provides comprehensive documentation for all API endpoints, authentication methods, and data formats supported by the Contacts & Calendar Downloader service.

## Authentication

All API endpoints that access user data require Bearer token authentication:

```bash
curl -H "Authorization: Bearer <your_access_token>" "http://localhost:5000/download/contacts"
```

### Getting an Access Token

1. **Initiate OAuth Flow:**
   ```bash
   curl http://localhost:5000/auth?provider=google
   # Returns: {"authorization_url": "https://accounts.google.com/o/oauth2/auth?...", ...}
   ```

2. **Complete OAuth in Browser:**
   - Open the `authorization_url` in a browser
   - Authorize the application
   - Receive access token on success page

3. **Use Token in API Requests:**
   ```bash
   ACCESS_TOKEN="your_token_here"
   curl -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:5000/download/contacts"
   ```

## API Endpoints

### GET /
Home page with service overview and quick start guide. **Not authenticated** - publicly accessible.

**Example:**
```bash
curl http://localhost:5000/

# Or visit in browser for full experience:
# http://localhost:5000/
```

---

### GET /auth
Initiates OAuth flow for a new user and returns authorization URL.

**Parameters:**
- `provider` (optional): Either `google` or `microsoft` (default: `google`)

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

### GET /google/oauth2callback and /microsoft/oauth2callback
Handles the OAuth callback after user authorization. Saves user-specific token.
These are the OAuth redirect URIs that must be configured in your provider consoles.

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

### GET /download/contacts?format=<csv|json>
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

### GET /download/calendar
Downloads calendar events for the authenticated user in ICS format. **Requires authentication..**

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

### POST /token/revoke
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

### GET /manage/{export_token}
Manage page for export tokens. **Requires valid export token in URL.**

**Parameters:**
- `export_token` (URL path): The export token to manage

**Response:** HTML page showing:
- Account information
- Permanent export URLs
- Active bearer tokens
- Token revocation options

---

### POST /manage/{export_token}/revoke
Revoke all tokens and delete credentials for the export token. **Requires valid export token.**

**Parameters:**
- `export_token` (URL path): The export token to revoke

**Response:** Redirects to home page after successful revocation

---

### GET /health
Health check endpoint showing service status and user count.

**Response:**
```json
{
  "status": "healthy",
}
```

---

### GET /metrics
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
  - job_name: 'contacts-calendar-downloader'
    static_configs:
      - targets: ['localhost:5000']
    scrape_interval: 30s
    metrics_path: /metrics
```

---

### GET /privacy_policy
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

## Error Responses

### Common HTTP Status Codes

- **200 OK** - Request successful
- **400 Bad Request** - Invalid request parameters or format
- **401 Unauthorized** - Missing or invalid authorization token
- **403 Forbidden** - Access denied (insufficient permissions)
- **404 Not Found** - Endpoint or resource not found
- **429 Too Many Requests** - Rate limit exceeded
- **500 Internal Server Error** - Server error (check logs)

### OAuth-Specific Errors

- **redirect_uri_mismatch** - Redirect URI not configured in provider console
- **invalid_client** - Invalid client credentials
- **access_denied** - User denied authorization
- **invalid_grant** - Authorization code expired or invalid
- **unsupported_grant_type** - Invalid OAuth grant type
