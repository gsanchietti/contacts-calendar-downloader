# Provider Configuration

This document covers the setup and configuration for Google and Microsoft OAuth providers, including step-by-step instructions for obtaining credentials and configuring the service.

## Google Cloud Setup

### Prerequisites

- A Google Cloud project with billing enabled (required for People API)
- Python 3.9 or newer installed locally

### Step-by-Step Google Cloud Configuration

1. **Visit the Google Cloud Console:**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a project (or choose an existing project) dedicated to this integration

2. **Enable Required APIs:**
   - Navigate to **APIs & Services → Library**
   - Search for and enable:
     - **Google People API** (for contacts)
     - **Google Calendar API** (for calendar events)

3. **Configure OAuth Consent Screen:**
   - Go to **APIs & Services → OAuth consent screen**
   - Choose **Internal** (same workspace) or **External** depending on your account type
   - Provide application details:
     - **App name:** Contacts & Calendar Downloader
     - **User support email:** Your email
     - **Developer contact information:** Your email

4. **Add Required Scopes:**
   - Click **"Add or remove scopes"**
   - Add these scopes:
     - `https://www.googleapis.com/auth/contacts.readonly` (for reading contacts)
     - `https://www.googleapis.com/auth/calendar.readonly` (for reading calendar)
     - `https://www.googleapis.com/auth/userinfo.email` (for user identification)
     - `openid` (automatically included with userinfo.email)
   - Save the consent screen configuration

5. **Create OAuth Client Credentials:**
   - Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**
   - Choose **Web application**
   - Name: "Contacts API Service"
   - Click **Create**

6. **Configure Authorized Redirect URIs:**
   - Click on the newly created OAuth client to edit it
   - Under **Authorized redirect URIs**, add:
     - For local development: `http://localhost:5000/oauth2callback`
     - For production: `https://your-domain.com/oauth2callback`
   - Click **Save**

7. **Download Credentials:**
   - From the Credentials page, click the download button (arrow down) next to your OAuth client
   - Save as `credentials.json` in your project root

### Redirect URI Configuration

**Local Development (Default):**
```
http://localhost:5000/oauth2callback
```

**Custom Port:**
```bash
export PORT=8000
# Redirect URI becomes: http://localhost:8000/oauth2callback
```

**Production with HTTPS:**
```bash
export OAUTH_REDIRECT_URI="https://your-production-domain.com/oauth2callback"
```

**Behind Reverse Proxy:**
```bash
export OAUTH_REDIRECT_URI="https://api.example.com/oauth2callback"
```

### Testing Google OAuth Setup

```bash
# 1. Set credentials path
export GOOGLE_CREDENTIALS=/path/to/credentials.json

# 2. Start service
python downloader.py

# 3. Test OAuth flow
curl http://localhost:5000/auth?provider=google

# 4. Check response includes proper redirect URI
curl -s http://localhost:5000/auth?provider=google | jq -r '.redirect_uri_used'
# Should show: http://localhost:5000/oauth2callback
```

## Microsoft Azure / Microsoft 365 Setup

### Prerequisites

- Microsoft 365 or Azure AD account
- Access to Azure Portal

### Step-by-Step Microsoft Configuration

1. **Visit Azure Portal:**
   - Go to [Azure Portal](https://portal.azure.com/)
   - Navigate to **Azure Active Directory → App registrations → New registration**

2. **Register Application:**
   - **Name:** Contacts Downloader - Microsoft
   - **Supported account types:** Choose based on your needs:
     - Single tenant (your organization only)
     - Multitenant (any Azure AD tenant)
     - Multitenant + personal Microsoft accounts
   - **Redirect URI:** Web → `https://your-domain.com/oauth2callback`
   - Click **Register**

3. **Configure API Permissions:**
   - Go to **API permissions** in your app registration
   - Click **Add a permission → Microsoft Graph**
   - Add **Delegated permissions:**
     - **User.Read** (Sign in and read user profile)
     - **Contacts.Read** (Read contacts)
     - **Calendars.Read** (Read calendars)
     - **offline_access** (Maintain access to data you have given it access to)
   - Click **Grant admin consent** if you have admin privileges

4. **Create Client Secret:**
   - Go to **Certificates & secrets → New client secret**
   - **Description:** Contacts API Secret
   - **Expires:** Choose appropriate expiration (recommend 24 months)
   - Click **Add**
   - **Important:** Copy the secret value immediately (you won't see it again)

5. **Note Application Details:**
   - **Application (client) ID:** Copy from Overview page
   - **Directory (tenant) ID:** Copy from Overview page
   - **Client Secret:** The value you copied in step 4

### Microsoft Credentials Configuration

Create a JSON file at `credentials/microsoft.json`:

```json
{
  "client_id": "<your-application-client-id>",
  "client_secret": "<your-client-secret>",
  "tenant": "common"
}
```

**Tenant Options:**
- `"common"` - Microsoft personal accounts + work/school accounts from any tenant
- `"organizations"` - Work/school accounts from any tenant
- `"consumers"` - Microsoft personal accounts only
- `"<tenant-id>"` - Specific tenant only

### Testing Microsoft OAuth Setup

```bash
# 1. Install Microsoft dependencies
pip install msal requests

# 2. Set credentials path
export MICROSOFT_CREDENTIALS=/path/to/microsoft.json

# 3. Start service
python downloader.py

# 4. Test OAuth flow
curl http://localhost:5000/auth?provider=microsoft

# 5. Complete OAuth in browser
# The flow works similarly to Google OAuth
```

## Provider-Specific Features

### Google Provider Features

- **Contacts API:** Full Google People API integration
- **Calendar API:** Google Calendar events export
- **Pagination:** Automatic handling of large contact lists
- **Field Mapping:** Comprehensive contact field extraction
- **Token Refresh:** Automatic OAuth token renewal

### Microsoft Provider Features

- **Microsoft Graph:** Modern Microsoft Graph API integration
- **Multi-Tenant:** Support for personal and organizational accounts
- **Calendar Export:** Outlook calendar events in ICS format
- **Contact Sync:** Microsoft 365 contacts export
- **Token Management:** MSAL library for secure token handling

## Environment Variables

### Provider Configuration

```bash
# Google credentials
export GOOGLE_CREDENTIALS="credentials/google.json"

# Microsoft credentials
export MICROSOFT_CREDENTIALS="credentials/microsoft.json"

# OAuth redirect URI override
export OAUTH_REDIRECT_URI="https://your-domain.com/oauth2callback"

# Server configuration
export HOST="0.0.0.0"
export PORT="5000"
export PROTOCOL="http"
```

### Advanced Provider Settings

```bash
# Google API settings
export PERSON_FIELDS="names,emailAddresses,phoneNumbers,addresses,organizations,birthdays"
export PAGE_SIZE="1000"

# Microsoft API settings
export MICROSOFT_TENANT="common"
export MICROSOFT_SCOPES="User.Read,Contacts.Read,Calendars.Read,offline_access"
```

## Troubleshooting Provider Issues

### Google OAuth Issues

**"redirect_uri_mismatch":**
```bash
# Check what URI the app is using
curl -s http://localhost:5000/auth | jq -r '.redirect_uri_used'

# Add this exact URI to Google Cloud Console
# APIs & Services → Credentials → OAuth client → Authorized redirect URIs
```

**"access_denied":**
- User denied authorization
- Check consent screen configuration
- Ensure required scopes are added

**"invalid_client":**
- Check credentials.json file exists and is valid
- Verify client ID and secret are correct
- Ensure OAuth client is properly configured

### Microsoft OAuth Issues

**"invalid_client":**
- Check client_id and client_secret in microsoft.json
- Verify tenant ID is correct
- Ensure app registration is active

**"access_denied":**
- Check API permissions are granted
- Admin consent may be required for organizational accounts
- Verify supported account types match your use case

**"invalid_scope":**
- Check that required scopes are added to app registration
- Ensure scopes match what's requested in the application

### Common Issues

**Credentials File Not Found:**
```bash
# Check file exists
ls -la credentials/

# Set correct path
export GOOGLE_CREDENTIALS="/full/path/to/credentials.json"
```

**HTTPS Required for Production:**
```bash
# For production, always use HTTPS
export OAUTH_REDIRECT_URI="https://your-domain.com/oauth2callback"

# Configure your web server for SSL/TLS
```

**Token Expiration:**
- Google tokens expire after 1 hour
- Microsoft tokens expire after 1 hour
- The service automatically refreshes tokens when needed

## Security Considerations

### Provider Security Best Practices

1. **Use HTTPS in Production:**
   - Always configure SSL/TLS certificates
   - Set `OAUTH_REDIRECT_URI` to HTTPS URLs

2. **Limit Scopes:**
   - Only request necessary permissions
   - Use read-only scopes when possible

3. **Secure Credentials:**
   - Store credentials files securely
   - Use environment variables for sensitive data
   - Rotate client secrets regularly

4. **Monitor Access:**
   - Review OAuth consent screen regularly
   - Monitor API usage in provider consoles
   - Set up alerts for unusual activity

### Provider-Specific Security

**Google:**
- Enable security sandbox in Google Cloud Console
- Use service accounts for server-to-server access when possible
- Implement domain restrictions for G Suite accounts

**Microsoft:**
- Use certificate-based authentication for production apps
- Implement conditional access policies
- Use managed identities when deploying to Azure

## Migration Between Providers

### Switching from Google to Microsoft

1. **Set up Microsoft credentials** as described above
2. **Update environment variables:**
   ```bash
   export MICROSOFT_CREDENTIALS="credentials/microsoft.json"
   unset GOOGLE_CREDENTIALS
   ```
3. **Restart service**
4. **Users need to re-authorize** with Microsoft OAuth

### Using Both Providers

The service supports both providers simultaneously:

```bash
# Configure both
export GOOGLE_CREDENTIALS="credentials/google.json"
export MICROSOFT_CREDENTIALS="credentials/microsoft.json"

# Users choose provider at auth time
curl http://localhost:5000/auth?provider=google
curl http://localhost:5000/auth?provider=microsoft
```

Each user authenticates with their preferred provider, and the service handles the differences transparently.