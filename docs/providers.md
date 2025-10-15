# Provider Configuration

This document covers the setup and configuration for Google and Microsoft OAuth providers, including step-by-step instructions for obtaining credentials and configuring the service.

## Google Cloud Setup

### Prerequisites

- A Google Cloud project with billing enabled (required for People API)

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
     - For local development: `http://localhost:5000/google/oauth2callback`
     - For production: `https://your-domain.com/google/oauth2callback`
   - Click **Save**

7. **Download Credentials:**
   - From the Credentials page, click the download button (arrow down) next to your OAuth client
   - Save as `credentials.json` in your project root

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
   - **Redirect URI:** choose Web type, then add:
     - For local development: `http://localhost:5000/google/oauth2callback`
     - For production: `https://your-domain.com/google/oauth2callback`
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
  "tenant": "consumers"
}
```
