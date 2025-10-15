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
   - Navigate to **Enabled APIs & Services → Library**
   - Click on **+ Enable APIs and Services** on top bar
   - Search for and enable:
     - **Google People API** (for contacts)
     - **Google Calendar API** (for calendar events)

3. **Configure OAuth Consent Screen:**
   - Go to **APIs & Services → OAuth consent screen**
   - Click on **Get Started** button
   - Enter the name of your application, like "Contacts & Calendar Downloader"
   - Select user support email, then click **Next**
   - As **Audiance**, choose **External**, then click **Next**
   - Enter the developer mail address, then click **Next**
   - Add a check to the "I agree to ...", then click **Continue**
   - Finally click **Create**

4. **Add Required Scopes:**
   - Go to **Data access** section
   - Click **"Add or remove scopes"**
   - Add these scopes:
     - `https://www.googleapis.com/auth/contacts.readonly` (for reading contacts)
     - `https://www.googleapis.com/auth/calendar.readonly` (for reading calendar)
     - `https://www.googleapis.com/auth/userinfo.email` (for user identification)
     - `openid` (automatically included with userinfo.email)
   - Save the consent screen configuration

5. **Create OAuth Client Credentials:**
   - Go to **APIs & Services → Clients**
   - Click on **+ Create Credentials**
   - Choose **Web application** as application type
   - Name it "Contacts Calendar Downloader"
   - Click **Create**
   - After creation, a popup will show your **Client ID** and **Client Secret**: download
     the JSON file

6. **Configure Authorized Redirect URIs:**
   - Click on the newly created OAuth client to edit it
   - Under **Authorized redirect URIs**, add:
     - For local development: `http://localhost:5000/google/oauth2callback`
     - For production: `https://your-domain.com/google/oauth2callback`
   - Click **Save**

7. **Download Credentials:**
   - If you did not download the JSON file in step 5, click on the newly created OAuth client to edit it
   - Download the JSON file from **Client secrets** section

8. **Configure allowed domains:**
   - Go to **Branding** section of the OAuth consent screen
   - Under the **App domain** section:
     - Add your application homepage URL, use the home page of your application (e.g., `https://downloader.example.org`)
     - Add your privacy policy URL, use the built-in privacy policy page (e.g., `https://downloader.example.org/privacy_policy` )
     - Add your terms of service URL, use the built-in terms of service page (e.g., `https://downloader.example.org/privacy_policy` )
     - Under the **Authorized domains** section, add your domain to the **Authorized domains** list (e.g., `example.org` )
   - Save changes

9. **Add Test Users:**
   - By default, your app will be in testing mode, you need to add test users
   - Go to **OAuth consent screen → Audience**
   - Under the **Test users** section, click on **Add users**
   - Add the email addresses of any Google accounts you will use to test the integration
   - Save changes


## Microsoft Azure / Microsoft 365 Setup

### Prerequisites

- Microsoft 365 or Azure AD account
- Access to Azure Portal

### Step-by-Step Microsoft Configuration

1. **Visit Azure Portal:**
   - Go to [Azure Portal](https://portal.azure.com/)
   - Navigate to **App registrations**
   - Click on **New registration**

2. **Register Application:**
   - As **Name** set "Contacts Calendar Downloader"
   - Under **Supported account types** choose "Personal Microsoft accounts only"
     The application has not been tested with other account types.  
   - Set the **Redirect URI**, it's not optional:
     - Choose Web platform, then add:
       - For local development: `http://localhost:5000/microsoft/oauth2callback`
       - For production: `https://your-domain.com/microsoft/oauth2callback`
   - Click **Register**

3. **Configure API Permissions:**
   - Go to **Manage → API permissions** in your app registration
   - Click **Add a permission**
   - Select **Microsoft Graph**
   - Select **Delegated permissions** as type of permissions
   - From the search bar, search for the following permissions:
     - **User.Read** (Sign in and read user profile)
     - **Contacts.Read** (Read contacts)
     - **Calendars.Read** (Read calendars)
     - **offline_access** (Maintain access to data you have given it access to)
   - Click **Add permissions** if you have admin privileges

4. **Create Client Secret:**
   - Go to **Certificates & secrets**
   - Click on **New client secret** and fill in:
     - **Description:** Contacts API Secret
     - **Expires:** Choose appropriate expiration (recommend 24 months)
   - Click **Add**
   - **Important:** Copy the secret under the ``Value`` field immediately (you won't see it again)

5. **Note Application Details:**
   - **Application (client) ID:** Copy from Overview page
   - **Client Secret:** The value you copied in step 4

6. **Create Microsoft Credentials Configuration:**

   - Create a JSON file at `credentials/microsoft.json`:
   ```json
   {
     "client_id": "<your-application-client-id>",
     "client_secret": "<your-client-secret>",
     "tenant": "consumers"
   }

7. **Configure branding**:
   - Go to **Branding** section of the App registration
   - Under the **App logo and description** section:
     - Add your application homepage URL, use the home page of your application (e.g., `https://downloader.example.org`)
     - Add your privacy policy URL, use the built-in privacy policy page (e.g., `https://downloader.example.org/privacy_policy` )
     - Add your terms of service URL, use the built-in terms of service page (e.g., `https://downloader.example.org/privacy_policy` )
   - Save changes
