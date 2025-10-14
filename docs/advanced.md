# Advanced Configuration

This document covers advanced configuration options, database details, environment variables, and technical implementation details.

## Environment Variables

### Supported Environment Variables

The service supports the following environment variables:

```bash
# Core Configuration
GOOGLE_CREDENTIALS="credentials/google.json"    # Google OAuth credentials file path
MICROSOFT_CREDENTIALS="credentials/microsoft.json"  # Microsoft OAuth credentials file path
DATABASE="downloader.db"                        # SQLite database file path
ENCRYPTION_KEY=""                               # AES-256 encryption key (REQUIRED for production)

# Server Configuration
HOST="localhost"                                # Server bind address for redirect URI
PORT="5000"                                     # Server port for redirect URI
PROTOCOL="http"                                 # Protocol for redirect URI (http/https)
FLASK_SECRET_KEY=""                             # Flask session secret (auto-generated if empty)

# OAuth Configuration
GOOGLE_OAUTH_REDIRECT_URI=""                    # Override Google OAuth redirect URI
MICROSOFT_OAUTH_REDIRECT_URI=""                 # Override Microsoft OAuth redirect URI

# API Configuration
PERSON_FIELDS="names,emailAddresses,phoneNumbers,addresses,organizations,birthdays,nicknames,metadata"  # Google People API fields
PAGE_SIZE="1000"                                # Contacts per API request (max 1000)
```

### Environment Variable Details

#### GOOGLE_CREDENTIALS
- **Type**: File path (string)
- **Default**: `credentials/google.json`
- **Description**: Path to the Google OAuth 2.0 client credentials JSON file obtained from Google Cloud Console
- **Required**: Yes (for Google provider functionality)

#### MICROSOFT_CREDENTIALS
- **Type**: File path (string)
- **Default**: `credentials/microsoft.json`
- **Description**: Path to the Microsoft OAuth 2.0 client credentials JSON file
- **Required**: Yes (for Microsoft provider functionality)

#### DATABASE
- **Type**: File path (string)
- **Default**: `downloader.db`
- **Description**: Path to the SQLite database file for storing encrypted user tokens and access tokens
- **Required**: No (defaults to current directory)

#### ENCRYPTION_KEY
- **Type**: Base64-encoded string
- **Default**: `"secret"` (with security warnings)
- **Description**: Fernet encryption key for AES-256 encryption of database contents
- **Required**: **YES for production** (using default shows warnings and is insecure)
- **Generation**: 
  ```bash
  python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
  ```

#### HOST
- **Type**: String (hostname or IP)
- **Default**: `localhost`
- **Description**: Server host address used for OAuth redirect URI generation
- **Note**: Used to construct redirect URIs like `PROTOCOL://HOST:PORT/<provider>/oauth2callback`

#### PORT
- **Type**: Integer
- **Default**: `5000`
- **Description**: Server port used for OAuth redirect URI generation
- **Note**: Used to construct redirect URIs like `PROTOCOL://HOST:PORT/<provider>/oauth2callback`

#### PROTOCOL
- **Type**: String (`http` or `https`)
- **Default**: `http`
- **Description**: Protocol used for OAuth redirect URI generation
- **Production**: Should be `https` in production environments
- **Note**: Used to construct redirect URIs like `PROTOCOL://HOST:PORT/<provider>/oauth2callback`

#### FLASK_SECRET_KEY
- **Type**: String (hex)
- **Default**: Auto-generated 32-byte hex string
- **Description**: Flask session secret for session cookie signing
- **Note**: Auto-generated if not provided, but setting explicitly ensures consistency across restarts

#### GOOGLE_OAUTH_REDIRECT_URI
- **Type**: URL string
- **Default**: None (uses `PROTOCOL://HOST:PORT/google/oauth2callback`)
- **Description**: Override the OAuth redirect URI for Google provider specifically
- **Use Case**: When behind reverse proxy or using custom domain

#### MICROSOFT_OAUTH_REDIRECT_URI
- **Type**: URL string
- **Default**: None (uses `PROTOCOL://HOST:PORT/microsoft/oauth2callback`)
- **Description**: Override the OAuth redirect URI for Microsoft provider specifically
- **Use Case**: When behind reverse proxy or using custom domain

#### PERSON_FIELDS
- **Type**: Comma-separated string
- **Default**: `names,emailAddresses,phoneNumbers,addresses,organizations,birthdays,nicknames,metadata`
- **Description**: Google People API fields to request when fetching contacts
- **Available Fields**: See [Google People API documentation](https://developers.google.com/people/api/rest/v1/people#Person)

#### PAGE_SIZE
- **Type**: Integer (1-1000)
- **Default**: `1000`
- **Description**: Number of contacts to fetch per API request
- **Note**: Google People API maximum is 1000

### Hardcoded Settings

The following are set by the application and not user-configurable:

- `OAUTHLIB_INSECURE_TRANSPORT=0` - HTTPS enforcement for OAuth (hardcoded for security)
- Debug mode - Enabled by default in development server, disabled in production with Gunicorn

## Database Storage

### Database Schema

The service uses a database with the following tables:
- `user_tokens`: Stores encrypted OAuth tokens per user
  The `token_data` field is encrypted using AES-256 and contains pickled OAuth credentials
- `access_tokens`: Stores Bearer tokens for API access
  The `access_token` field is encrypted using AES-256 and contains the Bearer token
- `downloads`: Logs download activity for auditing