#!/usr/bin/env python3
"""Google Contacts Downloader - Multi-tenant HTTP Service

This service allows multiple users to authenticate and download their Google Contacts.
Each user gets their own token file stored securely in the tokens directory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cryptography.fernet import Fernet

from flask import Flask, request, jsonify, Response, render_template
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Allow HTTP for local development (disable HTTPS requirement)
# WARNING: Only use this for local development, never in production!
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# Prometheus metrics
HTTP_REQUESTS_TOTAL = Counter(
    'gcd_http_requests_total',
    'Total HTTP requests', 
    ['method', 'endpoint', 'status_code']
)

HTTP_REQUEST_DURATION = Histogram(
    'gcd_http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
)

REGISTERED_USERS = Gauge(
    'gcd_registered_users_total',
    'Number of registered users in database'
)

ACTIVE_TOKENS = Gauge(
    'gcd_active_tokens_total', 
    'Number of active access tokens'
)

DOWNLOADS_TOTAL = Counter(
    'gcd_downloads_total',
    'Total number of downloads',
    ['format', 'status']
)

CONTACTS_DOWNLOADED = Counter(
    'gcd_contacts_downloaded_total',
    'Total number of contacts downloaded'
)

OAUTH_FLOWS_TOTAL = Counter(
    'gcd_oauth_flows_total',
    'Total number of OAuth flows',
    ['status']
)

DATABASE_SIZE_BYTES = Gauge(
    'gcd_database_size_bytes',
    'Size of the SQLite database file in bytes'
)

ENCRYPTION_WARNINGS_TOTAL = Counter(
    'gcd_encryption_warnings_total',
    'Number of times default encryption key warning was shown'
)

# Default OAuth scopes: read-only access to contacts + user profile for email identification
# Note: openid is automatically added when using userinfo.email scope
DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]
# Additional per-request fields we want from the People API.
DEFAULT_PERSON_FIELDS = (
    "names,emailAddresses,phoneNumbers,addresses,organizations,birthdays,nicknames,metadata"
)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Access tokens are stored in filesystem for persistence


@dataclass
class Config:
    """Runtime configuration."""

    credentials_path: Path
    tokens_dir: Path  # Directory for storing multiple user tokens (legacy)
    database_path: Path  # SQLite database for tokens and access tokens
    person_fields: str
    page_size: int


def get_config() -> Config:
    """Get configuration from environment variables."""
    return Config(
        credentials_path=Path(os.environ.get("GOOGLE_CREDENTIALS", "credentials.json")),
        tokens_dir=Path(os.environ.get("GOOGLE_TOKENS_DIR", "tokens")),
        database_path=Path(os.environ.get("GOOGLE_DATABASE", "google_contacts.db")),
        person_fields=os.environ.get("PERSON_FIELDS", DEFAULT_PERSON_FIELDS),
        page_size=int(os.environ.get("PAGE_SIZE", "1000")),
    )


def get_encryption_key() -> bytes:
    """Get encryption key from environment variable or use default with warning."""
    encryption_key = os.environ.get("GOOGLE_ENCRYPTION_KEY")
    
    if not encryption_key:
        print("⚠️  WARNING: GOOGLE_ENCRYPTION_KEY not set, using default 'secret' key.")
        print("⚠️  WARNING: This is NOT secure for production use!")
        print("⚠️  WARNING: Set GOOGLE_ENCRYPTION_KEY environment variable for security.")
        ENCRYPTION_WARNINGS_TOTAL.inc()
        encryption_key = "secret"
    
    # Create a Fernet key from the provided key
    # Hash the key to ensure it's exactly 32 bytes
    key_hash = hashlib.sha256(encryption_key.encode()).digest()
    # Fernet requires base64-encoded 32-byte key
    fernet_key = base64.urlsafe_b64encode(key_hash)
    return fernet_key


def get_cipher() -> Fernet:
    """Get Fernet cipher instance."""
    return Fernet(get_encryption_key())


def encrypt_data(data: bytes) -> bytes:
    """Encrypt data using AES encryption."""
    cipher = get_cipher()
    return cipher.encrypt(data)


def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt data using AES encryption."""
    cipher = get_cipher()
    return cipher.decrypt(encrypted_data)


def update_metrics(config: Config) -> None:
    """Update Prometheus metrics with current database state."""
    try:
        with get_database_connection(config) as conn:
            cursor = conn.cursor()
            
            # Count registered users
            cursor.execute("SELECT COUNT(*) FROM user_tokens")
            user_count = cursor.fetchone()[0]
            REGISTERED_USERS.set(user_count)
            
            # Count active access tokens  
            cursor.execute("SELECT COUNT(*) FROM access_tokens")
            token_count = cursor.fetchone()[0]
            ACTIVE_TOKENS.set(token_count)
        
        # Get database file size
        db_size = config.database_path.stat().st_size if config.database_path.exists() else 0
        DATABASE_SIZE_BYTES.set(db_size)
        
    except Exception as e:
        # Don't fail the application if metrics update fails
        print(f"Warning: Failed to update metrics: {e}")


def init_database(config: Config) -> None:
    """Initialize SQLite database with required tables."""
    with sqlite3.connect(config.database_path) as conn:
        cursor = conn.cursor()
        
        # Create table for OAuth tokens (replacing token.pickle files)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_tokens (
                user_email TEXT PRIMARY KEY,
                user_hash TEXT NOT NULL,
                token_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create table for access tokens
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_tokens (
                access_token TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_email) REFERENCES user_tokens (user_email) ON DELETE CASCADE
            )
        ''')
        
        # Create table for OAuth flows (replacing in-memory active_flows)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS oauth_flows (
                state TEXT PRIMARY KEY,
                credentials_path TEXT NOT NULL,
                scopes TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_access_tokens_user_email 
            ON access_tokens (user_email)
        ''')
        
        # Create index for OAuth flows cleanup
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_oauth_flows_created_at 
            ON oauth_flows (created_at)
        ''')
        
        conn.commit()


def get_database_connection(config: Config) -> sqlite3.Connection:
    """Get database connection with proper configuration for concurrency.

    Ensure the database parent directory exists and try a best-effort chown so
    a non-root container user can write the database file. Use WAL mode for
    better concurrent access with multiple Gunicorn workers.
    """
    db_path = Path(config.database_path)
    db_dir = db_path.parent

    # Create parent directory if missing
    try:
        db_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If this fails, let sqlite raise a clear error on connect
        pass

    # Best-effort chown to current uid/gid. Ignore permission errors.
    try:
        uid = os.getuid()
        gid = os.getgid()
        os.chown(db_dir, uid, gid)
    except PermissionError:
        pass
    except Exception:
        pass

    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    
    # Enable WAL mode for better concurrency (multiple readers, single writer)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        # Set busy timeout for better handling of concurrent writes
        conn.execute("PRAGMA busy_timeout=30000")  # 30 seconds
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception as e:
        print(f"Warning: Failed to set SQLite pragmas: {e}")
    
    return conn


def get_user_token_path(config: Config, user_id: str) -> Path:
    """Get the token file path for a specific user."""
    # Sanitize user_id to create a safe filename
    safe_user_id = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    config.tokens_dir.mkdir(parents=True, exist_ok=True)
    return config.tokens_dir / f"token_{safe_user_id}.pickle"


def get_user_email_from_credentials(creds: Any) -> Optional[str]:
    """Extract user email from credentials using the OAuth2 API."""
    try:
        # Method 1: Try OAuth2 API (requires userinfo.email scope)
        oauth2_service = build("oauth2", "v2", credentials=creds, cache_discovery=False)
        user_info = oauth2_service.userinfo().get().execute()
        email = user_info.get('email')
        if email:
            return email
    except Exception:
        pass
    
    try:
        # Method 2: Fallback to People API
        people_service = build("people", "v1", credentials=creds, cache_discovery=False)
        profile = people_service.people().get(resourceName='people/me', personFields='emailAddresses').execute()
        emails = profile.get('emailAddresses', [])
        if emails:
            # Return the primary email or first email
            primary_email = next((e['value'] for e in emails if e.get('metadata', {}).get('primary')), None)
            return primary_email or emails[0]['value']
    except Exception:
        pass
    
    return None


def store_oauth_flow(config: Config, state: str, flow: Flow) -> None:
    """Store OAuth flow configuration in database."""
    scopes_json = json.dumps(DEFAULT_SCOPES)
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        # Clean up expired flows (older than 10 minutes)
        cursor.execute(
            "DELETE FROM oauth_flows WHERE created_at < datetime('now', '-10 minutes')"
        )
        
        # Store new flow
        cursor.execute(
            "INSERT OR REPLACE INTO oauth_flows (state, credentials_path, scopes, redirect_uri) VALUES (?, ?, ?, ?)",
            (state, str(config.credentials_path), scopes_json, flow.redirect_uri)
        )
        conn.commit()


def get_oauth_flow(config: Config, state: str) -> Optional[Flow]:
    """Retrieve OAuth flow from database and recreate Flow object."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT credentials_path, scopes, redirect_uri FROM oauth_flows WHERE state = ? AND created_at > datetime('now', '-10 minutes')",
            (state,)
        )
        row = cursor.fetchone()
        
        if row:
            scopes = json.loads(row["scopes"])
            
            # Recreate the flow from stored configuration
            flow = Flow.from_client_secrets_file(
                row["credentials_path"],
                scopes=scopes,
                redirect_uri=row["redirect_uri"],
                state=state
            )
            return flow
        
        return None


def delete_oauth_flow(config: Config, state: str) -> None:
    """Delete OAuth flow from database."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM oauth_flows WHERE state = ?", (state,))
        conn.commit()


def get_redirect_uri() -> str:
    """Get the redirect URI for OAuth."""
    # Allow override via environment variable for production deployments
    redirect_uri = os.environ.get("OAUTH_REDIRECT_URI")
    if redirect_uri:
        return redirect_uri
    
    # For development, try to detect the correct URI
    try:
        from flask import url_for
        # Try to build from current request context
        return url_for('oauth2callback', _external=True)
    except RuntimeError:
        # Fallback when not in request context
        host = os.environ.get("HOST", "localhost")
        port = os.environ.get("PORT", "5000")
        protocol = os.environ.get("PROTOCOL", "http")
        
        # Include port only if it's not the default for the protocol
        if (protocol == "http" and port == "80") or (protocol == "https" and port == "443"):
            return f"{protocol}://{host}/oauth2callback"
        else:
            return f"{protocol}://{host}:{port}/oauth2callback"


def save_access_token(config: Config, token: str, user_email: str) -> None:
    """Save access token with encryption to database."""
    # Encrypt only the access token, keep user_email unencrypted for queries
    encrypted_token = encrypt_data(token.encode())
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO access_tokens (access_token, user_email) VALUES (?, ?)",
            (encrypted_token, user_email)
        )
        conn.commit()


def get_user_from_token(token: str) -> Optional[str]:
    """Get user email from encrypted access token stored in database."""
    config = get_config()
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT access_token, user_email FROM access_tokens")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                # Decrypt the stored token and compare with provided token
                decrypted_token = decrypt_data(row["access_token"]).decode()
                if decrypted_token == token:
                    # Return the user email (unencrypted)
                    return row["user_email"]
            except Exception:
                # Skip invalid/corrupted tokens
                continue
        
        return None


def revoke_access_token(config: Config, token: str) -> bool:
    """Revoke encrypted access token by deleting it from database."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rowid, access_token FROM access_tokens")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                # Decrypt the stored token and compare with provided token
                decrypted_token = decrypt_data(row["access_token"]).decode()
                if decrypted_token == token:
                    try:
                        # Fetch the associated user_email for this access token row
                        cursor.execute("SELECT user_email FROM access_tokens WHERE rowid = ?", (row["rowid"],))
                        user_row = cursor.fetchone()
                        if user_row and user_row["user_email"]:
                            # Also remove the user's stored credentials
                            cursor.execute("DELETE FROM user_tokens WHERE user_email = ?", (user_row["user_email"],))
                    except Exception:
                        # If anything goes wrong here, continue with deleting the token row to avoid leaving stale tokens
                        pass
                    # Delete this row
                    cursor.execute("DELETE FROM access_tokens WHERE rowid = ?", (row["rowid"],))
                    conn.commit()
                    return True
            except Exception:
                # Skip invalid/corrupted tokens
                continue
        
        return False


def list_user_tokens(config: Config, user_email: str) -> List[str]:
    """List all active tokens for a specific user."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT access_token FROM access_tokens WHERE user_email = ?",
            (user_email,)
        )
        rows = cursor.fetchall()
        
        user_tokens = []
        for row in rows:
            try:
                # Decrypt the access token
                decrypted_token = decrypt_data(row["access_token"]).decode()
                user_tokens.append(decrypted_token)
            except Exception:
                # Skip invalid/corrupted tokens
                continue
        
        return user_tokens


def save_user_credentials(config: Config, user_email: str, credentials: Any) -> None:
    """Save user OAuth credentials with encryption to database."""
    user_hash = hashlib.sha256(user_email.encode()).hexdigest()[:16]
    token_data = pickle.dumps(credentials)
    
    # Encrypt only the token_data, keep user_email and user_hash unencrypted for queries
    encrypted_token_data = encrypt_data(token_data)
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO user_tokens (user_email, user_hash, token_data) VALUES (?, ?, ?)",
            (user_email, user_hash, encrypted_token_data)
        )
        conn.commit()


def load_user_credentials(config: Config, user_email: str) -> Optional[Any]:
    """Load user OAuth credentials with decryption from database."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT token_data FROM user_tokens WHERE user_email = ?",
            (user_email,)
        )
        row = cursor.fetchone()
        if row:
            try:
                # Decrypt and return the token data
                decrypted_token_data = decrypt_data(row["token_data"])
                return pickle.loads(decrypted_token_data)
            except Exception:
                # Invalid/corrupted token data
                return None
        return None


def generate_access_token() -> str:
    """Generate a secure access token."""
    return secrets.token_urlsafe(32)


def authenticate_request() -> Optional[str]:
    """Authenticate the current request and return user email if valid."""
    # Check for Authorization header with Bearer token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ', 1)[1]
    return get_user_from_token(token)


def authenticate_google(config: Config, user_email: str) -> Optional[Any]:
    """Authenticate a specific user and return an authorized People API service."""
    
    creds: Optional[Credentials] = load_user_credentials(config, user_email)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Save refreshed credentials
            save_user_credentials(config, user_email, creds)
        else:
            return None  # Not authenticated

    return build("people", "v1", credentials=creds, cache_discovery=False)


def download_contacts(service, config: Config) -> List[Dict]:
    """Fetch all contacts using the People API, handling pagination."""

    contacts: List[Dict] = []
    page_token: Optional[str] = None

    while True:
        request = (
            service.people()
            .connections()
            .list(
                resourceName="people/me",
                pageToken=page_token,
                pageSize=config.page_size,
                personFields=config.person_fields,
            )
        )
        response = request.execute()
        contacts.extend(response.get("connections", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return contacts


def _choose_primary(entries: Iterable[Dict], key: str) -> str:
    primary = None
    for entry in entries:
        metadata = entry.get("metadata", {})
        if metadata.get("primary"):
            primary = entry
            break
    if primary is None:
        primary = next(iter(entries), None)
    return primary.get(key, "") if primary else ""


def _collect_all(entries: Iterable[Dict], key: str) -> str:
    values = [entry.get(key, "") for entry in entries if entry.get(key)]
    return "; ".join(values)


def _format_birthday(person: Dict) -> str:
    for birthday in person.get("birthdays", []):
        date = birthday.get("date", {})
        if date:
            parts = [
                f"{date.get('year', ''):04d}" if date.get("year") else None,
                f"{date.get('month', ''):02d}" if date.get("month") else None,
                f"{date.get('day', ''):02d}" if date.get("day") else None,
            ]
            formatted = "-".join(part for part in parts if part)
            if formatted:
                return formatted
    return ""


def _find_by_type(entries: Iterable[Dict], entry_type: str, key: str) -> str:
    for entry in entries:
        if entry.get("type", "").lower() == entry_type:
            value = entry.get(key)
            if value:
                return value
    return ""


def _extract_contact_row(person: Dict) -> Dict[str, str]:
    names = person.get("names", [])
    if names:
        primary_name = next((n for n in names if n.get("metadata", {}).get("primary")), names[0])
    else:
        primary_name = {}
    nicknames = person.get("nicknames", [])
    emails = person.get("emailAddresses", [])
    phones = person.get("phoneNumbers", [])
    addresses = person.get("addresses", [])
    organizations = person.get("organizations", [])

    return {
        "Full Name": primary_name.get("displayName", ""),
        "Given Name": primary_name.get("givenName", ""),
        "Family Name": primary_name.get("familyName", ""),
        "Nickname": _choose_primary(nicknames, "value"),
        "Primary Email": _choose_primary(emails, "value"),
        "Other Emails": _collect_all(emails[1:], "value") if emails else "",
        "Mobile Phone": _find_by_type(phones, "mobile", "value"),
        "Work Phone": _find_by_type(phones, "work", "value"),
        "Home Phone": _find_by_type(phones, "home", "value"),
        "Other Phones": _collect_all(phones, "value"),
        "Organization": _choose_primary(organizations, "name"),
        "Job Title": _choose_primary(organizations, "title"),
        "Birthday": _format_birthday(person),
        "Street Address": _find_by_type(addresses, "home", "streetAddress")
        or _find_by_type(addresses, "work", "streetAddress"),
        "City": _find_by_type(addresses, "home", "city")
        or _find_by_type(addresses, "work", "city"),
        "Region": _find_by_type(addresses, "home", "region")
        or _find_by_type(addresses, "work", "region"),
        "Postal Code": _find_by_type(addresses, "home", "postalCode")
        or _find_by_type(addresses, "work", "postalCode"),
        "Country": _find_by_type(addresses, "home", "country")
        or _find_by_type(addresses, "work", "country"),
        "Resource Name": person.get("resourceName", ""),
    }


# Initialize database on app startup (needed for Gunicorn)
try:
    config = get_config()
    init_database(config)
    print(f"✅ Database initialized at: {config.database_path}")
except Exception as e:
    print(f"⚠️  Warning: Database initialization failed: {e}")
    print("Will attempt to initialize on first request")


@app.route('/')
def index():
    """Home page with service overview and quick start guide."""
    config = get_config()
    
    # Get service health status
    try:
        if not config.credentials_path.exists():
            service_status = "unhealthy"
        else:
            service_status = "healthy"
    except Exception:
        service_status = "unknown"
    
    # Get authenticated user count
    authenticated_users = 0
    try:
        with get_database_connection(config) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM user_tokens')
            authenticated_users = cursor.fetchone()[0]
    except Exception:
        authenticated_users = 0
    
    return render_template('index.html', 
                         service_status=service_status,
                         authenticated_users=authenticated_users)


@app.route('/auth')
def auth():
    """Get authorization URL for a new user."""
    config = get_config()

    if not config.credentials_path.exists():
        return jsonify({
            "error": f"Credentials file not found: {config.credentials_path}",
            "solution": "Download credentials.json from Google Cloud Console"
        }), 400

    try:
        # Generate a unique state parameter to track this OAuth flow
        state = secrets.token_urlsafe(32)
        redirect_uri = get_redirect_uri()
        
        flow = Flow.from_client_secrets_file(
            str(config.credentials_path),
            scopes=DEFAULT_SCOPES,
            redirect_uri=redirect_uri,
            state=state
        )

        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        # Store the flow with the state as key in database
        store_oauth_flow(config, state, flow)

        # Prepare the payload to return for API clients
        payload = {
            "authorization_url": authorization_url,
            "state": state,
            "redirect_uri_used": redirect_uri,
            "message": "Visit this URL to authorize the application. Each user will get their own token.",
            "instructions": "Add the redirect_uri_used value to 'Authorized redirect URIs' in your OAuth 2.0 Client ID settings",
            "troubleshooting": {
                "google_cloud_console": "https://console.cloud.google.com/apis/credentials",
                "required_redirect_uri": redirect_uri,
                "oauth_scopes": DEFAULT_SCOPES
            }
        }

        # Content negotiation: keep JSON for API clients, but render a friendly
        # auto-redirect HTML page for browser requests (Accept: text/html).
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            return jsonify(payload)
        else:
            # Browser: render a page that will auto-redirect to the authorization URL
            host = request.headers.get('Host', 'localhost:5000')
            return render_template('auth_redirect.html',
                                 authorization_url=authorization_url,
                                 state=state,
                                 redirect_uri=redirect_uri,
                                 host=host,
                                 countdown=5,
                                 troubleshooting=payload['troubleshooting'])

    except Exception as e:
        return jsonify({
            "error": f"Failed to create authorization URL: {str(e)}",
            "troubleshooting": {
                "check_credentials": "Verify credentials.json is valid",
                "check_redirect_uri": f"Ensure '{get_redirect_uri()}' is added to Authorized redirect URIs in Google Cloud Console",
                "google_cloud_console": "https://console.cloud.google.com/apis/credentials"
            }
        }), 500


@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth callback and save user-specific token."""
    config = get_config()
    
    # Get the state parameter from the callback
    state = request.args.get('state')
    
    flow = get_oauth_flow(config, state) if state else None
    
    if not flow:
        error_msg = "No authorization flow in progress or invalid state"
        solution = "Start authorization by visiting /auth first (flows expire after 10 minutes)"
        
        # Check if request accepts JSON (API client) or HTML (browser)
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            return jsonify({
                "error": error_msg,
                "solution": solution
            }), 400
        else:
            return render_template('oauth_error.html',
                                 error_message=error_msg,
                                 troubleshooting={'solution': solution}), 400

    try:
        # Get authorization code from request
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        creds = flow.credentials
        
        # Get user email to identify the user
        user_email = get_user_email_from_credentials(creds)
        
        if not user_email:
            return jsonify({
                "error": "Could not identify user email",
                "solution": "Make sure the OAuth scope includes access to user profile"
            }), 400

        # Save credentials for this specific user
        save_user_credentials(config, user_email, creds)

        # Generate access token for this user
        access_token = generate_access_token()
        save_access_token(config, access_token, user_email)

        # Clear the flow from database
        if state:
            delete_oauth_flow(config, state)

        # Update metrics
        OAUTH_FLOWS_TOTAL.labels(status='success').inc()

        # Check if request accepts JSON (API client) or HTML (browser)
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            # API client - return JSON response
            return jsonify({
                "status": "success", 
                "message": "Authorization successful!",
                "user_email": user_email,
                "access_token": access_token,
                "token_saved_to": "database",
                "next_steps": "Use the access_token in Authorization header: 'Bearer <token>' to call /download"
            })
        else:
            # Browser request - return HTML page
            host = request.headers.get('Host', 'localhost:5000')
            return render_template('oauth_success.html', 
                                 user_email=user_email,
                                 access_token=access_token,
                                 host=host)

    except Exception as e:
        error_msg = str(e)
        troubleshooting = {}
        
        if "redirect_uri_mismatch" in error_msg:
            troubleshooting = {
                "error_type": "redirect_uri_mismatch",
                "solution": "The redirect URI in your request doesn't match what's configured in Google Cloud Console",
                "check_uri": get_redirect_uri(),
                "google_cloud_console": "https://console.cloud.google.com/apis/credentials",
                "steps": [
                    "Go to Google Cloud Console > APIs & Credentials > OAuth 2.0 Client IDs",
                    f"Add '{get_redirect_uri()}' to Authorized redirect URIs",
                    "Save and try again"
                ]
            }
        elif "invalid_client" in error_msg:
            troubleshooting = {
                "error_type": "invalid_client",
                "solution": "Your credentials.json file is invalid or doesn't match the OAuth client",
                "check_credentials": "Verify you downloaded the correct credentials.json from Google Cloud Console"
            }
        else:
            troubleshooting = {
                "error_type": "unknown_oauth_error",
                "solution": "Check the OAuth flow and try again",
                "details": error_msg
            }

        # Clean up the flow on error
        if state:
            delete_oauth_flow(config, state)

        # Update metrics
        OAUTH_FLOWS_TOTAL.labels(status='error').inc()

        # Check if request accepts JSON (API client) or HTML (browser)
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            # API client - return JSON response
            return jsonify({
                "error": f"OAuth callback failed: {error_msg}",
                "troubleshooting": troubleshooting
            }), 400
        else:
            # Browser request - return HTML error page
            return render_template('oauth_error.html',
                                 error_message=f"OAuth callback failed: {error_msg}",
                                 error_details=error_msg,
                                 troubleshooting=troubleshooting), 400


@app.route('/download')
def download():
    """Download contacts for the authenticated user in specified format."""
    config = get_config()
    format_param = request.args.get('format', 'csv').lower()

    # Authenticate the request
    user_email = authenticate_request()
    if not user_email:
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header",
            "example": "curl -H 'Authorization: Bearer your_access_token' http://localhost:5000/download?format=json"
        }), 401

    if format_param not in ['csv', 'json']:
        return jsonify({"error": "Invalid format. Use 'csv' or 'json'"}), 400

    if not config.credentials_path.exists():
        return jsonify({"error": f"Credentials file not found: {config.credentials_path}"}), 400

    service = authenticate_google(config, user_email)
    if not service:
        return jsonify({
            "error": f"User '{user_email}' token has expired or is invalid",
            "solution": "Re-authenticate by visiting /auth to get a new access token"
        }), 401

    try:
        contacts = download_contacts(service, config)

        if not contacts:
            return jsonify({"error": "No contacts found"}), 404

        rows = [_extract_contact_row(person) for person in contacts]

        # Update metrics
        DOWNLOADS_TOTAL.labels(format=format_param, status='success').inc()
        CONTACTS_DOWNLOADED.inc(len(rows))

        if format_param == 'json':
            return jsonify({
                "user_email": user_email,
                "total_contacts": len(rows),
                "contacts": rows
            })
        else:
            # Return CSV as text
            import csv
            import io

            headers = [
                "Full Name", "Given Name", "Family Name", "Nickname",
                "Primary Email", "Other Emails", "Mobile Phone", "Work Phone",
                "Home Phone", "Other Phones", "Organization", "Job Title",
                "Birthday", "Street Address", "City", "Region",
                "Postal Code", "Country", "Resource Name"
            ]

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

            return output.getvalue(), 200, {'Content-Type': 'text/csv'}

    except Exception as e:
        DOWNLOADS_TOTAL.labels(format=format_param, status='error').inc()
        return jsonify({"error": str(e)}), 500


@app.route('/me')
def me():
    """Get current authenticated user information."""
    user_email = authenticate_request()
    if not user_email:
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header"
        }), 401
    
    config = get_config()
    token_path = get_user_token_path(config, user_email)
    
    return jsonify({
        "user_email": user_email,
        "authenticated": True,
        "token_file": token_path.name if token_path.exists() else None
    })


@app.route('/token/revoke', methods=['POST'])
def revoke_token():
    """Revoke the current access token."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header"
        }), 401
    
    token = auth_header.split(' ', 1)[1]
    user_email = get_user_from_token(token)
    
    config = get_config()
    if revoke_access_token(config, token):
        return jsonify({
            "status": "success",
            "message": f"Access token revoked for user: {user_email}"
        })
    else:
        return jsonify({
            "error": "Invalid or expired token"
        }), 401


@app.route('/health')
def health():
    """Health check endpoint."""
    config = get_config()
    if not config.credentials_path.exists():
        return jsonify({"status": "unhealthy", "error": "Credentials file not found"}), 500
    
    return jsonify({"status": "healthy"})


@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint (not authenticated)."""
    config = get_config()
    
    # Update metrics with current database state
    update_metrics(config)
    
    # Return Prometheus formatted metrics
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


@app.route('/privacy_policy')
def privacy_policy():
    """Privacy policy page."""
    return render_template('privacy_policy.html')


if __name__ == '__main__':
    # Initialize database on startup
    config = get_config()
    init_database(config)
    print(f"Database initialized at: {config.database_path}")
    
    port = int(os.environ.get("PORT", "5000"))
    app.run(host='0.0.0.0', port=port, debug=True)
