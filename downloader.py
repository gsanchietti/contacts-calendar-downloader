#!/usr/bin/env python3
"""Contacts & Calendar Downloader - Multi-tenant HTTP Service

This service allows multiple users to authenticate and download their contacts and calendar
events from Google and Microsoft providers. Each user gets their own credentials stored 
securely in an encrypted SQLite database with provider-aware token management.
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
from typing import Any, Dict, List, Optional, cast

from cryptography.fernet import Fernet

from flask import Flask, request, jsonify, Response, render_template
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from providers.google import DEFAULT_SCOPES as GOOGLE_DEFAULT_SCOPES
from providers import google as google_provider
from providers import microsoft as microsoft_provider
import providers
import requests
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from datetime import datetime, timezone

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

# Default OAuth scopes: read-only access to contacts, calendar + user profile for email identification
# Note: openid is automatically added when using userinfo.email scope
DEFAULT_SCOPES = GOOGLE_DEFAULT_SCOPES
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

    google_credentials_path: Path
    microsoft_credentials_path: Path  # Microsoft OAuth credentials
    database_path: Path  # SQLite database for tokens and access tokens
    person_fields: str
    page_size: int
    host: str
    port: int
    protocol: str


def get_config() -> Config:
    """Get configuration from environment variables."""
    return Config(
        google_credentials_path=Path(os.environ.get("GOOGLE_CREDENTIALS", "credentials/google.json")),
        microsoft_credentials_path=Path(os.environ.get("MICROSOFT_CREDENTIALS", "credentials/microsoft.json")),
        database_path=Path(os.environ.get("DATABASE", "downloader.db")),
        person_fields=os.environ.get("PERSON_FIELDS", DEFAULT_PERSON_FIELDS),
        page_size=int(os.environ.get("PAGE_SIZE", "1000")),
        host=os.environ.get("HOST", "localhost"),
        port=int(os.environ.get("PORT", "5000")),
        protocol=os.environ.get("PROTOCOL", "http"),
    )


def get_encryption_key() -> bytes:
    """Get encryption key from environment variable or use default with warning."""
    encryption_key = os.environ.get("ENCRYPTION_KEY")
    
    if not encryption_key:
        print("⚠️  WARNING: ENCRYPTION_KEY not set, using default 'secret' key. This is NOT secure for production use!")
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
        
        # Create table for OAuth tokens (support multiple providers)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_tokens (
                user_email TEXT,
                provider TEXT DEFAULT 'google',
                user_hash TEXT NOT NULL,
                token_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_email, provider)
            )
        ''')
        
        # Create table for access tokens (support multiple providers)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_tokens (
                access_token TEXT,
                provider TEXT DEFAULT 'google',
                user_email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (access_token, provider),
                FOREIGN KEY (user_email, provider) REFERENCES user_tokens (user_email, provider) ON DELETE CASCADE
            )
        ''')
        
        # Create table for OAuth flows (supporting provider identification)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS oauth_flows (
                state TEXT PRIMARY KEY,
                provider TEXT DEFAULT 'google',
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
        
        # Create table for permanent export tokens
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS export_tokens (
                export_token TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                provider TEXT DEFAULT 'google',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_email, provider) REFERENCES user_tokens (user_email, provider) ON DELETE CASCADE
            )
        ''')
        
        # Create index for export tokens
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_export_tokens_user_email 
            ON export_tokens (user_email, provider)
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


def get_user_provider(config: Config, user_email: str) -> str:
    """Return the provider associated with the given user_email, default to 'google'."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT provider FROM user_tokens WHERE user_email = ? LIMIT 1", (user_email,))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]
    return 'google'


def store_oauth_flow(config: Config, state: str, flow_info: Dict[str, Any]) -> None:
    """Store OAuth flow configuration in database.

    flow_info is a dict that must contain: provider, credentials_path (optional), scopes (list), redirect_uri
    """
    provider = flow_info.get('provider', 'google')
    scopes_json = json.dumps(flow_info.get('scopes', DEFAULT_SCOPES))
    credentials_path = flow_info.get('credentials_path') or str(config.google_credentials_path)
    redirect_uri = flow_info.get('redirect_uri', get_redirect_uri(provider))

    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        # Clean up expired flows (older than 10 minutes)
        cursor.execute(
            "DELETE FROM oauth_flows WHERE created_at < datetime('now', '-10 minutes')"
        )

        # Store new flow
        cursor.execute(
            "INSERT OR REPLACE INTO oauth_flows (state, provider, credentials_path, scopes, redirect_uri) VALUES (?, ?, ?, ?, ?)",
            (state, provider, credentials_path, scopes_json, redirect_uri)
        )
        conn.commit()


def get_oauth_flow(config: Config, state: str, provider: str = 'google') -> Optional[Flow]:
    """Retrieve OAuth flow from database and recreate Flow object."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT credentials_path, scopes, redirect_uri FROM oauth_flows WHERE state = ? AND provider = ? AND created_at > datetime('now', '-10 minutes')",
            (state, provider)
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


def get_oauth_flow_row(config: Config, state: str) -> Optional[sqlite3.Row]:
    """Return the raw oauth_flows DB row for a given state (if recent)."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT state, provider, credentials_path, scopes, redirect_uri FROM oauth_flows WHERE state = ? AND created_at > datetime('now', '-10 minutes')",
            (state,)
        )
        return cursor.fetchone()





def delete_oauth_flow(config: Config, state: str) -> None:
    """Delete OAuth flow from database."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM oauth_flows WHERE state = ?", (state,))
        conn.commit()


def get_redirect_uri(provider: str = 'google') -> str:
    """Get the redirect URI for OAuth based on provider."""
    # Allow override via environment variable for production deployments
    if provider == 'google':
        redirect_uri = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")
    else:
        redirect_uri = os.environ.get("MICROSOFT_OAUTH_REDIRECT_URI")
    
    if redirect_uri:
        return redirect_uri
    
    # Always use environment variables for consistent URI generation
    host = os.environ.get("HOST", "localhost")
    port = os.environ.get("PORT", "5000")
    protocol = os.environ.get("PROTOCOL", "http")
    
    # Include port only if it's not the default for the protocol
    if (protocol == "http" and port == "80") or (protocol == "https" and port == "443"):
        base_uri = f"{protocol}://{host}"
    else:
        base_uri = f"{protocol}://{host}:{port}"
    
    if provider == 'microsoft':
        return f"{base_uri}/microsoft/oauth2callback"
    else:
        return f"{base_uri}/google/oauth2callback"


def save_access_token(config: Config, token: str, user_email: str, provider: str = 'google') -> None:
    """Save access token with encryption to database."""
    # Encrypt only the access token, keep user_email unencrypted for queries
    encrypted_token = encrypt_data(token.encode())
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO access_tokens (access_token, provider, user_email) VALUES (?, ?, ?)",
            (encrypted_token, provider, user_email)
        )
        conn.commit()


def get_user_from_token(token: str, provider: Optional[str] = None) -> Optional[str]:
    """Get user email from encrypted access token stored in database."""
    config = get_config()
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        if provider:
            cursor.execute(
                "SELECT access_token, user_email FROM access_tokens WHERE provider = ?",
                (provider,)
            )
        else:
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


def get_provider_from_token(token: str) -> Optional[Dict[str, str]]:
    """Return a dict with 'user_email' and 'provider' for the given access token, or None.

    This searches the access_tokens table across providers and decrypts stored tokens to find
    the matching row.
    """
    config = get_config()
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT access_token, user_email, provider, rowid FROM access_tokens")
        rows = cursor.fetchall()

        for row in rows:
            try:
                decrypted_token = decrypt_data(row[0]).decode()
                if decrypted_token == token:
                    return {"user_email": row[1], "provider": row[2]}
            except Exception:
                continue

    return None


def revoke_access_token(config: Config, token: str, provider: str = 'google') -> bool:
    """Revoke encrypted access token by deleting it from database."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        if provider:
            cursor.execute(
                "SELECT rowid, access_token FROM access_tokens WHERE provider = ?",
                (provider,)
            )
        else:
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
                            # Also remove the user's stored credentials for this provider
                            cursor.execute("DELETE FROM user_tokens WHERE user_email = ? AND provider = ?", (user_row["user_email"], provider))
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


def list_user_tokens(config: Config, user_email: str, provider: str = 'google') -> List[str]:
    """List all active tokens for a specific user."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT access_token FROM access_tokens WHERE user_email = ? AND provider = ?",
            (user_email, provider)
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


def save_user_credentials(config: Config, user_email: str, credentials: Any, provider: str = 'google') -> None:
    """Save user OAuth credentials with encryption to database."""
    user_hash = hashlib.sha256(user_email.encode()).hexdigest()[:16]
    token_data = pickle.dumps(credentials)
    
    # Encrypt only the token_data, keep user_email and user_hash unencrypted for queries
    encrypted_token_data = encrypt_data(token_data)
    
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO user_tokens (user_email, provider, user_hash, token_data) VALUES (?, ?, ?, ?)",
            (user_email, provider, user_hash, encrypted_token_data)
        )
        conn.commit()


def generate_export_token() -> str:
    """Generate a secure export token."""
    return secrets.token_urlsafe(48)


def save_export_token(config: Config, user_email: str, provider: str = 'google') -> str:
    """Save or retrieve existing export token for user."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        
        # Check if export token already exists
        cursor.execute(
            "SELECT export_token FROM export_tokens WHERE user_email = ? AND provider = ?",
            (user_email, provider)
        )
        row = cursor.fetchone()
        
        if row:
            return row["export_token"]
        
        # Generate new export token
        export_token = generate_export_token()
        cursor.execute(
            "INSERT INTO export_tokens (export_token, user_email, provider) VALUES (?, ?, ?)",
            (export_token, user_email, provider)
        )
        conn.commit()
        return export_token


def get_user_from_export_token(config: Config, export_token: str) -> Optional[Dict[str, str]]:
    """Get user email and provider from export token."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_email, provider FROM export_tokens WHERE export_token = ?",
            (export_token,)
        )
        row = cursor.fetchone()
        if row:
            return {"user_email": row["user_email"], "provider": row["provider"]}
        return None


def revoke_export_token(config: Config, export_token: str) -> bool:
    """Revoke export token."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM export_tokens WHERE export_token = ?", (export_token,))
        conn.commit()
        return cursor.rowcount > 0


def load_user_credentials(config: Config, user_email: str, provider: str = 'google') -> Optional[Any]:
    """Load user OAuth credentials with decryption from database."""
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT token_data FROM user_tokens WHERE user_email = ? AND provider = ?",
            (user_email, provider)
        )
        row = cursor.fetchone()
        if row:
            try:
                # Decrypt and return the token data
                decrypted_token_data = decrypt_data(row["token_data"])
                raw = None
                try:
                    # Try to unpickle (Google Credentials or other pickle-encoded objects)
                    raw = pickle.loads(decrypted_token_data)
                except Exception:
                    # Fall back to JSON decode for dict-shaped tokens (Microsoft)
                    try:
                        raw = json.loads(decrypted_token_data.decode())
                    except Exception:
                        raw = None

                if raw is None:
                    return None

                # Normalize shape for consistent handling across providers
                return normalize_loaded_credentials(raw, provider=provider)
            except Exception:
                # Invalid/corrupted token data
                return None
        return None


def normalize_loaded_credentials(raw: Any, provider: str = 'google') -> Dict[str, Any]:
    """Normalize various stored credential formats into a canonical dict:

    Canonical shape returned:
      {
         'access_token': str or None,
         'refresh_token': str or None,
         'expires_at': int or None,
         'scopes': list[str] or [],
         'provider_specific': original raw object (pickle or dict)
      }

    This supports:
    - Google `google.oauth2.credentials.Credentials` objects (pickled)
    - Microsoft dict-shaped tokens saved as JSON/pickled dicts
    - Pre-seeded test dicts
    """
    normalized: Dict[str, Any] = {
        'access_token': None,
        'refresh_token': None,
        'expires_at': None,
        'scopes': [],
        'provider_specific': raw,
    }

    # google.credentials.Credentials has attributes .token, .refresh_token, .expiry, .scopes
    try:
        # Try attribute access for Google Credentials-like objects
        token = getattr(raw, 'token', None)
        refresh = getattr(raw, 'refresh_token', None)
        expiry = getattr(raw, 'expiry', None)
        scopes = getattr(raw, 'scopes', None)

        if token or refresh or expiry or scopes:
            normalized['access_token'] = token
            normalized['refresh_token'] = refresh
            if expiry:
                try:
                    # expiry may be datetime
                    if hasattr(expiry, 'timestamp'):
                        normalized['expires_at'] = int(expiry.timestamp())
                    else:
                        normalized['expires_at'] = int(expiry)
                except Exception:
                    normalized['expires_at'] = None
            normalized['scopes'] = list(scopes) if scopes else []
            return normalized
    except Exception:
        pass

    # If it's a dict-like structure (Microsoft or seeded tests)
    if isinstance(raw, dict):
        normalized['access_token'] = raw.get('access_token') or raw.get('token')
        normalized['refresh_token'] = raw.get('refresh_token')
        expires = raw.get('expires_at') or raw.get('expires') or raw.get('expiry')
        try:
            normalized['expires_at'] = int(expires) if expires is not None else None
        except Exception:
            normalized['expires_at'] = None
        scopes = raw.get('scopes') or raw.get('scope')
        if isinstance(scopes, str):
            normalized['scopes'] = scopes.split()
        elif isinstance(scopes, list):
            normalized['scopes'] = scopes
        else:
            normalized['scopes'] = []

        return normalized

    # Fallback: keep original raw as provider_specific
    return normalized


def save_normalized_user_credentials(config: Config, user_email: str, normalized: Dict[str, Any], provider: str = 'microsoft') -> None:
    """Save a normalized credentials dict into user_tokens for testing or seeding.

    The normalized dict should follow the canonical shape described in `normalize_loaded_credentials`.
    This helper stores the normalized dict as JSON (encrypted) so `load_user_credentials` can read and normalize it back.
    """
    user_hash = hashlib.sha256(user_email.encode()).hexdigest()[:16]
    token_json = json.dumps(normalized).encode()
    encrypted = encrypt_data(token_json)

    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO user_tokens (user_email, provider, user_hash, token_data) VALUES (?, ?, ?, ?)",
            (user_email, provider, user_hash, encrypted)
        )
        conn.commit()


def create_access_token_for_user(config: Config, user_email: str, access_token: str, provider: str = 'microsoft') -> None:
    """Create an encrypted access_tokens row for a user (useful for tests).

    Stores the encrypted access_token and links it to user_email/provider.
    """
    encrypted = encrypt_data(access_token.encode())
    with get_database_connection(config) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO access_tokens (access_token, provider, user_email) VALUES (?, ?, ?)",
            (encrypted, provider, user_email)
        )
        conn.commit()


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
    # Search across providers for the token
    return get_user_from_token(token, provider=None)


# Google-specific functions moved to providers/google.py



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
    return render_template('index.html')


@app.route('/auth')
def auth():
    """Get authorization URL for a new user."""
    config = get_config()

    if not config.google_credentials_path.exists():
        return jsonify({
            "error": f"Credentials file not found: {config.google_credentials_path}",
            "solution": "Download credentials.json from Google Cloud Console"
        }), 400

    # Determine provider from query parameter (default: google)
    provider = request.args.get('provider', 'google')
    
    try:
        # Generate a unique state parameter to track this OAuth flow
        state = secrets.token_urlsafe(32)
        redirect_uri = get_redirect_uri(provider)

        if provider == 'microsoft':
            # Microsoft OAuth using MSAL
            import msal
            # Load microsoft credentials file
            ms_creds_path = config.microsoft_credentials_path
            if not ms_creds_path.exists():
                return jsonify({"error": f"Microsoft credentials file not found: {ms_creds_path}"}), 400
            ms_creds = json.loads(ms_creds_path.read_text())

            client_id = ms_creds.get('client_id')
            authority = f"https://login.microsoftonline.com/{ms_creds.get('tenant', 'common')}"

            app_msal = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=ms_creds.get('client_secret'),
                authority=authority
            )

            # MSAL rejects certain OIDC reserved scopes in the authorization URL builder
            # Keep the full scope list for storage, but pass a filtered list to MSAL
            full_scopes = providers.microsoft.DEFAULT_SCOPES
            msal_scopes = [s for s in full_scopes if s.lower() not in ('openid', 'profile', 'offline_access')]
            authorization_url = app_msal.get_authorization_request_url(
                scopes=msal_scopes,
                state=state,
                redirect_uri=redirect_uri
            )

            # Store flow info for microsoft
            flow_info = {
                'provider': 'microsoft',
                'credentials_path': str(ms_creds_path),
                'scopes': full_scopes,
                'redirect_uri': redirect_uri
            }
            store_oauth_flow(config, state, flow_info)

        else:
            # Default: Google flow
            state = state
            flow = Flow.from_client_secrets_file(
                str(config.google_credentials_path),
                scopes=DEFAULT_SCOPES,
                redirect_uri=redirect_uri,
                state=state
            )

            authorization_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true'
            )

            # Store the flow with the state as key in database
            flow_info = {
                'provider': 'google',
                'credentials_path': str(config.google_credentials_path),
                'scopes': DEFAULT_SCOPES,
                'redirect_uri': redirect_uri
            }
            store_oauth_flow(config, state, flow_info)

        # Prepare the payload to return for API clients - include provider and the exact scopes used
        oauth_scopes = flow_info.get('scopes') if isinstance(flow_info, dict) else DEFAULT_SCOPES
        payload = {
            "provider": provider,
            "authorization_url": authorization_url,
            "state": state,
            "redirect_uri_used": redirect_uri,
            "message": "Visit this URL to authorize the application. Each user will get their own token.",
            "instructions": "Add the redirect_uri_used value to 'Authorized redirect URIs' in your OAuth 2.0 Client ID settings",
            "troubleshooting": {
                "provider_docs": "https://docs.microsoft.com/en-us/graph/" if provider == 'microsoft' else "https://console.cloud.google.com/apis/credentials",
                "required_redirect_uri": redirect_uri,
                "oauth_scopes": oauth_scopes
            }
        }

        # Content negotiation: keep JSON for API clients, but render a friendly
        # auto-redirect HTML page for browser requests (Accept: text/html).
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            return jsonify(payload)
        else:
            # Browser: render a page that will auto-redirect to the authorization URL
            return render_template('auth_redirect.html',
                                 authorization_url=authorization_url,
                                 state=state,
                                 redirect_uri=redirect_uri,
                                 base_url=f"{config.protocol}://{config.host}:{config.port}",
                                 countdown=5,
                                 troubleshooting=payload['troubleshooting'],
                                 provider=provider)

    except Exception as e:
        return jsonify({
            "error": f"Failed to create authorization URL: {str(e)}",
            "troubleshooting": {
                "check_credentials": "Verify credentials.json is valid",
                "check_redirect_uri": f"Ensure '{get_redirect_uri(provider)}' is added to Authorized redirect URIs in your OAuth provider console",
                "google_cloud_console": "https://console.cloud.google.com/apis/credentials" if provider == 'google' else "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps"
            }
        }), 500


@app.route('/google/oauth2callback')
def google_oauth2callback():
    """Handle Google OAuth callback and save user-specific token."""
    config = get_config()
    
    # Get the state parameter from the callback
    state = request.args.get('state')
    
    # Get Google flow
    flow = get_oauth_flow(config, state, provider='google') if state else None
    
    if not flow:
        error_msg = "No Google authorization flow in progress or invalid state"
        solution = "Start authorization by visiting /auth?provider=google first (flows expire after 10 minutes)"
        
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
        # Delegate Google-specific flow completion to providers.google
        from providers.google import handle_oauth_callback as google_handle_oauth_callback
        user_email, creds = google_handle_oauth_callback(config, flow)
        # Persist credentials (saved in main app DB)
        save_user_credentials(config, user_email, creds, provider='google')

        # Generate access token for this user and persist
        access_token = generate_access_token()
        save_access_token(config, access_token, user_email, provider='google')

        # Generate export token for permanent URLs
        export_token = save_export_token(config, user_email, provider='google')

        # Clear the flow from database
        if state:
            delete_oauth_flow(config, state)

        # Update metrics
        OAUTH_FLOWS_TOTAL.labels(status='success').inc()

        # Respond to client
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            return jsonify({
                "status": "success",
                "message": "Google authorization successful!",
                "user_email": user_email,
                "access_token": access_token,
                "export_token": export_token,
                "provider": "google",
                "token_saved_to": "database",
                "next_steps": "Use the access_token in Authorization header: 'Bearer <token>' to call /download/contacts"
            })
        else:
            return render_template('oauth_success.html', user_email=user_email, access_token=access_token, export_token=export_token, base_url=f"{config.protocol}://{config.host}:{config.port}", provider='google')

    except Exception as e:
        error_msg = str(e)
        troubleshooting = {}

        if "redirect_uri_mismatch" in error_msg:
            troubleshooting = {
                "error_type": "redirect_uri_mismatch",
                "solution": "The redirect URI in your request doesn't match what's configured in Google Cloud Console",
                "check_uri": get_redirect_uri('google'),
                "google_cloud_console": "https://console.cloud.google.com/apis/credentials",
                "steps": [
                    "Go to Google Cloud Console > APIs & Credentials > OAuth 2.0 Client IDs",
                    f"Add '{get_redirect_uri('google')}' to Authorized redirect URIs",
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
            return jsonify({
                "error": f"Google OAuth callback failed: {error_msg}",
                "troubleshooting": troubleshooting
            }), 400
        else:
            return render_template('oauth_error.html', error_message=f"Google OAuth callback failed: {error_msg}", error_details=error_msg, troubleshooting=troubleshooting), 400


@app.route('/microsoft/oauth2callback')
def microsoft_oauth2callback():
    """Handle Microsoft OAuth callback and save user-specific token."""
    config = get_config()
    
    # Get the state parameter from the callback
    state = request.args.get('state')
    
    # Get Microsoft flow row
    flow_row = get_oauth_flow_row(config, state) if state else None
    
    if not flow_row or flow_row['provider'] != 'microsoft':
        error_msg = "No Microsoft authorization flow in progress or invalid state"
        solution = "Start authorization by visiting /auth?provider=microsoft first (flows expire after 10 minutes)"
        
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
        # Delegate Microsoft-specific flow completion to providers.microsoft
        from providers.microsoft import handle_oauth_callback as ms_handle_oauth_callback
        user_email, creds = ms_handle_oauth_callback(config, flow_row)
        # Persist credentials (normalized dict)
        save_user_credentials(config, user_email, creds, provider='microsoft')

        # Generate access token for this user and persist
        access_token = generate_access_token()
        save_access_token(config, access_token, user_email, provider='microsoft')

        # Generate export token for permanent URLs
        export_token = save_export_token(config, user_email, provider='microsoft')

        # Clear the flow from database
        if state:
            delete_oauth_flow(config, state)

        # Update metrics
        OAUTH_FLOWS_TOTAL.labels(status='success').inc()

        # Respond to client
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            return jsonify({
                "status": "success",
                "message": "Microsoft authorization successful!",
                "user_email": user_email,
                "access_token": access_token,
                "export_token": export_token,
                "provider": "microsoft",
                "token_saved_to": "database",
                "next_steps": "Use the access_token in Authorization header: 'Bearer <token>' to call /download/contacts"
            })
        else:
            return render_template('oauth_success.html', user_email=user_email, access_token=access_token, export_token=export_token, base_url=f"{config.protocol}://{config.host}:{config.port}", provider='microsoft')

    except Exception as e:
        error_msg = str(e)
        troubleshooting = {}

        if "redirect_uri_mismatch" in error_msg or "invalid_request" in error_msg.lower():
            troubleshooting = {
                "error_type": "redirect_uri_mismatch",
                "solution": "The redirect URI in your request doesn't match what's configured in Azure App Registration",
                "check_uri": get_redirect_uri('microsoft'),
                "azure_portal": "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps",
                "steps": [
                    "Go to Azure Portal > App registrations > Your app > Authentication",
                    f"Add '{get_redirect_uri('microsoft')}' to Redirect URIs",
                    "Save and try again"
                ]
            }
        elif "unauthorized_client" in error_msg:
            troubleshooting = {
                "error_type": "unauthorized_client",
                "solution": "Your Azure app registration or tenant configuration is invalid",
                "check_tenant": "Verify tenant ID in credentials/microsoft.json matches your Azure tenant"
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
            return jsonify({
                "error": f"Microsoft OAuth callback failed: {error_msg}",
                "troubleshooting": troubleshooting
            }), 400
        else:
            return render_template('oauth_error.html', error_message=f"Microsoft OAuth callback failed: {error_msg}", error_details=error_msg, troubleshooting=troubleshooting), 400


@app.route('/download/contacts')
def download_contacts_endpoint() -> Any:
    """Download contacts for the authenticated user in specified format."""
    config = get_config()
    format_param = request.args.get('format', 'csv').lower()

    # Authenticate the request and determine provider from token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header",
            "example": "curl -H 'Authorization: Bearer your_access_token' http://localhost:5000/download/contacts?format=json"
        }), 401

    token = auth_header.split(' ', 1)[1]
    token_info = get_provider_from_token(token)
    if not token_info:
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header",
            "example": "curl -H 'Authorization: Bearer your_access_token' http://localhost:5000/download/contacts?format=json"
        }), 401

    user_email = token_info['user_email']
    provider = token_info['provider']

    if format_param not in ['csv', 'json']:
        return jsonify({"error": "Invalid format. Use 'csv' or 'json'"}), 400

    if not config.google_credentials_path.exists():
        return jsonify({"error": f"Credentials file not found: {config.google_credentials_path}"}), 400

    # provider is derived from the access token above

    if provider == 'google':
        service = google_provider.authenticate_google(config, user_email, save_user_credentials)
        if not service:
            return jsonify({
                "error": f"User '{user_email}' token has expired or is invalid",
                "solution": "Re-authenticate by visiting /auth to get a new access token"
            }), 401

        try:
            contacts = google_provider.download_contacts(service, page_size=config.page_size, person_fields=config.person_fields)

            if not contacts:
                return jsonify({"error": "No contacts found"}), 404

            rows = [google_provider.extract_contact_row(person) for person in contacts]

        except Exception as e:
            DOWNLOADS_TOTAL.labels(format=format_param, status='error').inc()
            return jsonify({"error": str(e)}), 500

    elif provider == 'microsoft':
        # Load microsoft credentials dict
        creds = load_user_credentials(config, user_email, provider='microsoft')
        if not creds:
            return jsonify({
                "error": f"User '{user_email}' token not found for Microsoft",
                "solution": "Re-authenticate by visiting /auth?provider=microsoft to get a new access token"
            }), 401

        # Refresh token if expired
        if creds.get('expires_at') and time.time() > creds['expires_at'] and creds.get('refresh_token'):
            # Attempt refresh via token endpoint
            ms_creds_path = config.microsoft_credentials_path
            if ms_creds_path.exists():
                ms_creds = json.loads(ms_creds_path.read_text())
                token_url = f"https://login.microsoftonline.com/{ms_creds.get('tenant','common')}/oauth2/v2.0/token"
                data = {
                    'client_id': ms_creds.get('client_id'),
                    'client_secret': ms_creds.get('client_secret'),
                    'grant_type': 'refresh_token',
                    'refresh_token': creds.get('refresh_token'),
                    'scope': ' '.join(creds.get('scopes', []))
                }
                try:
                    resp = requests.post(token_url, data=data, timeout=10)
                    resp.raise_for_status()
                    token_result = resp.json()
                    creds['access_token'] = token_result.get('access_token')
                    creds['refresh_token'] = token_result.get('refresh_token', creds.get('refresh_token'))
                    creds['expires_at'] = int(time.time()) + int(token_result.get('expires_in', 0))
                    save_user_credentials(config, user_email, creds, provider='microsoft')
                except Exception:
                    pass

        try:
            contacts = microsoft_provider.fetch_contacts(creds, page_size=config.page_size)
            if not contacts:
                return jsonify({"error": "No contacts found"}), 404
            rows = [microsoft_provider.extract_contact_row(c) for c in contacts]
        except Exception as e:
            DOWNLOADS_TOTAL.labels(format=format_param, status='error').inc()
            return jsonify({"error": str(e)}), 500

    else:
        return jsonify({"error": f"Unsupported provider: {provider}"}), 400

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


@app.route('/download/calendar')
def download_calendar() -> Any:
    """Download calendar for authenticated user (Google or Microsoft)."""
    HTTP_REQUESTS_TOTAL.labels(method="GET", endpoint="download_calendar", status_code="200").inc()

    config = get_config()

    # Authenticate user and determine provider from token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        HTTP_REQUESTS_TOTAL.labels(method="GET", endpoint="download_calendar", status_code="401").inc()
        return jsonify({
            "error": "Authentication required",
            "troubleshooting": {
                "details": "Missing or invalid Authorization header",
                "error_type": "authentication_error",
                "solution": "Provide valid Bearer token in Authorization header"
            }
        }), 401

    token = auth_header.split(' ', 1)[1]
    token_info = get_provider_from_token(token)
    if not token_info:
        HTTP_REQUESTS_TOTAL.labels(method="GET", endpoint="download_calendar", status_code="401").inc()
        return jsonify({
            "error": "Authentication required",
            "troubleshooting": {
                "details": "Missing or invalid Authorization header",
                "error_type": "authentication_error",
                "solution": "Provide valid Bearer token in Authorization header"
            }
        }), 401

    user_email = token_info['user_email']
    provider = token_info['provider']

    try:

        if provider == 'google':
            credentials = load_user_credentials(config, user_email, provider='google')
            if not credentials:
                return jsonify({
                    "error": "User not authenticated with Google",
                    "troubleshooting": {
                        "details": f"No stored credentials found for user {user_email}",
                        "error_type": "no_credentials",
                        "solution": "Complete OAuth flow first by visiting /auth"
                    }
                }), 400

            if not getattr(credentials, 'scopes', None) or 'https://www.googleapis.com/auth/calendar.readonly' not in credentials.scopes:
                return jsonify({
                    "error": "Missing calendar scope",
                    "troubleshooting": {
                        "details": "Calendar access not granted during OAuth flow",
                        "error_type": "missing_scope",
                        "solution": "Re-authorize with calendar permissions by visiting /auth"
                    }
                }), 400

            if getattr(credentials, 'expired', False) and getattr(credentials, 'refresh_token', None):
                credentials.refresh(Request())
                save_user_credentials(config, user_email, credentials, provider='google')

            calendar_ics = google_provider.fetch_google_calendar(credentials)

        elif provider == 'microsoft':
            creds = load_user_credentials(config, user_email, provider='microsoft')
            if not creds:
                return jsonify({
                    "error": "User not authenticated with Microsoft",
                    "troubleshooting": {
                        "details": f"No stored credentials found for user {user_email}",
                        "error_type": "no_credentials",
                        "solution": "Complete OAuth flow first by visiting /auth?provider=microsoft"
                    }
                }), 400

            # Try refresh if expired
            if creds.get('expires_at') and time.time() > creds['expires_at'] and creds.get('refresh_token'):
                ms_creds_path = config.microsoft_credentials_path
                if ms_creds_path.exists():
                    ms_creds = json.loads(ms_creds_path.read_text())
                    token_url = f"https://login.microsoftonline.com/{ms_creds.get('tenant','common')}/oauth2/v2.0/token"
                    data = {
                        'client_id': ms_creds.get('client_id'),
                        'client_secret': ms_creds.get('client_secret'),
                        'grant_type': 'refresh_token',
                        'refresh_token': creds.get('refresh_token'),
                        'scope': ' '.join(creds.get('scopes', []))
                    }
                    try:
                        resp = requests.post(token_url, data=data, timeout=10)
                        resp.raise_for_status()
                        token_result = resp.json()
                        creds['access_token'] = token_result.get('access_token')
                        creds['refresh_token'] = token_result.get('refresh_token', creds.get('refresh_token'))
                        creds['expires_at'] = int(time.time()) + int(token_result.get('expires_in', 0))
                        save_user_credentials(config, user_email, creds, provider='microsoft')
                    except Exception:
                        pass

            calendar_ics = microsoft_provider.fetch_microsoft_calendar(creds)

        else:
            return jsonify({"error": f"Unsupported provider: {provider}"}), 400

        DOWNLOADS_TOTAL.labels(format="ics", status="success").inc()

        response = Response(
            calendar_ics,
            mimetype='text/calendar',
            headers={
                'Content-Disposition': f'attachment; filename="calendar_{user_email.replace("@", "_")}.ics"',
                'Content-Type': 'text/calendar; charset=utf-8'
            }
        )

        HTTP_REQUESTS_TOTAL.labels(method="GET", endpoint="download_calendar", status_code="200").inc()
        return response

    except Exception as e:
        DOWNLOADS_TOTAL.labels(format="ics", status="error").inc()
        HTTP_REQUESTS_TOTAL.labels(method="GET", endpoint="download_calendar", status_code="500").inc()
        return jsonify({
            "error": "Calendar download failed",
            "troubleshooting": {
                "details": str(e),
                "error_type": "calendar_fetch_error",
                "solution": "Check calendar permissions and try again"
            }
        }), 500


@app.route('/export/contacts/<export_token>.csv')
def export_contacts_csv(export_token: str) -> Any:
    """Export contacts as CSV using permanent export token."""
    config = get_config()
    
    # Get user from export token
    token_info = get_user_from_export_token(config, export_token)
    if not token_info:
        return jsonify({"error": "Invalid export token"}), 404
    
    user_email = token_info['user_email']
    provider = token_info['provider']
    
    try:
        if provider == 'google':
            service = google_provider.authenticate_google(config, user_email, save_user_credentials)
            if not service:
                return jsonify({"error": "Authentication failed"}), 401
            
            contacts = google_provider.download_contacts(service, page_size=config.page_size, person_fields=config.person_fields)
            if not contacts:
                return jsonify({"error": "No contacts found"}), 404
            
            rows = [google_provider.extract_contact_row(person) for person in contacts]
            
        elif provider == 'microsoft':
            creds = load_user_credentials(config, user_email, provider='microsoft')
            if not creds:
                return jsonify({"error": "Authentication failed"}), 401
            
            # Refresh token if expired
            if creds.get('expires_at') and time.time() > creds['expires_at'] and creds.get('refresh_token'):
                # Token refresh logic (same as in download_contacts_endpoint)
                ms_creds_path = config.microsoft_credentials_path
                if ms_creds_path.exists():
                    ms_creds = json.loads(ms_creds_path.read_text())
                    token_url = f"https://login.microsoftonline.com/{ms_creds.get('tenant','common')}/oauth2/v2.0/token"
                    data = {
                        'client_id': ms_creds.get('client_id'),
                        'client_secret': ms_creds.get('client_secret'),
                        'grant_type': 'refresh_token',
                        'refresh_token': creds.get('refresh_token'),
                        'scope': ' '.join(creds.get('scopes', []))
                    }
                    try:
                        resp = requests.post(token_url, data=data, timeout=10)
                        resp.raise_for_status()
                        token_result = resp.json()
                        creds['access_token'] = token_result.get('access_token')
                        creds['refresh_token'] = token_result.get('refresh_token', creds.get('refresh_token'))
                        creds['expires_at'] = int(time.time()) + int(token_result.get('expires_in', 0))
                        save_user_credentials(config, user_email, creds, provider='microsoft')
                    except Exception:
                        pass
            
            contacts = microsoft_provider.fetch_contacts(creds, page_size=config.page_size)
            if not contacts:
                return jsonify({"error": "No contacts found"}), 404
            rows = [microsoft_provider.extract_contact_row(c) for c in contacts]
            
        else:
            return jsonify({"error": f"Unsupported provider: {provider}"}), 400
        
        # Generate CSV
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
        return jsonify({"error": str(e)}), 500


@app.route('/export/calendar/<export_token>.ics')
def export_calendar_ics(export_token: str) -> Any:
    """Export calendar as ICS using permanent export token."""
    config = get_config()
    
    # Get user from export token
    token_info = get_user_from_export_token(config, export_token)
    if not token_info:
        return jsonify({"error": "Invalid export token"}), 404
    
    user_email = token_info['user_email']
    provider = token_info['provider']
    
    try:
        if provider == 'google':
            credentials = load_user_credentials(config, user_email, provider='google')
            if not credentials:
                return jsonify({"error": "Authentication failed"}), 401
            
            if getattr(credentials, 'expired', False) and getattr(credentials, 'refresh_token', None):
                credentials.refresh(Request())
                save_user_credentials(config, user_email, credentials, provider='google')
            
            calendar_ics = google_provider.fetch_google_calendar(credentials)
            
        elif provider == 'microsoft':
            creds = load_user_credentials(config, user_email, provider='microsoft')
            if not creds:
                return jsonify({"error": "Authentication failed"}), 401
            
            # Token refresh logic (same as above)
            if creds.get('expires_at') and time.time() > creds['expires_at'] and creds.get('refresh_token'):
                ms_creds_path = config.microsoft_credentials_path
                if ms_creds_path.exists():
                    ms_creds = json.loads(ms_creds_path.read_text())
                    token_url = f"https://login.microsoftonline.com/{ms_creds.get('tenant','common')}/oauth2/v2.0/token"
                    data = {
                        'client_id': ms_creds.get('client_id'),
                        'client_secret': ms_creds.get('client_secret'),
                        'grant_type': 'refresh_token',
                        'refresh_token': creds.get('refresh_token'),
                        'scope': ' '.join(creds.get('scopes', []))
                    }
                    try:
                        resp = requests.post(token_url, data=data, timeout=10)
                        resp.raise_for_status()
                        token_result = resp.json()
                        creds['access_token'] = token_result.get('access_token')
                        creds['refresh_token'] = token_result.get('refresh_token', creds.get('refresh_token'))
                        creds['expires_at'] = int(time.time()) + int(token_result.get('expires_in', 0))
                        save_user_credentials(config, user_email, creds, provider='microsoft')
                    except Exception:
                        pass
            
            calendar_ics = microsoft_provider.fetch_microsoft_calendar(creds)
            
        else:
            return jsonify({"error": f"Unsupported provider: {provider}"}), 400
        
        return Response(
            calendar_ics,
            mimetype='text/calendar',
            headers={
                'Content-Disposition': f'attachment; filename="calendar_{user_email.replace("@", "_")}.ics"',
                'Content-Type': 'text/calendar; charset=utf-8'
            }
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/manage/<export_token>')
def manage_data(export_token: str) -> Any:
    """Management page for user data using export token."""
    config = get_config()
    
    # Get user from export token
    token_info = get_user_from_export_token(config, export_token)
    if not token_info:
        return render_template('error.html', error="Invalid management token"), 404
    
    user_email = token_info['user_email']
    provider = token_info['provider']
    
    # Get host for URL generation
    base_url = f"{config.protocol}://{config.host}:{config.port}"
    
    # Build export URLs
    contacts_url = f"{base_url}/export/contacts/{export_token}.csv"
    calendar_url = f"{base_url}/export/calendar/{export_token}.ics"
    
    # Get user tokens for display
    user_tokens = list_user_tokens(config, user_email, provider)
    
    return render_template('manage.html', 
                         user_email=user_email,
                         provider=provider,
                         export_token=export_token,
                         export_contacts_url=contacts_url,
                         export_calendar_url=calendar_url,
                         tokens=user_tokens,
                         base_url=base_url
                         )


@app.route('/manage/<export_token>/revoke', methods=['POST'])
def revoke_all_tokens(export_token: str) -> Any:
    """Revoke all tokens for a user."""
    config = get_config()
    
    # Get user from export token
    token_info = get_user_from_export_token(config, export_token)
    if not token_info:
        return jsonify({"error": "Invalid management token"}), 404
    
    user_email = token_info['user_email']
    provider = token_info['provider']
    
    try:
        # Revoke all access tokens for this user
        user_tokens = list_user_tokens(config, user_email, provider)
        for token in user_tokens:
            revoke_access_token(config, token, provider)
        
        # Revoke export token
        revoke_export_token(config, export_token)
        
        # Delete user credentials
        with get_database_connection(config) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_tokens WHERE user_email = ? AND provider = ?", (user_email, provider))
            conn.commit()
        
        return jsonify({
            "status": "success",
            "message": f"All tokens revoked for {user_email} ({provider})"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/token/revoke', methods=['POST'])
def revoke_token() -> Any:
    """Revoke the current access token and associated user credentials for its provider."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header"
        }), 401

    token = auth_header.split(' ', 1)[1]
    token_info = get_provider_from_token(token)
    if not token_info:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_email = token_info['user_email']
    provider = token_info['provider']

    config = get_config()
    # Revoke access token and delete associated user_tokens row for that provider
    success = revoke_access_token(config, token, provider=provider)
    if success:
        return jsonify({
            "status": "success",
            "message": f"Access token revoked for user: {user_email} (provider: {provider})"
        })
    else:
        return jsonify({"error": "Invalid or expired token"}), 401


@app.route('/health')
def health():
    """Health check endpoint."""
    config = get_config()
    if not config.google_credentials_path.exists():
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
