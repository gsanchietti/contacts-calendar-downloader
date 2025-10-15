#!/usr/bin/env python3
"""Contacts & Calendar Downloader - Multi-tenant HTTP Service

This service allows multiple users to authenticate and download their contacts and calendar
events from Google and Microsoft providers. Each user gets their own credentials stored 
securely in an encrypted PostgreSQL database with provider-aware token management.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import secrets
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
import database

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
        person_fields=os.environ.get("PERSON_FIELDS", DEFAULT_PERSON_FIELDS),
        page_size=int(os.environ.get("PAGE_SIZE", "1000")),
        host=os.environ.get("HOST", "localhost"),
        port=int(os.environ.get("PORT", "5000")),
        protocol=os.environ.get("PROTOCOL", "http"),
    )


# Encryption functions are now handled by database.py
# These functions are kept for backward compatibility but are no longer used


def update_metrics(config: Config) -> None:
    """Update Prometheus metrics with current database state."""
    try:
        db = database.get_db(config)
        
        # Count registered users
        user_count = db.get_user_count()
        REGISTERED_USERS.set(user_count)
        
        # Count active access tokens  
        token_count = db.get_active_token_count()
        ACTIVE_TOKENS.set(token_count)
        
        # Get database size
        db_size = db.get_database_size()
        DATABASE_SIZE_BYTES.set(db_size)
        
    except Exception as e:
        # Don't fail the application if metrics update fails
        print(f"Warning: Failed to update metrics: {e}")


def init_database(config: Config) -> None:
    """Initialize PostgreSQL database with required tables."""
    db = database.get_db(config)
    db.init_database()
    print(f"✅ PostgreSQL database initialized successfully")


def get_oauth_flow(config: Config, state: str, provider: str = 'google') -> Optional[Flow]:
    """Retrieve OAuth flow from database and recreate Flow object."""
    db = database.get_db(config)
    row = db.get_oauth_flow_row(state)
    
    if row and row.get('provider') == provider:
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

def get_redirect_uri(provider: str = 'google') -> str:
    """Get the redirect URI for OAuth based on provider."""
    # Allow override via environment variable for production deployments
    if provider == 'google':
        redirect_uri = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")
    else:
        redirect_uri = os.environ.get("MICROSOFT_OAUTH_REDIRECT_URI")
    
    if redirect_uri:
        return redirect_uri
    
    config = get_config()
    if (config.protocol == 'https' and config.port == 443):
        base_uri = f"{config.protocol}://{config.host}"
    else:
        base_uri = f"{config.protocol}://{config.host}:{config.port}"
    
    if provider == 'microsoft':
        return f"{base_uri}/microsoft/oauth2callback"
    else:
        return f"{base_uri}/google/oauth2callback"


def generate_export_token() -> str:
    """Generate a secure export token."""
    return secrets.token_urlsafe(48)


def save_export_token(config: Config, user_email: str, provider: str = 'google') -> str:
    """Save or retrieve existing export token for user."""
    db = database.get_db(config)
    
    # Check if export token already exists
    existing_token = db.get_export_token(user_email, provider)
    if existing_token:
        return existing_token
    
    # Generate new export token
    export_token = generate_export_token()
    db.save_export_token(export_token, user_email, provider)
    return export_token

def load_user_credentials(config: Config, user_email: str, provider: str = 'google') -> Optional[Any]:
    """Load user OAuth credentials with decryption from database."""
    db = database.get_db(config)
    return db.load_user_credentials(user_email, provider)


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
    db = database.get_db(config)
    # For saving normalized credentials, we'll pickle them like other credentials
    db.save_user_credentials(user_email, normalized, provider)


def create_access_token_for_user(config: Config, user_email: str, access_token: str, provider: str = 'microsoft') -> None:
    """Create an encrypted access token for a user."""
    db = database.get_db(config)
    db.create_access_token(access_token, user_email, provider)


def generate_access_token() -> str:
    """Generate a secure access token."""
    return secrets.token_urlsafe(32)

def get_base_url(config: Config) -> str:
    """Get the base URL for the application."""
    if config.port == 443 and config.protocol == 'https':
        return f"{config.protocol}://{config.host}"
    return f"{config.protocol}://{config.host}:{config.port}"

def authenticate_request() -> Optional[str]:
    """Authenticate the current request and return user email if valid."""
    db = database.get_db(get_config())
    # Check for Authorization header with Bearer token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ', 1)[1]
    # Search across providers for the token
    return db.get_user_from_token(token, provider=None)


# Initialize database on app startup (needed for Gunicorn)
try:
    config = get_config()
    init_database(config)
    print(f"✅ Database initialized at: {"PostgreSQL database"}")
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
    db = database.get_db(config)

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
            db.store_oauth_flow(state, flow_info)

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
            db.store_oauth_flow(state, flow_info)

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
                                 base_url=get_base_url(config),
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
    db = database.get_db(config)
    
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
        db.save_user_credentials(user_email, creds, provider='google')

        # Generate access token for this user and persist
        access_token = generate_access_token()
        db.create_access_token(access_token, user_email, provider='google')

        # Generate export token for permanent URLs
        export_token = save_export_token(config, user_email, provider='google')

        # Clear the flow from database
        if state:
            db.delete_oauth_flow(state)

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
            return render_template('oauth_success.html', user_email=user_email, access_token=access_token, export_token=export_token, base_url=get_base_url(config), provider='google')

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
            db.delete_oauth_flow(state)

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
    db = database.get_db(config)
    
    # Get the state parameter from the callback
    state = request.args.get('state')
    
    # Get Microsoft flow row
    flow_row = db.get_oauth_flow_row(state) if state else None
    
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
        db.save_user_credentials(user_email, creds, provider='microsoft')

        # Generate access token for this user and persist
        access_token = generate_access_token()
        db.create_access_token(access_token, user_email, provider='microsoft')

        # Generate export token for permanent URLs
        export_token = save_export_token(config, user_email, provider='microsoft')

        # Clear the flow from database
        if state:
            db.delete_oauth_flow(state)

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
            return render_template('oauth_success.html', user_email=user_email, access_token=access_token, export_token=export_token, base_url=get_base_url(config), provider='microsoft')

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
            db.delete_oauth_flow(state)

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
    db = database.get_db(config)
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
    token_info = db.get_provider_from_token(token)
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
        service = google_provider.authenticate_google(config, user_email)
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
        creds = microsoft_provider.authenticate_microsoft(config, user_email)
        if not creds:
            return jsonify({
                "error": f"User '{user_email}' token has expired or is invalid",
                "solution": "Re-authenticate by visiting /auth?provider=microsoft to get a new access token"
            }), 401

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
    db = database.get_db(config)

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
    token_info = db.get_provider_from_token(token)
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
                db.save_user_credentials(user_email, credentials, provider='google')

            calendar_ics = google_provider.fetch_google_calendar(credentials)

        elif provider == 'microsoft':
            creds = microsoft_provider.authenticate_microsoft(config, user_email)
            if not creds:
                return jsonify({
                    "error": "User not authenticated with Microsoft",
                    "troubleshooting": {
                        "details": f"No stored credentials found for user {user_email}",
                        "error_type": "no_credentials",
                        "solution": "Complete OAuth flow first by visiting /auth?provider=microsoft"
                    }
                }), 400

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
    import sys
    config = get_config()
    db = database.get_db(config)
    
    try:
        # Get user from export token
        token_info = db.get_user_from_export_token(export_token)
        if not token_info:
            return jsonify({"error": "Invalid export token"}), 404
        
        user_email = token_info['user_email']
        provider = token_info['provider']
        
        print(f"[DEBUG] Processing export for user: {user_email}, provider: {provider}", file=sys.stderr, flush=True)
        
        if provider == 'google':
            print(f"[DEBUG] Authenticating Google user...", file=sys.stderr, flush=True)
            service = google_provider.authenticate_google(config, user_email)
            if not service:
                return jsonify({"error": "Authentication failed"}), 401
            
            print(f"[DEBUG] Downloading Google contacts...", file=sys.stderr, flush=True)
            contacts = google_provider.download_contacts(service, page_size=config.page_size, person_fields=config.person_fields)
            if not contacts:
                return jsonify({"error": "No contacts found"}), 404
            
            rows = [google_provider.extract_contact_row(person) for person in contacts]
            
        elif provider == 'microsoft':
            print(f"[DEBUG] Authenticating Microsoft user...", file=sys.stderr, flush=True)
            creds = microsoft_provider.authenticate_microsoft(config, user_email)
            if not creds:
                return jsonify({"error": "Authentication failed"}), 401
            
            print(f"[DEBUG] Downloading Microsoft contacts...", file=sys.stderr, flush=True)
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
        print(f"[ERROR] Export failed: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": str(e)}), 500


@app.route('/export/calendar/<export_token>.ics')
def export_calendar_ics(export_token: str) -> Any:
    """Export calendar as ICS using permanent export token."""
    config = get_config()
    db = database.get_db(config)
    
    # Get user from export token
    token_info = db.get_user_from_export_token(export_token)
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
                db.save_user_credentials(user_email, credentials, provider='google')
            
            calendar_ics = google_provider.fetch_google_calendar(credentials)
            
        elif provider == 'microsoft':
            creds = microsoft_provider.authenticate_microsoft(config, user_email)
            if not creds:
                return jsonify({"error": "Authentication failed"}), 401
            
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
    db = database.get_db(config)    
    
    # Get user from export token
    token_info = db.get_user_from_export_token(export_token)
    if not token_info:
        return render_template('error.html', error="Invalid management token"), 404
    
    user_email = token_info['user_email']
    provider = token_info['provider']
    
    # Get host for URL generation
    base_url = get_base_url(config)
    
    # Build export URLs
    contacts_url = f"{base_url}/export/contacts/{export_token}.csv"
    calendar_url = f"{base_url}/export/calendar/{export_token}.ics"
    
    # Get user tokens for display
    user_tokens = db.list_user_tokens(user_email, provider)
    
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
    db = database.get_db(config)
    
    # Get user from export token
    token_info = db.get_user_from_export_token(export_token)
    if not token_info:
        return jsonify({"error": "Invalid management token"}), 404
    
    user_email = token_info['user_email']
    provider = token_info['provider']
    
    try:
        # Revoke all access tokens for this user
        user_tokens = db.list_user_tokens(user_email, provider)
        for token in user_tokens:
            db.revoke_access_token(token, provider)
        
        # Revoke export token
        db.revoke_export_token(export_token)

        # Delete user credentials
        db.delete_user_credentials(user_email, provider)

        return jsonify({
            "status": "success",
            "message": f"All tokens revoked for {user_email} ({provider})"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/token/revoke', methods=['POST'])
def revoke_token() -> Any:
    """Revoke the current access token, export tokens, and associated user credentials for its provider."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "error": "Authentication required",
            "solution": "Include 'Authorization: Bearer <access_token>' header"
        }), 401
    
    db = database.get_db(get_config())
    token = auth_header.split(' ', 1)[1]
    token_info = db.get_provider_from_token(token)
    if not token_info:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_email = token_info['user_email']
    provider = token_info['provider']

    config = get_config()
    db = database.get_db(config)
    
    try:
        # Get export token before revoking (for response details)
        export_token = db.get_export_token(user_email, provider)
        
        # Revoke the export token if it exists
        export_token_revoked = False
        if export_token:
            export_token_revoked = db.revoke_export_token(export_token)
        
        # Revoke the current access token (this also deletes user credentials via database.revoke_access_token)
        access_token_revoked = db.revoke_access_token(token, provider=provider)
        if not access_token_revoked:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        return jsonify({
            "status": "success",
            "message": f"All tokens and credentials revoked for user: {user_email} (provider: {provider})",
            "details": {
                "access_token_revoked": True,
                "export_token_revoked": export_token_revoked,
                "credentials_deleted": True,
                "user_email": user_email,
                "provider": provider
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": "Failed to revoke tokens",
            "details": str(e)
        }), 500


@app.route('/health')
def health():
    """Health check endpoint."""
    config = get_config()
    if not config.google_credentials_path.exists() or not config.microsoft_credentials_path.exists():
        return jsonify({"status": "unhealthy", "error": "One or more credential files not found"}), 500
    
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
    print(f"Database initialized at: {"PostgreSQL database"}")
    
    port = int(os.environ.get("PORT", "5000"))
    app.run(host='0.0.0.0', port=port, debug=True)
