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
PERSON_FIELDS="names,emailAddresses,phoneNumbers,addresses,organizations,birthdays"  # Google People API fields
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
- **Note**: Used to construct redirect URIs like `http://HOST:PORT/oauth2callback`

#### PORT
- **Type**: Integer
- **Default**: `5000`
- **Description**: Server port used for OAuth redirect URI generation
- **Note**: Used to construct redirect URIs like `http://HOST:PORT/oauth2callback`

#### PROTOCOL
- **Type**: String (`http` or `https`)
- **Default**: `http`
- **Description**: Protocol used for OAuth redirect URI generation
- **Production**: Should be `https` in production environments

#### FLASK_SECRET_KEY
- **Type**: String (hex)
- **Default**: Auto-generated 32-byte hex string
- **Description**: Flask session secret for session cookie signing
- **Note**: Auto-generated if not provided, but setting explicitly ensures consistency across restarts

#### GOOGLE_OAUTH_REDIRECT_URI
- **Type**: URL string
- **Default**: None (uses `PROTOCOL://HOST:PORT/oauth2callback`)
- **Description**: Override the OAuth redirect URI for Google provider specifically
- **Use Case**: When behind reverse proxy or using custom domain

#### MICROSOFT_OAUTH_REDIRECT_URI
- **Type**: URL string
- **Default**: None (uses `PROTOCOL://HOST:PORT/oauth2callback`)
- **Description**: Override the OAuth redirect URI for Microsoft provider specifically
- **Use Case**: When behind reverse proxy or using custom domain

#### PERSON_FIELDS
- **Type**: Comma-separated string
- **Default**: `names,emailAddresses,phoneNumbers,addresses,organizations,birthdays`
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

The service uses SQLite with the following tables:

#### user_tokens Table

```sql
CREATE TABLE user_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT UNIQUE NOT NULL,
    user_hash TEXT,  -- Legacy field
    provider TEXT NOT NULL DEFAULT 'google',
    token_data TEXT NOT NULL,  -- Encrypted OAuth credentials
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### access_tokens Table

```sql
CREATE TABLE access_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    access_token TEXT NOT NULL,  -- Encrypted Bearer token
    export_token TEXT UNIQUE,     -- Public export token
    provider TEXT NOT NULL DEFAULT 'google',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES user_tokens(user_email)
);
```

#### downloads Table

```sql
CREATE TABLE downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    format TEXT NOT NULL,  -- csv/json
    item_count INTEGER DEFAULT 0,
    provider TEXT NOT NULL DEFAULT 'google',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT
);
```

### Database Operations

#### Initialization

```python
from database import init_database, get_db_connection

# Initialize database
init_database()

# Get connection
conn = get_db_connection()
```

#### User Token Management

```python
from database import save_user_token, get_user_token, delete_user_token

# Save OAuth token
save_user_token(user_email, token_data, provider='google')

# Retrieve token
token_data = get_user_token(user_email)

# Delete token
delete_user_token(user_email)
```

#### Access Token Management

```python
from database import create_access_token, validate_access_token, revoke_access_token

# Create Bearer token
access_token = create_access_token(user_email, provider='google')

# Validate token
user_info = validate_access_token(access_token)

# Revoke token
revoke_access_token(access_token)
```

### Encryption Details

#### AES-256 Encryption

The service uses Fernet (AES 128 in CBC mode + HMAC) for encryption:

```python
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()

# Encrypt data
f = Fernet(key)
encrypted = f.encrypt(data.encode())

# Decrypt data
decrypted = f.decrypt(encrypted).decode()
```

#### Encrypted Fields

- **user_tokens.token_data**: Pickled OAuth credentials
- **access_tokens.access_token**: Bearer tokens for API access

#### Key Management

```bash
# Generate secure key
ENCRYPTION_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# Set in environment
export ENCRYPTION_KEY="$ENCRYPTION_KEY"

# Key rotation (requires service restart)
# 1. Generate new key
# 2. Update ENCRYPTION_KEY environment variable
# 3. Restart service
# 4. Old data remains encrypted with old key until re-encrypted
```

## Security Features

### Authentication & Authorization

#### Bearer Token Authentication

```python
from functools import wraps
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        user_info = validate_access_token(token)
        if not user_info:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Add user info to request context
        request.user_email = user_info['user_email']
        request.provider = user_info['provider']
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/download/contacts')
@require_auth
def download_contacts():
    # Access user info via request.user_email, request.provider
    pass
```

#### OAuth Flow Security

- **State Parameter**: Prevents CSRF attacks
- **PKCE**: Proof Key for Code Exchange (future enhancement)
- **HTTPS Enforcement**: Required for production OAuth
- **Redirect URI Validation**: Strict URI matching

### Data Protection

#### Input Validation

```python
import re
from werkzeug.exceptions import BadRequest

def validate_email(email):
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise BadRequest('Invalid email format')

def validate_provider(provider):
    if provider not in ['google', 'microsoft']:
        raise BadRequest('Invalid provider')

def sanitize_filename(filename):
    return re.sub(r'[^\w\-_\.]', '_', filename)
```

#### Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

@app.route('/auth')
@limiter.limit("10 per minute")
def auth():
    pass

@app.route('/download/contacts')
@limiter.limit("50 per hour")
@require_auth
def download_contacts():
    pass
```

### Audit Logging

#### Security Events

```python
import logging

security_logger = logging.getLogger('security')

def log_security_event(event_type, user_email, details=None):
    security_logger.info(f'{event_type} - {user_email} - {details or ""}')

# Usage
log_security_event('OAUTH_SUCCESS', user_email, {'provider': 'google'})
log_security_event('TOKEN_REVOKED', user_email, {'reason': 'user_request'})
log_security_event('DOWNLOAD_ATTEMPT', user_email, {'format': 'csv', 'count': 150})
```

## Monitoring & Metrics

### Prometheus Metrics

#### Custom Metrics Implementation

```python
from prometheus_client import Counter, Histogram, Gauge

# Counters
oauth_flows_total = Counter(
    'gcd_oauth_flows_total',
    'Total OAuth flows',
    ['status']
)

downloads_total = Counter(
    'gcd_downloads_total',
    'Total downloads',
    ['format', 'status']
)

# Gauges
registered_users_total = Gauge(
    'gcd_registered_users_total',
    'Total registered users'
)

active_tokens_total = Gauge(
    'gcd_active_tokens_total',
    'Total active tokens'
)

# Histograms
http_request_duration = Histogram(
    'gcd_http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)
```

#### Metrics Collection

```python
@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    duration = time.time() - request.start_time
    http_request_duration.labels(
        method=request.method,
        endpoint=request.endpoint
    ).observe(duration)
    return response
```

### Health Checks

#### Comprehensive Health Endpoint

```python
@app.route('/health')
def health():
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }
    
    # Check database connectivity
    try:
        conn = get_db_connection()
        conn.execute('SELECT 1')
        health_status['database'] = 'connected'
    except Exception as e:
        health_status['database'] = f'error: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Check credentials
    health_status['credentials'] = {
        'google': os.path.exists(os.getenv('GOOGLE_CREDENTIALS', 'credentials/google.json')),
        'microsoft': os.path.exists(os.getenv('MICROSOFT_CREDENTIALS', 'credentials/microsoft.json'))
    }
    
    # Check encryption
    if not os.getenv('ENCRYPTION_KEY'):
        health_status['encryption'] = 'warning: no key set'
        health_status['status'] = 'degraded'
    else:
        health_status['encryption'] = 'configured'
    
    # User statistics
    try:
        users_count = conn.execute('SELECT COUNT(*) FROM user_tokens').fetchone()[0]
        tokens_count = conn.execute('SELECT COUNT(*) FROM access_tokens WHERE expires_at > datetime("now")').fetchone()[0]
        health_status['users'] = users_count
        health_status['active_tokens'] = tokens_count
    except:
        health_status['users'] = 'unknown'
        health_status['active_tokens'] = 'unknown'
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code
```

## Performance Optimization

### Database Optimization

#### Connection Pooling

```python
import sqlite3
from contextlib import contextmanager

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(
        DATABASE,
        check_same_thread=False,
        timeout=30.0
    )
    conn.row_factory = sqlite3.Row
    try:
        # Enable WAL mode for better concurrency
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=-64000')  # 64MB cache
        yield conn
    finally:
        conn.close()
```

#### Query Optimization

```sql
-- Add indexes for performance
CREATE INDEX idx_user_tokens_email ON user_tokens(user_email);
CREATE INDEX idx_access_tokens_email ON access_tokens(user_email);
CREATE INDEX idx_access_tokens_export ON access_tokens(export_token);
CREATE INDEX idx_downloads_user ON downloads(user_email);

-- Optimize for common queries
EXPLAIN QUERY PLAN
SELECT * FROM user_tokens WHERE user_email = ?;

EXPLAIN QUERY PLAN
SELECT * FROM access_tokens WHERE export_token = ? AND expires_at > datetime('now');
```

### API Optimization

#### Pagination Handling

```python
def fetch_all_contacts(service, page_size=1000):
    """Fetch all contacts with automatic pagination"""
    contacts = []
    page_token = None
    
    while True:
        results = service.people().connections().list(
            resourceName='people/me',
            pageSize=page_size,
            personFields=PERSON_FIELDS,
            pageToken=page_token
        ).execute()
        
        contacts.extend(results.get('connections', []))
        page_token = results.get('nextPageToken')
        
        if not page_token:
            break
    
    return contacts
```

#### Caching Strategy

```python
from flask_caching import Cache

cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0'
})

@app.route('/download/contacts')
@cache.cached(timeout=300, key_prefix=lambda: f"contacts_{request.user_email}")
@require_auth
def download_contacts():
    # Cache results for 5 minutes per user
    pass
```

### Memory Management

#### Large Dataset Handling

```python
def stream_csv_response(contacts):
    """Stream CSV response for large datasets"""
    def generate():
        writer = csv.writer(io.StringIO())
        
        # Write header
        yield writer.writerow(['Full Name', 'Email', 'Phone'])
        
        # Write data in chunks
        for contact in contacts:
            row = extract_contact_data(contact)
            yield writer.writerow(row)
    
    return Response(
        generate(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=contacts.csv'}
    )
```

## Error Handling

### Global Error Handlers

```python
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'error': 'Bad Request',
        'message': str(error),
        'status_code': 400
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Valid Bearer token required',
        'status_code': 401
    }), 401

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'error': 'Rate Limit Exceeded',
        'message': 'Too many requests',
        'status_code': 429
    }), 429

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Internal error: {str(error)}')
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred',
        'status_code': 500
    }), 500
```

### Provider-Specific Error Handling

```python
def handle_google_api_error(error):
    """Handle Google API specific errors"""
    if error.resp.status == 401:
        # Token expired, try refresh
        return refresh_google_token()
    elif error.resp.status == 403:
        # Insufficient permissions
        raise BadRequest('Insufficient Google API permissions')
    elif error.resp.status == 429:
        # Rate limited
        raise TooManyRequests('Google API rate limit exceeded')
    else:
        app.logger.error(f'Google API error: {error}')
        raise InternalServerError('Google API error')

def handle_microsoft_api_error(error):
    """Handle Microsoft Graph API specific errors"""
    if 'invalid_token' in str(error):
        return refresh_microsoft_token()
    elif 'insufficient_privileges' in str(error):
        raise BadRequest('Insufficient Microsoft Graph permissions')
    else:
        app.logger.error(f'Microsoft Graph error: {error}')
        raise InternalServerError('Microsoft Graph API error')
```

## Development & Testing

### Testing Configuration

```bash
# Test environment variables
export FLASK_ENV="testing"
export TESTING="true"
export DATABASE=":memory:"  # Use in-memory database for tests

# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### Development Tools

#### Debug Mode

```python
if app.debug:
    # Enable debug toolbar
    from flask_debugtoolbar import DebugToolbarExtension
    toolbar = DebugToolbarExtension(app)
    
    # Log all SQL queries
    import logging
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
```

#### Profiling

```python
from werkzeug.middleware.profiler import ProfilerMiddleware

app.wsgi_app = ProfilerMiddleware(app.wsgi_app, profile_dir='./profiles')
```

This advanced configuration guide covers all technical aspects of the Contacts & Calendar Downloader service, from low-level database operations to high-level security and performance considerations.