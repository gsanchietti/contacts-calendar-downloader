# Local Development Setup

## Prerequisites

- Python 3.9 or newer
- PostgreSQL 12 or newer
- OAuth 2.0 credentials from Google Cloud and/or Microsoft Azure
- See [Provider Setup Guide](docs/providers.md) for detailed configuration instructions

## Local Development Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment variables
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=contacts_calendar_downloader
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=your_secure_password

# 3. Configure Google and Microsoft credentials, save the JSON files locally
# See the Provider Setup documentation for details
mkdir -p credentials
# Save your credentials files as:
# credentials/google.json
# credentials/microsoft.json
export GOOGLE_CREDENTIALS=./credentials/google.json
export MICROSOFT_CREDENTIALS=./credentials/microsoft.json

# 5. Start the service
python downloader.py

# 6. Visit the web interface
# Open http://localhost:5000/ in your browser

# 7. Or use the API directly
curl http://localhost:5000/auth?provider=google | jq -r '.authorization_url'
# Open the URL, authorize, then use the access token to download data
```

The service runs on `http://localhost:5000` by default. For production deployment, environment variables, and advanced configuration, see the [Deployment Guide](docs/deployment.md) and [Advanced Configuration](docs/advanced.md).

## Usage Examples

```bash
# 1. Get authorization URL
curl http://localhost:5000/auth?provider=google | jq -r '.authorization_url'

# 2. Open URL in browser and authorize

# 3. Download contacts
curl -H "Authorization: Bearer <token>" \
  "http://localhost:5000/download/contacts?format=json" > contacts.json

# 4. Download calendar
curl -H "Authorization: Bearer <token>" \
  "http://localhost:5000/download/calendar" > calendar.ics
```

For complete API documentation and more examples, see the [API Reference](docs/api.md).
