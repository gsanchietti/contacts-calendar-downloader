# Contacts & Calendar Downloader

A **multi-tenant** Flask-based HTTP service that allows multiple users to authenticate and download their contacts and calendar events from **Google** and **Microsoft** providers using OAuth 2.0.
Access your data in CSV, JSON, or ICS formats via a simple public URL (or API endpoint).

## Key Features

✅ **Multi-Provider Support** - Google and Microsoft (Outlook/Office 365) authentication  
✅ **Multi-Tenant Architecture** - Multiple users can authenticate independently  
✅ **PostgreSQL Database** - Secure token and credentials storage with AES-256 encryption  
✅ **Contacts & Calendar Export** - Download data in CSV, JSON, or ICS formats using a public URL or API endpoint 
✅ **Bearer Token Authentication** - Secure API access with JWT-like tokens  
✅ **Auto Token Refresh** - Automatic credential renewal  
✅ **RESTful API** - Simple HTTP endpoints for all operations  
✅ **Beautiful Web Interface** - Professional UI with quick start guide  
✅ **Privacy Policy & Terms of Service** - Built-in legal documentation

## Quick Start

### Prerequisites

- Python 3.9 or newer
- PostgreSQL 12 or newer
- OAuth 2.0 credentials from Google Cloud and/or Microsoft Azure
- See [Provider Setup Guide](docs/providers.md) for detailed configuration instructions

### Local Development Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up PostgreSQL database
# Option A: Using Docker Compose (recommended)
docker-compose up postgres -d

# Option B: Using local PostgreSQL installation
createdb contacts_calendar_downloader
# Or using psql:
# psql -U postgres -c "CREATE DATABASE contacts_calendar_downloader;"

# 3. Configure environment variables
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=contacts_calendar_downloader
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=your_secure_password

# 4. Configure Google and Microsoft credentials, save the JSON files locally
# See the Provider Setup documentation for details
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

## Documentation

📚 **Complete Documentation:**

- **[API Reference](docs/api.md)** - Endpoints, authentication, and data formats
- **[Provider Setup](docs/providers.md)** - Google Cloud and Microsoft Azure configuration
- **[Deployment Guide](docs/deployment.md)** - Production deployment and operations
- **[Advanced Configuration](docs/advanced.md)** - Environment variables and technical details

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


## Security & Compliance

For production deployment, monitoring, and security details, see the [Deployment Guide](docs/deployment.md).

## Contributing

Contributions are welcome! Please see the documentation for technical details.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.
