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

## Documentation

📚 **Complete Documentation:**

- **[Local Development Guide](docs/local-development.md)** - Setup for local development including Tailwind CSS
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
