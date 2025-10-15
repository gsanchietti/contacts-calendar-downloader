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
✅ **Prometheus Metrics** - Monitor usage and performance  
✅ **Health Checks** - Built-in health endpoint for monitoring  
✅ **Dockerized** - Easy deployment with Podman Compose (or Docker Compose) with PostgreSQL database and Traefik with Let's Encrypt


## Screenshots

To see the web interface in action, check the screenshots below.

- [Home Page](docs/screenshots/index.png)
- [Auth Page](docs/screenshots/google.png)
- [Export Page](docs/screenshots/auth_ok.png)


## Documentation

📚 **Complete Documentation:**

- **[API Reference](docs/api.md)** - Endpoints, authentication, and data formats
- **[Provider Setup](docs/providers.md)** - Google Cloud and Microsoft Azure configuration
- **[Deployment Guide](docs/deployment.md)** - Production deployment and operations
- **[Advanced Configuration](docs/advanced.md)** - Environment variables and technical details
- **[Local Development Setup](docs/local_development.md)** - Getting started for developers

## Contributing

Contributions are welcome! Please see the documentation for technical details.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.
