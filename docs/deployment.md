# Deployment Guide

This document covers production deployment, security configuration, monitoring, and operational procedures for the Contacts & Calendar Downloader service.

Before beginning, ensure you have completed the [Provider Setup](providers.md) to obtain Google and Microsoft OAuth credentials.

## Production Deployment Options

### Podman Compose (Rootless) - Recommended

Deploy with rootless Podman using the included compose configuration for production-ready deployment with automatic SSL.

#### Prerequisites

```bash
# Install Podman and Podman Compose on RHEL/Rocky Linux
dnf install epel-release
dnf install podman podman-compose

# Configure rootless Podman
useradd downloader -s /bin/bash -m
loginctl enable-linger downloader

# Allow unprivileged ports (80, 443) for rootless Podman
echo "net.ipv4.ip_unprivileged_port_start=80" | tee /etc/sysctl.d/user_priv_ports.conf
sysctl -p /etc/sysctl.d/user_priv_ports.conf
```

#### Quick Production Deploy

```bash
# 1. Clone repository as service user
su -u downloader
git clone https://github.com/gsanchietti/contacts-calendar-downloader.git
cd contacts-calendar-downloader

# 2. Configure environment
cp .env.example .env

# 3. Generate secure encryption key and PostgreSQL password, set them in .env
ENCRYPTION_KEY=$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '\n')
POSTGRES_PASSWORD=$(uuidgen | sha1sum | awk '{print $1}')

# 4. Edit other settings
vi .env  # Configure DOMAIN, ACME_EMAIL, etc.

# 5. Download credentials files from Microsoft and Google Cloud and save them in the credentials directory
mkdir -p credentials
# Save your credentials files as:
# credentials/google.json
# credentials/microsoft.json

# 6. Deploy services
./deploy.sh

# 7. Verify deployment
curl https://your-domain.com/health
```

#### Port Configuration

The service uses different ports depending on the deployment method:

- **Development**: Runs on port `5000` (default, configurable via `PORT` environment variable)
- **Container**: Internal port `8000` (mapped to host port via `PORT` environment variable)
- **Production with Traefik**: Ports `80`/`443` (handled by Traefik reverse proxy)

### Manual Container Deployment

For custom deployment scenarios or different container runtimes.

#### Build and Run Container

```bash
# Build image
podman build -t contacts-calendar-downloader .

# Run with production settings (requires external PostgreSQL)
podman run --rm --name contacts-service \
  -p 8443:8443 \
  -v ./credentials.json:/app/credentials.json:ro,z \
  -e GOOGLE_CREDENTIALS=/app/credentials.json \
  -e POSTGRES_HOST=your-postgres-host \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_DB=downloader \
  -e POSTGRES_USER=downloader \
  -e POSTGRES_PASSWORD=your-secure-password \
  -e ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  -e GOOGLE_OAUTH_REDIRECT_URI="https://your-domain.com/google/oauth2callback" \
  -e MICROSOFT_OAUTH_REDIRECT_URI="https://your-domain.com/microsoft/oauth2callback" \
  contacts-calendar-downloader
```

#### Docker Alternative

```bash
# Build image
docker build -t contacts-calendar-downloader .

# Run container (requires external PostgreSQL)
docker run --rm --name contacts-service \
  -p 8443:8443 \
  -v ./credentials.json:/app/credentials.json:ro \
  -e GOOGLE_CREDENTIALS=/app/credentials.json \
  -e POSTGRES_HOST=your-postgres-host \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_DB=contacts_calendar_downloader \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=your-secure-password \
  -e ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  -e GOOGLE_OAUTH_REDIRECT_URI="https://your-domain.com/google/oauth2callback" \
  -e MICROSOFT_OAUTH_REDIRECT_URI="https://your-domain.com/microsoft/oauth2callback" \
  contacts-calendar-downloader
```

**Note:** These examples require an external PostgreSQL server. For a complete production setup with PostgreSQL included, use the Docker Compose configuration (see Quick Production Deploy section above).

## Monitoring & Observability

### Status and Metrics

See `/health` and `/metrics` endpoints inside [API](api.md) for details.

### Logs

```bash
# View application logs
podman-compose logs -f contacts-calendar-downloader

# View Traefik logs
podman-compose logs -f traefik

# Search for errors
podman-compose logs contacts-calendar-downloader | grep ERROR
```


## Backup & Recovery

```bash
# Full container backup
podman volume export contacts-calendar-downloader_app-data > contacts-calendar-downloader_app-data.tar
podman volume export contacts-calendar-downloader_traefik-letsencrypt > traefik-letsencrypt-backup.tar
podman volume export contacts-calendar-downloader_postgres-data > postgres-data-backup.tar

# Backup configuration
tar czf config-backup.tar.gz \
  .env \
  credentials/ \
  traefik.yml \
  compose.yml
```

### Recovery Procedures

```bash
# 1. Stop services
podman-compose down

# 2. Restore volume
podman volume import contacts-calendar-downloader_app-data < contacts-calendar-downloader_app-data.tar
podman volume import contacts-calendar-downloader_traefik-letsencrypt < traefik-letsencrypt-backup.tar
podman volume import contacts-calendar-downloader_postgres-data < postgres-data-backup.tar

# 3. Restore configuration
tar xzf config-backup.tar.gz

# 4. Restart services
./deploy.sh

# 5. Verify restoration
curl https://your-domain.com/health
```
