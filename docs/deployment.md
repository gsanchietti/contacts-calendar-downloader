# Deployment Guide

This document covers production deployment, security configuration, monitoring, and operational procedures for the Contacts & Calendar Downloader service.

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

# Generate secure encryption key and PostgreSQL password, set them in .env
ENCRYPTION_KEY=$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '\n')
POSTGRES_PASSWORD=$(uuidgen | sha1sum | awk '{print $1}')

# Edit other settings
vi .env  # Configure DOMAIN, ACME_EMAIL, etc.

# 3. Deploy services
./deploy.sh

# 4. Verify deployment
curl https://your-domain.com/health
```

#### Service URLs (Production)

- **Application**: https://your-domain.com
- **Health/Metrics**: https://your-domain.com/health, /metrics

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

### Health Checks

```bash
# Basic health check
curl https://your-domain.com/health
# {"status": "healthy"}

# Health check (credentials validation included)
curl https://your-domain.com/health
```

### Prometheus Metrics

The service exposes comprehensive metrics for monitoring:

```bash
# Get all metrics
curl https://your-domain.com/metrics
```

**Key Metrics to Monitor:**

- `gcd_registered_users_total` - Total registered users
- `gcd_active_tokens_total` - Active access tokens
- `gcd_downloads_total{format,status}` - Downloads by format/status
- `gcd_contacts_downloaded_total` - Total contacts downloaded
- `gcd_oauth_flows_total{status}` - OAuth success/failure rates
- `gcd_database_size_bytes` - Database size monitoring
- `gcd_encryption_warnings_total` - Security configuration alerts
- `gcd_http_request_duration_seconds` - Response time histogram

#### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'contacts-downloader'
    static_configs:
      - targets: ['your-domain.com']
    scrape_interval: 30s
    metrics_path: /metrics
    scheme: https
```

#### Grafana Dashboard Examples

```promql
# Success rate
rate(gcd_http_requests_total{status_code=~"2.."}[5m]) /
rate(gcd_http_requests_total[5m])

# 95th percentile response time
histogram_quantile(0.95, rate(gcd_http_request_duration_seconds_bucket[5m]))

# OAuth failure rate
rate(gcd_oauth_flows_total{status="error"}[5m])

# Database growth
increase(gcd_database_size_bytes[1h])
```

### Log Monitoring

#### Container Logs

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
podman volume export contacts-downloader_app-data > app-data-backup.tar

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
podman volume import contacts-downloader_app-data app-data-backup.tar

# 3. Restore configuration
tar xzf config-backup.tar.gz

# 4. Restart services
podman-compose up -d

# 5. Verify restoration
curl https://your-domain.com/health
```
