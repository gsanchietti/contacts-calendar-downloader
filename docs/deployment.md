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
sudo -u downloader bash
git clone https://github.com/gsanchietti/google-contacts-downloader.git
cd google-contacts-downloader

# 2. Configure environment
cp .env.example .env

# Generate secure encryption key
ENCRYPTION_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env

# Edit other settings
vi .env  # Configure DOMAIN, ACME_EMAIL, etc.

# 3. Deploy services
./deploy.sh

# 4. Verify deployment
curl https://your-domain.com/health
```

#### Service URLs (Production)

- **Application**: https://your-domain.com
- **Traefik Dashboard**: http://localhost:8081 (local only)
- **Health/Metrics**: https://your-domain.com/health, /metrics

### Manual Container Deployment

For custom deployment scenarios or different container runtimes.

#### Build and Run Container

```bash
# Build image
podman build -t google-contacts-downloader .

# Create persistent volume
podman volume create contacts-data

# Run with production settings
podman run --rm --name contacts-service \
  -p 8443:8443 \
  -v contacts-data:/app/data:z \
  -v ./credentials.json:/app/credentials.json:ro,z \
  -e GOOGLE_CREDENTIALS=/app/credentials.json \
  -e DATABASE_PATH=/app/data/credentials.db \
  -e ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  -e OAUTH_REDIRECT_URI="https://your-domain.com/oauth2callback" \
  google-contacts-downloader
```

#### Docker Alternative

```bash
# Build image
docker build -t google-contacts-downloader .

# Run container
docker run --rm --name contacts-service \
  -p 8443:8443 \
  -v contacts-data:/app/data \
  -v ./credentials.json:/app/credentials.json:ro \
  -e GOOGLE_CREDENTIALS=/app/credentials.json \
  -e DATABASE_PATH=/app/data/credentials.db \
  -e ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  -e OAUTH_REDIRECT_URI="https://your-domain.com/oauth2callback" \
  google-contacts-downloader
```

## Security Configuration

### Production Security Checklist

```bash
# 1. Generate strong encryption key (REQUIRED for production)
export ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

# 2. Configure HTTPS and secure redirect URI
export OAUTH_REDIRECT_URI="https://your-production-domain.com/oauth2callback"
export PROTOCOL="https"

# 3. Secure database file permissions
chmod 600 credentials.db

# 4. Configure firewall (allow only necessary ports)
sudo ufw allow 80,443/tcp
sudo ufw --force enable

# 5. Use non-root user for service
sudo useradd -r -s /bin/false downloader
sudo chown -R downloader:downloader /path/to/app

# 6. Monitor for security warnings
curl https://your-domain.com/metrics | grep gcd_encryption_warnings_total
# Should return 0.0 (no warnings)
```

### Security Features

- ✅ **AES-256 Encryption** - Database tokens encrypted with Fernet
- ✅ **Rootless Containers** - No privileged execution required
- ✅ **Bearer Token Authentication** - Secure API access
- ✅ **HTTPS Enforcement** - Automatic SSL with Let's Encrypt
- ✅ **Non-root Execution** - Service runs as unprivileged user
- ✅ **Secure Headers** - Security headers configured in production

### Advanced Security

#### Database Encryption Details

**Encrypted Columns:**
- `user_tokens.token_data` - OAuth credentials (pickled)
- `access_tokens.access_token` - Bearer tokens

**Unencrypted Columns:**
- `user_tokens.user_email` - For efficient queries
- `access_tokens.user_email` - For token lookups

**Key Management:**
```bash
# Generate new key
NEW_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# Rotate encryption key (requires service restart)
export ENCRYPTION_KEY="$NEW_KEY"
systemctl restart contacts-downloader

# Backup old database before key rotation
cp credentials.db credentials.db.backup
```

## Monitoring & Observability

### Health Checks

```bash
# Basic health check
curl https://your-domain.com/health
# {"status": "healthy", "authenticated_users": 5}

# Detailed health with credentials check
curl https://your-domain.com/health?details=true
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
podman-compose logs -f google-contacts-downloader

# View Traefik logs
podman-compose logs -f traefik

# Search for errors
podman-compose logs google-contacts-downloader | grep ERROR
```

#### Log Rotation

```bash
# Configure log rotation for container logs
cat > /etc/logrotate.d/contacts-downloader << EOF
/var/log/podman/contacts-downloader/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0644 root root
    postrotate
        podman-compose logs google-contacts-downloader > /dev/null 2>&1 || true
    endscript
}
EOF
```

## Backup & Recovery

### Database Backup

```bash
# Automated daily backup
cat > /etc/cron.daily/contacts-backup << EOF
#!/bin/bash
BACKUP_DIR="/var/backups/contacts-downloader"
mkdir -p \$BACKUP_DIR

# Create timestamped backup
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
podman exec contacts-downloader cp /app/data/credentials.db /tmp/backup_\$TIMESTAMP.db
podman cp contacts-downloader:/tmp/backup_\$TIMESTAMP.db \$BACKUP_DIR/

# Keep only last 7 days
find \$BACKUP_DIR -name "backup_*.db" -mtime +7 -delete

# Verify backup integrity
if sqlite3 \$BACKUP_DIR/backup_\$TIMESTAMP.db "SELECT COUNT(*) FROM user_tokens;" > /dev/null 2>&1; then
    echo "Backup successful: \$TIMESTAMP"
else
    echo "Backup failed: \$TIMESTAMP" >&2
    exit 1
fi
EOF

chmod +x /etc/cron.daily/contacts-backup
```

### Complete Backup

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

## Troubleshooting

### Common Production Issues

#### Service Won't Start

```bash
# Check container status
podman-compose ps

# View startup logs
podman-compose logs google-contacts-downloader

# Check for port conflicts
netstat -tlnp | grep :8443

# Verify environment variables
podman-compose exec google-contacts-downloader env | grep -E "(ENCRYPTION|OAUTH|DATABASE)"
```

#### High Memory Usage

```bash
# Monitor memory usage
podman stats

# Check for memory leaks in application
curl https://your-domain.com/metrics | grep gcd_http

# Restart if necessary
podman-compose restart google-contacts-downloader
```

#### SSL Certificate Issues

```bash
# Check certificate status
curl -v https://your-domain.com/health 2>&1 | grep -A 5 "Server certificate"

# Renew Let's Encrypt certificates
podman-compose exec traefik traefik certificates

# Force certificate renewal
podman-compose restart traefik
```

#### Database Corruption

```bash
# Check database integrity
podman-compose exec google-contacts-downloader sqlite3 /app/data/credentials.db "PRAGMA integrity_check;"

# Repair if corrupted
podman-compose exec google-contacts-downloader sqlite3 /app/data/credentials.db ".recover" > recovered.sql
podman-compose exec google-contacts-downloader sqlite3 /app/data/credentials.db < recovered.sql
```

### Performance Tuning

#### Gunicorn Configuration

```python
# In production, adjust Gunicorn settings
bind = "0.0.0.0:8443"
workers = 4  # (2 * CPU cores) + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 10
```

#### Database Optimization

```bash
# Enable WAL mode for better concurrency
podman-compose exec google-contacts-downloader sqlite3 /app/data/credentials.db "PRAGMA journal_mode=WAL;"

# Optimize database
podman-compose exec google-contacts-downloader sqlite3 /app/data/credentials.db "VACUUM; ANALYZE;"
```

### Scaling Considerations

#### Horizontal Scaling

```bash
# Run multiple instances behind load balancer
for i in {1..3}; do
  podman run --name contacts-service-$i \
    --network contacts-net \
    -e DATABASE_PATH=/shared/data/credentials.db \
    google-contacts-downloader &
done
```

#### Database Scaling

For high-traffic deployments, consider:
- PostgreSQL instead of SQLite
- Redis for session storage
- Database connection pooling
- Read replicas for metrics

## Operational Procedures

### Service Management

```bash
# Start services
podman-compose up -d

# Stop services
podman-compose down

# Restart services
podman-compose restart

# Update deployment
podman-compose pull && podman-compose up -d

# View service status
podman-compose ps

# Monitor resource usage
podman stats
```

### Maintenance Tasks

#### Weekly Tasks

```bash
# Rotate logs
logrotate /etc/logrotate.d/contacts-downloader

# Clean old backups (keep last 4 weeks)
find /var/backups/contacts-downloader -name "backup_*.db" -mtime +28 -delete

# Database maintenance
podman-compose exec google-contacts-downloader sqlite3 /app/data/credentials.db "VACUUM;"
```

#### Monthly Tasks

```bash
# Review access logs
grep "oauth2callback" /var/log/contacts-downloader/access.log | tail -20

# Check certificate expiration
openssl x509 -in /path/to/cert.pem -text -noout | grep "Not After"

# Update dependencies
podman-compose build --no-cache google-contacts-downloader
podman-compose up -d
```

### Emergency Procedures

#### Service Outage

1. **Check service status:**
   ```bash
   podman-compose ps
   curl https://your-domain.com/health
   ```

2. **Restart services:**
   ```bash
   podman-compose restart
   ```

3. **Check logs for errors:**
   ```bash
   podman-compose logs --tail=100 google-contacts-downloader
   ```

4. **Failover if needed:**
   ```bash
   # Start backup instance
   podman run --name contacts-backup -d google-contacts-downloader
   ```

#### Security Incident

1. **Isolate the service:**
   ```bash
   podman-compose down
   ```

2. **Change encryption key:**
   ```bash
   NEW_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
   sed -i "s/ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$NEW_KEY/" .env
   ```

3. **Audit logs:**
   ```bash
   grep -i "error\|fail\|invalid" /var/log/contacts-downloader/*.log
   ```

4. **Restore from backup:**
   ```bash
   podman volume import contacts-downloader_app-data app-data-backup.tar
   ```

5. **Restart with new configuration:**
   ```bash
   podman-compose up -d
   ```

This deployment guide provides comprehensive procedures for production operation, monitoring, and maintenance of the Contacts & Calendar Downloader service.