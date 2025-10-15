#!/bin/bash

# Production deployment script for Google Contacts Downloader (Podman)
set -e

echo "🚀 Google Contacts Downloader - Production Deployment (Podman)"
echo "=============================================================="

# Check prerequisites
command -v podman >/dev/null 2>&1 || { echo "❌ Podman is required but not installed. Aborting." >&2; exit 1; }
command -v podman-compose >/dev/null 2>&1 || { echo "❌ Podman Compose is required but not installed. Aborting." >&2; exit 1; }

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✅ Created .env file from template"
        echo "📝 Please edit .env file with your configuration:"
        echo "   - DOMAIN: your domain name"
        echo "   - ACME_EMAIL: your email for Let's Encrypt"
        echo "   - ENCRYPTION_KEY: generate using the command below"
        echo ""
        echo "🔑 Generate encryption key:"
        echo "   python3 -c \"from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())\""
        echo ""
        echo "📋 Then run this script again to deploy"
        exit 1
    else
        echo "❌ .env.example file not found. Please create .env file manually."
        exit 1
    fi
fi

# Source environment variables
source .env

# Validate required environment variables
if [ "$DOMAIN" == "localhost" ]; then
  echo "⚠️  DOMAIN is set to 'localhost'. For production, please set it to your actual domain name in .env file."
else
  echo "✅ DOMAIN is set to '$DOMAIN': forcing PROTOCOL to https and PORT to 443"
  export HOST="$DOMAIN"
  export PROTOCOL="https"
  export PORT=443
  export GOOGLE_OAUTH_REDIRECT_URI="https://${DOMAIN}/google/oauth2callback"
  export MICROSOFT_OAUTH_REDIRECT_URI="https://${DOMAIN}/microsoft/oauth2callback"
fi


if [ -z "$ENCRYPTION_KEY" ] || [ "$ENCRYPTION_KEY" = "your-encryption-key-here" ]; then
    echo "❌ Please set ENCRYPTION_KEY in .env file"
    echo "🔑 Generate one using: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    exit 1
fi

echo "✅ Configuration validated"

# Check if services are already running
if podman-compose ps | grep -q "Up"; then
    echo "⚠️  Services are already running"
    echo
    echo "🔄 Stopping existing services..."
    podman-compose down
    echo "✅ Existing services stopped"
fi

# Generate Traefik configuration with environment variables
echo "⚙️  Generating Traefik configuration..."
cat > traefik-dynamic.yml << EOF
# Traefik Dynamic Configuration (Generated)
http:
  routers:
    # Main application router
    contacts:
      rule: "Host(\`${DOMAIN}\`)"
      entryPoints:
        - websecure
        - web
      middlewares:
        - security-headers
      service: contacts
      tls:
        certResolver: letsencrypt

  middlewares:
    # Security headers
    security-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-Proto: "https"
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
          X-Frame-Options: "DENY"
          X-XSS-Protection: "1; mode=block"
          Strict-Transport-Security: "max-age=31536000; includeSubDomains"

  services:
    contacts:
      loadBalancer:
        servers:
          - url: "http://contacts-calendar-downloader:8000"
EOF

# Build and start services
echo "🏗️  Building and starting services..."
podman-compose up -d --build

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Check service health
echo "🏥 Checking service health..."
for i in {1..30}; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo "✅ Service is healthy!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Service health check failed after 30 attempts"
        echo "📋 Checking logs..."
        podman-compose logs --tail=20 contacts-calendar-downloader
        exit 1
    fi
    echo "   Attempt $i/30..."
    sleep 2
done

# Display status
echo ""
echo "🎉 Deployment completed successfully!"
echo "=================================================="
echo "🌐 Application URL: https://$DOMAIN"
echo "🔐 OAuth Redirect URIs:"
echo "   Google: $GOOGLE_OAUTH_REDIRECT_URI"
echo "   Microsoft: $MICROSOFT_OAUTH_REDIRECT_URI"

echo ""
echo "📋 Service Status:"
podman-compose ps

echo ""
echo "📖 Useful Commands:"
echo "   View logs: podman-compose logs -f"
echo "   Stop services: podman-compose down"
echo "   Restart: podman-compose restart"
echo "   Update: podman-compose pull && podman-compose up -d --build"

echo ""
echo "⚠️  Don't forget to:"
echo "   1. Backup your encryption key securely"
echo "   2. Set up monitoring for the health endpoint"
echo "   3. Configure regular database backups"