# Use a slim, secure Python base image
### Build stage: use official Node image to build Tailwind CSS
FROM node:18-bullseye AS build-assets
WORKDIR /build

# Copy only what's needed to build CSS
COPY package.json package-lock.json* ./
COPY tailwind.config.cjs ./
COPY src ./src

RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
RUN mkdir -p /build/static/css && npm run build:css

### Final stage: Python runtime image
FROM python:3.13.7-slim

# Set environment variables for production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash --uid 1000 downloader

# Copy built static assets from the build stage
COPY --from=build-assets /build/static ./static

# Copy application files
COPY --chown=downloader:downloader . .

# Create data directory for database and credentials
RUN mkdir -p /app/data && chown downloader:downloader /app/data

# Switch to non-root user
USER downloader

# Expose the port the service runs on
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use gunicorn as WSGI server for production with multiple workers
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "downloader:app"]
