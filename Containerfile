# Use a slim, secure Python base image
FROM python:3.13.7-slim

# Set environment variables for production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies including Node.js for building Tailwind CSS
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd --create-home -d /app --shell /bin/bash --uid 1000 downloader

# Ensure pip --user scripts are on PATH for the downloader user
ENV PATH=/app/.local/bin:${PATH}

# Switch to non-root user
USER downloader

# Create app directory
WORKDIR /app

# Copy package files and install Node.js dependencies
COPY --chown=downloader:downloader package*.json ./
RUN npm ci

# Copy Tailwind config and source files
COPY --chown=downloader:downloader tailwind.config.js ./
COPY --chown=downloader:downloader static/src ./static/src

# Build Tailwind CSS
RUN npm run build:css

# Copy and install Python dependencies
COPY --chown=downloader:downloader requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY --chown=downloader:downloader . .

# Create data directory for database and credentials
#RUN mkdir -p /app/data && chown downloader:downloader /app/


# Expose the port the service runs on
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use gunicorn as WSGI server for production with multiple workers
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "downloader:app"]
