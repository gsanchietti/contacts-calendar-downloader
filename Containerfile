# Use a slim, secure Python base image
FROM python:3.13.7-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
# Account records and the generated API key are stored under this path; mount
# a volume here to persist logins across container recreation.
ENV CCD_CONFIG_DIR=/data
# Bind all interfaces *inside* the container. Restricting exposure is the
# host's job: publish with -p 127.0.0.1:8080:8080.
ENV CCD_LISTEN=0.0.0.0:8080

# Create a non-root user for security, and let it own the config volume
RUN useradd --create-home -d /home/ccd --shell /usr/sbin/nologin --uid 1000 ccd \
    && mkdir -p /data \
    && chown ccd:ccd /data

WORKDIR /app

# Install Python dependencies first so they are cached independently of
# application code changes
COPY requirements.txt pyproject.toml ./
COPY ccd ./ccd
COPY providers ./providers
RUN pip install --no-cache-dir .

USER ccd

VOLUME /data
EXPOSE 8080

ENTRYPOINT ["python", "-m", "ccd"]
CMD ["serve"]
