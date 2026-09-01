# Use a slim, secure Python base image
FROM python:3.13.7-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
# Tokens are stored under this path; mount a volume here to persist logins
# across container recreation.
ENV CCD_CONFIG_DIR=/data

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

ENTRYPOINT ["python", "-m", "ccd"]
CMD ["--help"]
