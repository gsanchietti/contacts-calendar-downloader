# Use a slim, secure Python base image
FROM python:3.11-slim

# Install on /app
WORKDIR /app

# Copy and install dependencies as root (safe in containers)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash downloader

# Copy the application scripts and set ownership
COPY --chown=downloader:downloader downloader.py .

RUN chmod a+x /app/downloader.py

# Switch to non-root user
USER downloader

# Set the working directory inside the container
WORKDIR /home/downloader

# Set the entrypoint to run the script with system Python
ENTRYPOINT ["/app/downloader.py"]

# By default, if no arguments are provided to `podman run`, show the script's help message.
CMD ["--help"]
