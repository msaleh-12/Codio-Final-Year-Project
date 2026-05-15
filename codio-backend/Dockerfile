FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies needed by yt-dlp, OpenCV, and gunicorn builds
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        build-essential \
        ffmpeg \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY . /app

# Ensure cache folder exists
RUN mkdir -p /app/codio_cache

ENV PORT=8080

EXPOSE 8080

# Use a single worker with threads to reduce memory pressure on Render's smaller instances.
# Bind to Render's PORT when available, otherwise fall back to 8080 for local/container runs.
CMD ["sh", "-c", "gunicorn -w 1 --threads 4 --timeout 600 --graceful-timeout 120 -b 0.0.0.0:${PORT:-8080} wsgi:app"]
