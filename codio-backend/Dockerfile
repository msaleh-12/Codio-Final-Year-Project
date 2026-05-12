FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY . /app

# Ensure cache folder exists
RUN mkdir -p /app/codio_cache

EXPOSE 8080

# Use gunicorn with the wsgi entrypoint
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "wsgi:app"]
