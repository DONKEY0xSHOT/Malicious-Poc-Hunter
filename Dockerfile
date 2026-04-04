FROM python:3.12-slim

# Install system YARA library (yara-python needs libyara)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        yara \
        libssl-dev \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/  ./backend/
COPY Rules/    ./Rules/
COPY frontend/ ./frontend/

# Create data directory for SQLite volume mount
RUN mkdir -p /data

# Non-root user for security
RUN useradd -r -u 1001 -g root appuser \
    && chown -R appuser:root /app /data
USER appuser

ENV ENV=production
ENV DATABASE_PATH=/data/poc-hunter.db
ENV RULES_DIR=/app/Rules

EXPOSE 8000

CMD ["uvicorn", "backend.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info"]
