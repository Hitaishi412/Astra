# ============================================================
# Astra — Dockerfile
# Runs FastAPI (port 8000) + Dash (port 8050) in one container
# using supervisord as the process manager.
#
# Koyeb free tier: 512MB RAM, 0.1 vCPU
# Target image size: <400MB (keeps startup time acceptable)
# ============================================================

# ── Stage 1: dependency builder ──────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies (needed for some Python packages with C extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ───────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Supervisord config — manages both API and dashboard processes
COPY docker/supervisord.conf /etc/supervisor/conf.d/astra.conf

# Port declarations (Koyeb routes external traffic to these)
EXPOSE 8000 8050

# Health check — Koyeb uses this to determine if the container is ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Start both services via supervisord
CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/astra.conf"]
