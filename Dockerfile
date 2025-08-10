# Multi-stage Dockerfile for Git2in
# Build stage for dependency installation
FROM python:3.11-slim AS builder

# Set build arguments for version pinning
ARG PIP_VERSION=24.0
ARG SETUPTOOLS_VERSION=69.0.3

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and setuptools
RUN pip install --no-cache-dir --upgrade \
    pip==${PIP_VERSION} \
    setuptools==${SETUPTOOLS_VERSION}

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage with minimal image
FROM python:3.11-slim AS production

# Security: Install only necessary runtime packages and security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    tini \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Create non-root user with specific UID/GID
RUN groupadd -g 1000 git2in \
    && useradd -r -u 1000 -g git2in -s /sbin/nologin -c "Git2in user" git2in \
    && mkdir -p /home/git2in \
    && chown -R git2in:git2in /home/git2in

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=git2in:git2in src/ ./src/
COPY --chown=git2in:git2in run.py ./
COPY --chown=git2in:git2in setup.py ./
COPY --chown=git2in:git2in git2in ./

# Create necessary directories with proper permissions
RUN mkdir -p /data/repositories /data/logs /data/config /app/logs \
    && chown -R git2in:git2in /data /app \
    && chmod 755 /data/repositories /data/logs /data/config /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GIT2IN_DATA_DIR=/data \
    GIT2IN_REPO_BASE_PATH=/data/repositories \
    GIT2IN_LOG_DIR=/data/logs \
    GIT2IN_CONFIG_DIR=/data/config \
    GIT2IN_HOST=0.0.0.0 \
    GIT2IN_PORT=8000 \
    GIT2IN_WORKERS=4 \
    GIT2IN_LOG_LEVEL=info

# Security: Set file permissions
RUN chmod -R 755 /app \
    && find /app -type f -name "*.py" -exec chmod 644 {} \; \
    && chmod 755 /app/git2in /app/run.py

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()" || exit 1

# Switch to non-root user
USER git2in

# Use tini as PID 1 to handle signals properly
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["python", "run.py"]

# Development stage with additional tools
FROM production AS development

USER root

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    curl \
    wget \
    net-tools \
    procps \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
RUN /opt/venv/bin/pip install --no-cache-dir \
    ipython \
    ipdb \
    pytest \
    pytest-asyncio \
    pytest-cov

# Create development directories
RUN mkdir -p /app/tests /app/docs \
    && chown -R git2in:git2in /app/tests /app/docs

# Switch back to non-root user
USER git2in

# Development command with auto-reload
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]