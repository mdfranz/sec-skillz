# Stage 1: Builder
FROM python:3.13-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
# These are needed for compiling some Python packages but not for runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    libtool \
    automake \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install uv (using the official image is the cleanest way)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy requirements file
COPY requirements.txt .

# Create virtual environment and install dependencies
# We use a virtual env so we can easily copy it to the next stage
RUN uv venv /app/.venv && \
    uv pip install --no-cache -r requirements.txt


# Stage 2: Runtime
FROM python:3.13-slim-bookworm

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    GOOGLE_API_KEY="" \
    ANTHROPIC_API_KEY="" \
    OPENAI_API_KEY=""

# Install runtime dependencies
# 'jq' is specified as a requirement for data analysis pipelines
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY . .

# Create directories for data and skills to be mounted
# Ensure the non-root user has ownership
RUN mkdir -p /app/data /app/skills && \
    chown -R appuser:appuser /app/data /app/skills /app

# Expose volumes for persistence and configuration
VOLUME /app/data
VOLUME /app/skills

# Switch to the non-root user
USER appuser

# Default entrypoint to the runner script
ENTRYPOINT ["python", "runner.py"]
