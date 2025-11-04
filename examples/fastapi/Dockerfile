FROM python:3.12-slim

WORKDIR /app

# Install system dependencies including CA certificates and uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

# Copy workspace files
COPY pyproject.toml /workspace/pyproject.toml
COPY uv.lock /workspace/uv.lock
COPY README.md /workspace/README.md
COPY src /workspace/src
COPY examples/fastapi /workspace/examples/fastapi

# Set workspace root
WORKDIR /workspace

# Install dependencies using workspace
RUN uv sync --all-packages

# Switch to example directory
WORKDIR /workspace/examples/fastapi

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /workspace

# Copy entrypoint script
COPY examples/fastapi/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose FastAPI port
EXPOSE 8000

# Note: Running as root is required for update-ca-certificates in entrypoint
# Update CA certificates at runtime if custom CA is mounted
CMD ["/entrypoint.sh"]
