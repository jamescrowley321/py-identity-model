FROM python:3.12-slim

WORKDIR /app

# Install system dependencies including CA certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

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

# Expose FastAPI port
EXPOSE 8000

# Update CA certificates at runtime if custom CA is mounted
CMD sh -c ' \
    echo "🔍 Checking for CA certificate..."; \
    if [ -f /usr/local/share/ca-certificates/dev/ca-cert.crt ]; then \
        echo "✅ Found CA certificate, installing..."; \
        cp /usr/local/share/ca-certificates/dev/ca-cert.crt /usr/local/share/ca-certificates/dev-ca.crt && \
        update-ca-certificates && \
        echo "✅ CA certificates updated"; \
    else \
        echo "⚠️  No custom CA certificate found"; \
    fi && \
    uv run uvicorn app:app --host 0.0.0.0 --port 8000'
