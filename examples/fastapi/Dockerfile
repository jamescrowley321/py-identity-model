FROM python:3.12-slim

WORKDIR /app

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

# Run the FastAPI application
CMD ["uv", "run", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
