FROM python:3.12-slim

WORKDIR /app

# Install harness dependencies
COPY conformance/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install py-identity-model from source (relocated under /py in CONS-2.1; build
# context is the repo root, so the package now lives at py/).
COPY py/pyproject.toml py/README.md ./
COPY py/src/ src/
RUN pip install --no-cache-dir .

# Copy harness app
COPY conformance/app.py .

EXPOSE 8888

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8888"]
