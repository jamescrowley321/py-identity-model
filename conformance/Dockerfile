FROM python:3.12-slim

WORKDIR /app

# Install harness dependencies
COPY conformance/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install py-identity-model from source
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Copy harness app
COPY conformance/app.py .

EXPOSE 8888

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8888"]
