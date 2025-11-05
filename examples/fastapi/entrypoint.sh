#!/bin/bash
set -e

echo "🔍 Checking for CA certificate..."
if [[ -f /usr/local/share/ca-certificates/dev/ca-cert.crt ]]; then
    echo "✅ Found CA certificate, installing..."
    cp /usr/local/share/ca-certificates/dev/ca-cert.crt /usr/local/share/ca-certificates/dev-ca.crt
    update-ca-certificates
    echo "✅ CA certificates updated"
else
    echo "⚠️  No custom CA certificate found"
fi

# Drop privileges and run as appuser
echo "🔐 Dropping privileges to appuser..."
exec gosu appuser uv run uvicorn app:app --host 0.0.0.0 --port 8000
