#!/bin/bash
set -e

echo "🔍 Checking for CA certificate..."
if [[ -f /usr/local/share/ca-certificates/dev/ca-cert.crt ]]; then
    echo "✅ Found CA certificate, installing..."
    cp /usr/local/share/ca-certificates/dev/ca-cert.crt /usr/local/share/ca-certificates/dev-ca.crt
    update-ca-certificates
    echo "✅ CA certificates updated"
    echo "📋 REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE"
    echo "📋 SSL_CERT_FILE=$SSL_CERT_FILE"
else
    echo "⚠️  CA certificate not found at /usr/local/share/ca-certificates/dev/ca-cert.crt"
    ls -la /usr/local/share/ca-certificates/ || true
fi

# Drop privileges and run as appuser
echo "🔐 Dropping privileges to appuser..."
exec gosu appuser /workspace/.venv/bin/python test_integration.py
