#!/bin/bash
set -e

echo "🔍 Checking for certificate..."
CERT_PATH="${ASPNETCORE_Kestrel__Certificates__Default__Path}"

if [ ! -z "$CERT_PATH" ]; then
    # Wait for certificate to be available (max 30 seconds)
    for i in $(seq 1 30); do
        if [ -f "$CERT_PATH" ]; then
            echo "✅ Found certificate at $CERT_PATH"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "⚠️  Certificate not found at $CERT_PATH after 30 seconds"
            echo "📋 Directory contents:"
            ls -la "$(dirname "$CERT_PATH")" 2>/dev/null || echo "Directory does not exist"
        fi
        sleep 1
    done
fi

echo "🚀 Starting Identity Server..."
exec dotnet IdentityServer.dll
