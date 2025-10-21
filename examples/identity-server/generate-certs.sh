#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate a self-signed certificate for local development
# This creates both a .pfx file for .NET Core and separate .crt/.key files
# Include Subject Alternative Names (SAN) for proper hostname validation
openssl req -x509 -newkey rsa:4096 -keyout certs/aspnetapp.key -out certs/aspnetapp.crt -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:0.0.0.0"

# Convert to .pfx format for .NET Core
openssl pkcs12 -export -out certs/aspnetapp.pfx -inkey certs/aspnetapp.key -in certs/aspnetapp.crt -password pass:password

echo "SSL certificates generated successfully in ./certs/"
echo "Certificate password: password"
echo ""

# Detect OS and install certificate as trusted
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Linux - Installing certificate as trusted..."
    if sudo cp certs/aspnetapp.crt /usr/local/share/ca-certificates/aspnetapp.crt && sudo update-ca-certificates; then
        echo "✓ Certificate installed successfully on Linux"
    else
        echo "✗ Failed to install certificate on Linux. You may need to run with sudo."
        echo "Manual command: sudo cp certs/aspnetapp.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS - Installing certificate as trusted..."
    if sudo security add-trusted-cert -d root -r trustRoot -k /Library/Keychains/System.keychain certs/aspnetapp.crt; then
        echo "✓ Certificate installed successfully on macOS"
    else
        echo "✗ Failed to install certificate on macOS. You may need to run with sudo."
        echo "Manual command: sudo security add-trusted-cert -d root -r trustRoot -k /Library/Keychains/System.keychain certs/aspnetapp.crt"
    fi
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "Detected Windows - Please install certificate manually:"
    echo "1. Double-click certs/aspnetapp.crt"
    echo "2. Click 'Install Certificate...'"
    echo "3. Select 'Local Machine' and click 'Next'"
    echo "4. Select 'Place all certificates in the following store'"
    echo "5. Click 'Browse...' and select 'Trusted Root Certification Authorities'"
    echo "6. Click 'Next' then 'Finish'"
    echo ""
    echo "Or use PowerShell as Administrator:"
    echo "Import-Certificate -FilePath \"$(pwd)/certs/aspnetapp.crt\" -CertStoreLocation Cert:\\LocalMachine\\Root"
else
    echo "Unknown OS - Please install certificate manually:"
    echo "Certificate location: $(pwd)/certs/aspnetapp.crt"
fi

echo ""
echo "Note: You may need to restart your browser/application to recognize the new trusted certificate."