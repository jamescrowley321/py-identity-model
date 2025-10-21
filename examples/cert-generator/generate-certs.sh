#!/bin/sh
set -e

CERT_DIR="/certs"
HOSTNAME="${CERT_HOSTNAME:-identityserver}"
DAYS="${CERT_DAYS:-365}"

echo "Generating self-signed certificates for $HOSTNAME..."

# Check if certificates already exist
if [ -f "$CERT_DIR/aspnetapp.pfx" ] && [ -f "$CERT_DIR/ca-cert.crt" ]; then
    echo "Certificates already exist. Skipping generation."
    exit 0
fi

# Generate CA private key
openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096

# Generate CA certificate
openssl req -new -x509 -days $DAYS -key "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca-cert.crt" \
    -subj "/C=US/ST=State/L=City/O=Development/OU=Testing/CN=Development CA"

# Generate server private key
openssl genrsa -out "$CERT_DIR/aspnetapp.key" 2048

# Generate certificate signing request
openssl req -new -key "$CERT_DIR/aspnetapp.key" \
    -out "$CERT_DIR/aspnetapp.csr" \
    -subj "/C=US/ST=State/L=City/O=Development/OU=Testing/CN=$HOSTNAME"

# Create extension file for SAN
cat > "$CERT_DIR/cert-ext.cnf" << EOF
subjectAltName = DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1
EOF

# Sign the certificate with our CA
openssl x509 -req -days $DAYS \
    -in "$CERT_DIR/aspnetapp.csr" \
    -CA "$CERT_DIR/ca-cert.crt" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/aspnetapp.crt" \
    -extfile "$CERT_DIR/cert-ext.cnf"

# Create PFX file for ASP.NET Core
openssl pkcs12 -export \
    -out "$CERT_DIR/aspnetapp.pfx" \
    -inkey "$CERT_DIR/aspnetapp.key" \
    -in "$CERT_DIR/aspnetapp.crt" \
    -certfile "$CERT_DIR/ca-cert.crt" \
    -password pass:password

# Set appropriate permissions
chmod 644 "$CERT_DIR"/*.crt "$CERT_DIR"/*.pfx
chmod 600 "$CERT_DIR"/*.key "$CERT_DIR"/*.pem

# Clean up intermediate files
rm -f "$CERT_DIR/aspnetapp.csr" "$CERT_DIR/cert-ext.cnf" "$CERT_DIR/ca-cert.srl"

echo "Certificate generation complete!"
echo "CA Certificate: $CERT_DIR/ca-cert.crt"
echo "Server Certificate: $CERT_DIR/aspnetapp.crt"
echo "Server Key: $CERT_DIR/aspnetapp.key"
echo "PFX Bundle: $CERT_DIR/aspnetapp.pfx"
