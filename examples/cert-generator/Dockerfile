FROM alpine:3.19

# Install OpenSSL
RUN apk add --no-cache openssl

# Create directory for certificates
RUN mkdir -p /certs

# Copy the certificate generation script
COPY generate-certs.sh /generate-certs.sh
RUN chmod +x /generate-certs.sh

WORKDIR /certs

# Run the certificate generation script
CMD ["/generate-certs.sh"]
