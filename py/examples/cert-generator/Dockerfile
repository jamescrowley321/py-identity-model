FROM alpine:3.19

# Install OpenSSL, setup certificate directory, and create non-root user
RUN apk add --no-cache openssl && \
    mkdir -p /certs && \
    adduser -D -u 1000 certuser && \
    chown -R certuser:certuser /certs

# Copy the certificate generation script
COPY generate-certs.sh /generate-certs.sh
RUN chmod +x /generate-certs.sh

WORKDIR /certs

# Switch to non-root user
USER certuser

# Run the certificate generation script
CMD ["/generate-certs.sh"]
