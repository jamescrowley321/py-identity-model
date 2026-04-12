FROM nginx:1.27.3

# Use the pre-generated self-signed cert checked into the repo rather
# than generating one at build time. This cert is for localhost.emobix.co.uk
# (the OIDF conformance suite's standard loopback hostname) and is shared
# with the RP container via a Docker volume so the library's default
# HTTP client can verify TLS when calling validate_token without an
# injected http_client (see PR #335 for the full rationale).
COPY localhost.emobix.co.uk.crt /etc/ssl/certs/nginx-selfsigned.crt
COPY localhost.emobix.co.uk.key /etc/ssl/private/nginx-selfsigned.key

COPY nginx.conf /etc/nginx/nginx.conf
