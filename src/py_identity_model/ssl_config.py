"""
SSL certificate configuration utilities.

This module provides backward compatibility for SSL certificate environment variables
when migrating from requests to httpx.
"""

import os


def ensure_ssl_compatibility() -> None:
    """
    Ensure backward compatibility for SSL certificate environment variables.

    httpx respects SSL_CERT_FILE and CURL_CA_BUNDLE, but not REQUESTS_CA_BUNDLE
    (which was used by the requests library). For backward compatibility, if
    REQUESTS_CA_BUNDLE is set but SSL_CERT_FILE is not, we set SSL_CERT_FILE
    to the value of REQUESTS_CA_BUNDLE.

    This function is called automatically when the library is imported, so users
    don't need to call it explicitly.

    Environment variables checked (in priority order):
    1. SSL_CERT_FILE - httpx native variable (highest priority)
    2. CURL_CA_BUNDLE - also respected by httpx
    3. REQUESTS_CA_BUNDLE - legacy requests library variable (for backward compatibility)
    """
    # Only set SSL_CERT_FILE if it's not already set
    if "SSL_CERT_FILE" not in os.environ:
        # Check CURL_CA_BUNDLE first (also respected by httpx)
        if "CURL_CA_BUNDLE" in os.environ:
            # CURL_CA_BUNDLE is already set and httpx will use it
            pass
        # Then check REQUESTS_CA_BUNDLE for backward compatibility
        elif "REQUESTS_CA_BUNDLE" in os.environ:
            # Set SSL_CERT_FILE to REQUESTS_CA_BUNDLE value for httpx to use
            os.environ["SSL_CERT_FILE"] = os.environ["REQUESTS_CA_BUNDLE"]


# Initialize SSL compatibility when module is imported
ensure_ssl_compatibility()


__all__ = ["ensure_ssl_compatibility"]
