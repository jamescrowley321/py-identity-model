"""
Token revocation (synchronous implementation).

This module provides synchronous HTTP layer for OAuth 2.0 Token
Revocation (RFC 7009).
"""

from ..core.error_handlers import handle_revocation_error
from ..core.models import TokenRevocationRequest, TokenRevocationResponse
from ..core.revocation_logic import (
    log_revocation_request,
    prepare_revocation_request_data,
    process_revocation_response,
)
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _revoke_token(client, url, data, headers, auth=None):
    """Make revocation request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def revoke_token(
    request: TokenRevocationRequest,
    http_client: HTTPClient | None = None,
) -> TokenRevocationResponse:
    """Revoke an OAuth 2.0 token (RFC 7009).

    Args:
        request: Revocation request with token and client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        TokenRevocationResponse indicating success or error.
    """
    log_revocation_request(request)
    params, headers, auth = prepare_revocation_request_data(request)

    try:
        client = http_client.client if http_client else get_http_client()
        response = _revoke_token(
            client, request.address, params, headers, auth
        )
        result = process_revocation_response(response)
        response.close()
        return result
    except Exception as e:
        return handle_revocation_error(e)


__all__ = [
    "TokenRevocationRequest",
    "TokenRevocationResponse",
    "revoke_token",
]
