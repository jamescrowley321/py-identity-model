"""
Pushed Authorization Requests (synchronous implementation, RFC 9126).
"""

import httpx

from ..core.error_handlers import handle_par_error
from ..core.models import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
)
from ..core.par_logic import (
    log_par_request,
    prepare_par_request_data,
    process_par_response,
)
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _push_authorization_request(
    client: httpx.Client,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make PAR request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def push_authorization_request(
    request: PushedAuthorizationRequest,
    http_client: HTTPClient | None = None,
) -> PushedAuthorizationResponse:
    """Push authorization parameters to the PAR endpoint (RFC 9126).

    Args:
        request: PAR request with authorization parameters.
        http_client: Optional managed HTTP client.

    Returns:
        PushedAuthorizationResponse with ``request_uri`` and ``expires_in``.
    """
    log_par_request(request)

    response = None
    try:
        params, headers, auth = prepare_par_request_data(request)
        client = http_client.client if http_client else get_http_client()
        response = _push_authorization_request(
            client, request.address, params, headers, auth
        )
        return process_par_response(response)
    except Exception as e:
        return handle_par_error(e)
    finally:
        if response is not None:
            response.close()


__all__ = [
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    "push_authorization_request",
]
