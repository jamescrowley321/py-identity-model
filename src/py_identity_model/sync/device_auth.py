"""
Device Authorization Grant (synchronous implementation, RFC 8628).
"""

from ..core.device_auth_logic import (
    handle_device_auth_error,
    handle_device_token_error,
    log_device_auth_request,
    log_device_token_request,
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
    process_device_auth_response,
    process_device_token_response,
)
from ..core.models import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _request_device_auth(client, url, data, headers, auth=None):
    """Make device authorization request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def request_device_authorization(
    request: DeviceAuthorizationRequest,
    http_client: HTTPClient | None = None,
) -> DeviceAuthorizationResponse:
    """Request device authorization from the device authorization endpoint (RFC 8628).

    Args:
        request: Device authorization request with client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        DeviceAuthorizationResponse with ``device_code``, ``user_code``,
        and ``verification_uri`` for user display.
    """
    log_device_auth_request(request)
    params, headers, auth = prepare_device_auth_request_data(request)

    try:
        client = http_client.client if http_client else get_http_client()
        response = _request_device_auth(
            client, request.address, params, headers, auth
        )
        result = process_device_auth_response(response)
        response.close()
        return result
    except Exception as e:
        return handle_device_auth_error(e)


@retry_with_backoff()
def _poll_device_token(client, url, data, headers, auth=None):
    """Make device token poll request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def poll_device_token(
    request: DeviceTokenRequest,
    http_client: HTTPClient | None = None,
) -> DeviceTokenResponse:
    """Poll the token endpoint for device authorization completion (RFC 8628).

    Makes a single poll attempt. Check ``error_code`` on the response
    to determine whether to continue polling:

    - ``"authorization_pending"`` - poll again after ``interval`` seconds
    - ``"slow_down"`` - poll again after ``interval`` seconds (increased)
    - ``"expired_token"`` / ``"access_denied"`` - stop polling

    Args:
        request: Device token request with device code.
        http_client: Optional managed HTTP client.

    Returns:
        DeviceTokenResponse with ``token`` on success or ``error_code``
        indicating poll status.
    """
    log_device_token_request(request)
    params, headers, auth = prepare_device_token_request_data(request)

    try:
        client = http_client.client if http_client else get_http_client()
        response = _poll_device_token(
            client, request.address, params, headers, auth
        )
        result = process_device_token_response(response)
        response.close()
        return result
    except Exception as e:
        return handle_device_token_error(e)


__all__ = [
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    "poll_device_token",
    "request_device_authorization",
]
