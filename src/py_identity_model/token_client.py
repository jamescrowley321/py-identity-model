from dataclasses import dataclass

import requests

from .logging_config import logger
from .logging_utils import redact_url


@dataclass
class ClientCredentialsTokenRequest:
    address: str
    client_id: str
    client_secret: str
    scope: str


@dataclass
class ClientCredentialsTokenResponse:
    is_successful: bool
    token: dict | None = None
    error: str | None = None


def request_client_credentials_token(
    request: ClientCredentialsTokenRequest,
) -> ClientCredentialsTokenResponse:
    logger.info(
        f"Requesting client credentials token from {redact_url(request.address)}",
    )
    logger.debug(f"Client ID: {request.client_id}, Scope: {request.scope}")

    params = {"grant_type": "client_credentials", "scope": request.scope}

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(
            request.address,
            data=params,
            headers=headers,
            auth=(request.client_id, request.client_secret),
        )

        logger.debug(f"Token request status code: {response.status_code}")

        if response.ok:
            response_json = response.json()
            logger.info("Client credentials token request successful")
            logger.debug(
                f"Token type: {response_json.get('token_type')}, "
                f"Expires in: {response_json.get('expires_in')} seconds",
            )
            return ClientCredentialsTokenResponse(
                is_successful=True,
                token=response_json,
            )
        error_msg = (
            f"Token generation request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}"
        )
        logger.error(error_msg)
        return ClientCredentialsTokenResponse(
            is_successful=False,
            error=error_msg,
        )
    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during token request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return ClientCredentialsTokenResponse(
            is_successful=False,
            error=error_msg,
        )


__all__ = [
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_client_credentials_token",
]
