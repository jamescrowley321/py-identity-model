from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class ClientCredentialsTokenRequest:
    address: str
    client_id: str
    client_secret: str
    scope: str


@dataclass
class ClientCredentialsTokenResponse:
    is_successful: bool
    token: Optional[dict] = None
    error: Optional[str] = None


def request_client_credentials_token(
    request: ClientCredentialsTokenRequest,
) -> ClientCredentialsTokenResponse:
    params = {"grant_type": "client_credentials", "scope": request.scope}

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(
        request.address,
        data=params,
        headers=headers,
        auth=(request.client_id, request.client_secret),
    )

    if response.ok:
        return ClientCredentialsTokenResponse(
            is_successful=True, token=response.json()
        )
    else:
        return ClientCredentialsTokenResponse(
            is_successful=False,
            error=f"Token generation request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}",
        )


__all__ = [
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "request_client_credentials_token",
]
