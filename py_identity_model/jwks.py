from dataclasses import dataclass
from typing import List, Optional

import requests


@dataclass
class JwksRequest:
    address: str


@dataclass
class JsonWebKey:
    kty: str
    use: str
    kid: str
    n: str
    e: str
    x5t: str = None
    x5c: List[str] = None
    issuer: Optional[str] = None
    alg: Optional[str] = None

    def as_dict(self):
        return {
            "kty": self.kty,
            "use": self.use,
            "kid": self.kid,
            "x5t": self.x5t,
            "n": self.n,
            "e": self.e,
            "x5c": self.x5c,
            "issuer": self.issuer,
            "alg": self.alg,
        }


@dataclass
class JwksResponse:
    is_successful: bool
    keys: Optional[List[JsonWebKey]] = None
    error: Optional[str] = None


def get_jwks(jwks_request: JwksRequest) -> JwksResponse:
    response = requests.get(jwks_request.address)
    # TODO: raise for status and handle exceptions
    if response.ok:
        response_json = response.json()
        keys = [JsonWebKey(**key) for key in response_json["keys"]]
        return JwksResponse(is_successful=True, keys=keys)
    else:
        return JwksResponse(
            is_successful=False,
            error=f"JSON web keys request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}",
        )


__all__ = ["JwksRequest", "JwksResponse", "JsonWebKey", "get_jwks"]
