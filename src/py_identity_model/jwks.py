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


def jwks_from_dict(keys_dict: dict) -> JsonWebKey:
    return JsonWebKey(
        kty=keys_dict.get("kty"),
        use=keys_dict.get("use"),
        kid=keys_dict.get("kid"),
        x5c=keys_dict.get("x5c"),
        x5t=keys_dict.get("x5t"),
        n=keys_dict.get("n"),
        e=keys_dict.get("e"),
        issuer=keys_dict.get("issuer"),
        alg=keys_dict.get("alg"),
    )


def get_jwks(jwks_request: JwksRequest) -> JwksResponse:
    try:
        response = requests.get(jwks_request.address)
        if response.ok:
            response_json = response.json()
            keys = [jwks_from_dict(key) for key in response_json["keys"]]
            return JwksResponse(is_successful=True, keys=keys)
        else:
            return JwksResponse(
                is_successful=False,
                error=f"JSON web keys request failed with status code: "
                f"{response.status_code}. Response Content: {response.content}",
            )
    except Exception as e:
        return JwksResponse(
            is_successful=False,
            error=f"Unhandled exception during JWKS request: {e}",
        )


__all__ = ["JwksRequest", "JwksResponse", "JsonWebKey", "get_jwks"]
