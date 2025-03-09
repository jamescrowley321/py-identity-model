from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import requests


class JsonWebAlgorithmsKeyTypes(Enum):
    EllipticCurve = "EC"
    RSA = "RSA"
    Octet = "oct"


@dataclass
class JwksRequest:
    address: str


@dataclass
class JsonWebKey:
    kty: str
    kid: str
    n: str
    e: str
    x5t: str = None
    x5c: List[str] = None
    issuer: Optional[str] = None
    alg: Optional[str] = None
    crv: Optional[str] = None
    d: Optional[str] = None
    dp: Optional[str] = None
    dq: Optional[str] = None
    k: Optional[str] = None
    key_ops: Optional[list[str]] = None
    oth: Optional[list[str]] = None
    p: Optional[list[str]] = None
    q: Optional[list[str]] = None
    qi: Optional[list[str]] = None
    use: Optional[str] = None
    x: Optional[list[str]] = None
    x5ts256: Optional[str] = None
    x5u: Optional[str] = None
    y: Optional[str] = None

    # TODO: key size and has private key

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
        kid=keys_dict.get("kid"),
        kty=keys_dict.get("kty"),
        x5c=keys_dict.get("x5c"),
        x5t=keys_dict.get("x5t"),
        n=keys_dict.get("n"),
        e=keys_dict.get("e"),
        issuer=keys_dict.get("issuer"),
        alg=keys_dict.get("alg"),
        use=keys_dict.get("use"),
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
