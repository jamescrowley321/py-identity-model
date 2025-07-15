import json
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict

import requests


class JsonWebKeyParameterNames(Enum):
    """Parameter names as defined in RFC 7517"""

    # Required for all keys
    KTY = "kty"

    # Optional for all keys
    USE = "use"
    KEY_OPS = "key_ops"
    ALG = "alg"
    KID = "kid"

    # Optional JWK parameters
    X5U = "x5u"
    X5C = "x5c"
    X5T = "x5t"
    X5T_S256 = "x5t#S256"

    # Parameters for Elliptic Curve Keys
    CRV = "crv"
    X = "x"
    Y = "y"
    D = "d"

    # Parameters for RSA Keys
    N = "n"
    E = "e"
    P = "p"
    Q = "q"
    DP = "dp"
    DQ = "dq"
    QI = "qi"
    OTH = "oth"

    # Parameters for Symmetric Keys
    K = "k"

    def __str__(self) -> str:
        """Return the string value of the enum"""
        return self.value


class JsonWebAlgorithmsKeyTypes(Enum):
    EllipticCurve = "EC"
    RSA = "RSA"
    Octet = "oct"


@dataclass
class JwksRequest:
    address: str


@dataclass
class JsonWebKey:
    """
    A JSON Web Key (JWK) as defined in RFC 7517.
    The 'kty' (key type) parameter is required for all key types.
    Other parameters are required based on the key type.
    """

    # Required parameter for all keys
    kty: str

    # Optional parameters for all keys
    use: Optional[str] = None
    key_ops: Optional[List[str]] = None
    alg: Optional[str] = None
    kid: Optional[str] = None

    # Optional JWK parameters
    x5u: Optional[str] = None
    x5c: Optional[List[str]] = None
    x5t: Optional[str] = None
    x5t_s256: Optional[str] = None

    # Parameters for Elliptic Curve Keys
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    d: Optional[str] = None  # Private key

    # Parameters for RSA Keys
    n: Optional[str] = None  # Modulus
    e: Optional[str] = None  # Exponent
    # RSA Private key parameters
    p: Optional[str] = None
    q: Optional[str] = None
    dp: Optional[str] = None
    dq: Optional[str] = None
    qi: Optional[str] = None
    oth: Optional[List[Dict[str, str]]] = None

    # Parameters for Symmetric Keys
    k: Optional[str] = None

    def __post_init__(self):
        """Validate the JWK after initialization"""
        if not self.kty:
            raise ValueError("The 'kty' (Key Type) parameter is required")

        self._validate_key_parameters()

    def _validate_key_parameters(self):
        """Validate required parameters based on the key type"""
        if self.kty == "EC":
            if not all([self.crv, self.x, self.y]):
                raise ValueError("EC keys require 'crv', 'x', and 'y' parameters")
        elif self.kty == "RSA":
            if not all([self.n, self.e]):
                raise ValueError("RSA keys require 'n' and 'e' parameters")
        elif self.kty == "oct":
            if not self.k:
                raise ValueError("Symmetric keys require 'k' parameter")

    @classmethod
    def from_json(cls, json_str: str) -> "JsonWebKey":
        """Create a JWK from a JSON string"""
        if not json_str or not json_str.strip():
            raise ValueError("JSON string cannot be empty")

        try:
            data = json.loads(json_str)
            return cls(**{k.lower(): v for k, v in data.items()})
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format")
        except TypeError as e:
            raise ValueError(f"Invalid JWK format: {str(e)}")

    def to_json(self) -> str:
        """Convert the JWK to a JSON string"""
        data = {k: v for k, v in self.__dict__.items() if v is not None}
        return json.dumps(data)

    @property
    def has_private_key(self) -> bool:
        """Check if the key contains private key parts"""
        if self.kty == "RSA":
            return all([self.d, self.p, self.q, self.dp, self.dq, self.qi])
        elif self.kty == "EC":
            return self.d is not None
        return False

    @property
    def key_size(self) -> int:
        """Calculate the key size in bits"""
        if self.kty == "RSA":
            return len(self._decode_base64url(self.n)) * 8 if self.n else 0
        elif self.kty == "EC":
            return len(self._decode_base64url(self.x)) * 8 if self.x else 0
        elif self.kty == "oct":
            return len(self._decode_base64url(self.k)) * 8 if self.k else 0
        return 0

    @staticmethod
    def _decode_base64url(input_str: Optional[str]) -> bytes:
        """Decode a base64url-encoded string"""
        if not input_str:
            return b""
        from base64 import urlsafe_b64decode

        padding = "=" * (4 - len(input_str) % 4)
        return urlsafe_b64decode(input_str + padding)

    def as_dict(self):
        """Convert the JWK to a dictionary with all available properties"""
        result = {}

        # Add all non-None properties to the dictionary
        for key, value in self.__dict__.items():
            if value is not None:
                result[key] = value

        return result


@dataclass
class JwksResponse:
    is_successful: bool
    keys: Optional[List[JsonWebKey]] = None
    error: Optional[str] = None


def jwks_from_dict(keys_dict: dict) -> JsonWebKey:
    return JsonWebKey(
        # Required parameter
        kty=keys_dict.get("kty"),
        # Optional parameters for all keys
        use=keys_dict.get("use"),
        key_ops=keys_dict.get("key_ops"),
        alg=keys_dict.get("alg"),
        kid=keys_dict.get("kid"),
        # Optional JWK parameters
        x5u=keys_dict.get("x5u"),
        x5c=keys_dict.get("x5c"),
        x5t=keys_dict.get("x5t"),
        x5t_s256=keys_dict.get("x5t#S256"),
        # Parameters for Elliptic Curve Keys
        crv=keys_dict.get("crv"),
        x=keys_dict.get("x"),
        y=keys_dict.get("y"),
        d=keys_dict.get("d"),
        # Parameters for RSA Keys
        n=keys_dict.get("n"),
        e=keys_dict.get("e"),
        p=keys_dict.get("p"),
        q=keys_dict.get("q"),
        dp=keys_dict.get("dp"),
        dq=keys_dict.get("dq"),
        qi=keys_dict.get("qi"),
        oth=keys_dict.get("oth"),
        # Parameters for Symmetric Keys
        k=keys_dict.get("k"),
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


__all__ = [
    "JwksRequest",
    "JwksResponse",
    "JsonWebKey",
    "get_jwks",
    "JsonWebKeyParameterNames",
]
