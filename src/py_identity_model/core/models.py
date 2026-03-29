"""
Shared data models for py-identity-model.

This module contains all dataclasses and models used by both sync and async implementations.
"""

from collections.abc import Callable
from dataclasses import dataclass, fields
from enum import Enum
import json
from typing import ClassVar

from ..exceptions import ConfigurationException


# ============================================================================
# Guarded Response Mixin
# ============================================================================


class _GuardedResponseMixin:
    """Mixin that guards field access based on response success state.

    Subclasses declare _guarded_fields as a frozenset of field names.
    Accessing a guarded field when is_successful is False raises
    FailedResponseAccessError with the original error message.
    Accessing 'error' when is_successful is True raises
    SuccessfulResponseAccessError.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset()

    _error_fields: ClassVar[frozenset[str]] = frozenset(
        {"error", "error_description"}
    )

    def __getattribute__(self, name: str):
        guarded = object.__getattribute__(self, "_guarded_fields")
        if name in guarded:
            is_successful = object.__getattribute__(self, "is_successful")
            if not is_successful:
                error = object.__getattribute__(self, "error")
                from ..exceptions import FailedResponseAccessError

                raise FailedResponseAccessError(name, error)
        elif name in object.__getattribute__(self, "_error_fields"):
            is_successful = object.__getattribute__(self, "is_successful")
            if is_successful:
                from ..exceptions import SuccessfulResponseAccessError

                raise SuccessfulResponseAccessError(name)
        return object.__getattribute__(self, name)


# ============================================================================
# Base Request / Response Classes
# ============================================================================


@dataclass
class BaseRequest:
    """Base class for all API requests.

    Every request targets an endpoint URL via the *address* field.
    Subclasses add endpoint-specific parameters.
    """

    address: str


@dataclass(repr=False, eq=False)
class BaseResponse(_GuardedResponseMixin):
    """Base class for all API responses with success/error state.

    Inherits field-access guarding from ``_GuardedResponseMixin``.
    Subclasses override ``_guarded_fields`` and add data fields.
    Check ``is_successful`` before accessing data or error fields.

    .. note::

       ``dataclasses.asdict()`` and ``astuple()`` trigger the field-access
       guards and will raise.  Use ``vars(response)`` instead for dict
       conversion.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset()

    is_successful: bool
    error: str | None = None

    __hash__ = None  # type: ignore[assignment]  # mutable dataclass

    def __repr__(self) -> str:
        """Safe repr that bypasses field-access guards."""
        cls_name = type(self).__name__
        parts: list[str] = []
        for f in fields(self):
            val = object.__getattribute__(self, f.name)
            parts.append(f"{f.name}={val!r}")
        return f"{cls_name}({', '.join(parts)})"

    def __eq__(self, other: object) -> bool:
        """Safe equality that bypasses field-access guards."""
        if type(self) is not type(other):
            return NotImplemented
        return self.__dict__ == other.__dict__


# ============================================================================
# JSON Web Key (JWK) Models - RFC 7517
# ============================================================================


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
class JsonWebKey:
    """
    A JSON Web Key (JWK) as defined in RFC 7517.
    The 'kty' (key type) parameter is required for all key types.
    Other parameters are required based on the key type.
    """

    # Required parameter for all keys
    kty: str

    # Optional parameters for all keys
    use: str | None = None
    key_ops: list[str] | None = None
    alg: str | None = None
    kid: str | None = None

    # Optional JWK parameters
    x5u: str | None = None
    x5c: list[str] | None = None
    x5t: str | None = None
    x5t_s256: str | None = None

    # Parameters for Elliptic Curve Keys
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    d: str | None = None  # Private key

    # Parameters for RSA Keys
    n: str | None = None  # Modulus
    e: str | None = None  # Exponent
    # RSA Private key parameters
    p: str | None = None
    q: str | None = None
    dp: str | None = None
    dq: str | None = None
    qi: str | None = None
    oth: list[dict[str, str]] | None = None

    # Parameters for Symmetric Keys
    k: str | None = None

    def __post_init__(self):
        """Validate the JWK after initialization"""
        if not self.kty:
            raise ConfigurationException(
                "The 'kty' (Key Type) parameter is required",
            )

        self._validate_key_parameters()

    def _validate_ec_key(self):
        """Validate EC key parameters per RFC 7518"""
        if not all([self.crv, self.x, self.y]):
            raise ConfigurationException(
                "EC keys require 'crv', 'x', and 'y' parameters",
            )

        valid_curves = ["P-256", "P-384", "P-521", "secp256k1"]
        if self.crv not in valid_curves:
            raise ConfigurationException(
                f"Unsupported curve: {self.crv}. Supported curves: {valid_curves}",
            )

    def _validate_rsa_key(self):
        """Validate RSA key parameters"""
        if not all([self.n, self.e]):
            raise ConfigurationException(
                "RSA keys require 'n' and 'e' parameters",
            )

    def _validate_symmetric_key(self):
        """Validate symmetric key parameters"""
        if self.k is None:
            raise ConfigurationException(
                "Symmetric keys require 'k' parameter",
            )

    def _validate_use_parameter(self):
        """Validate 'use' parameter per RFC 7517 Section 4.2"""
        if self.use is None:
            return

        valid_use_values = ["sig", "enc"]
        if self.use not in valid_use_values and not self.use.startswith(
            "https://",
        ):
            raise ConfigurationException(
                f"Invalid 'use' parameter: {self.use}. Must be 'sig', 'enc', or a URI",
            )

    def _validate_key_ops_parameter(self):
        """Validate 'key_ops' parameter per RFC 7517 Section 4.3"""
        if self.key_ops is None:
            return

        valid_key_ops = [
            "sign",
            "verify",
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ]
        for op in self.key_ops:
            if op not in valid_key_ops:
                raise ConfigurationException(
                    f"Invalid key operation: {op}. Valid operations: {valid_key_ops}",
                )

    def _validate_key_parameters(self):
        """Validate required parameters based on the key type"""
        # Validate key type specific parameters
        if self.kty == "EC":
            self._validate_ec_key()
        elif self.kty == "RSA":
            self._validate_rsa_key()
        elif self.kty == "oct":
            self._validate_symmetric_key()

        # Validate 'use' and 'key_ops' parameters
        self._validate_use_parameter()
        self._validate_key_ops_parameter()

        # Validate mutual exclusivity per RFC 7517 Section 4.3
        if self.use is not None and self.key_ops is not None:
            raise ConfigurationException(
                "The 'use' and 'key_ops' parameters are mutually exclusive",
            )

    @classmethod
    def from_json(cls, json_str: str) -> "JsonWebKey":
        """Create a JWK from a JSON string"""
        if not json_str or not json_str.strip():
            raise ConfigurationException("JSON string cannot be empty")

        try:
            data = json.loads(json_str)

            # Validate that the parsed JSON is a dictionary
            if not isinstance(data, dict):
                raise ConfigurationException(
                    "Invalid JWK format: JSON must be an object, not a "
                    + type(data).__name__,
                )

            # Dynamically get valid field names from the JsonWebKey dataclass
            valid_fields = {field.name for field in fields(cls)}

            # Map JWK parameter names to Python field names
            from typing import Any

            mapped_data: dict[str, Any] = {}
            for k, v in data.items():
                if k == JsonWebKeyParameterNames.X5T_S256.value:
                    mapped_data["x5t_s256"] = v
                elif k == "key_ops" and isinstance(v, str):
                    # Ensure key_ops is a list
                    mapped_data[k] = [v]
                elif k == "x5c" and isinstance(v, str):
                    # Ensure x5c is a list
                    mapped_data[k] = [v]
                elif k == "oth" and isinstance(v, str):
                    # Ensure oth is a list (though a string oth is unusual)
                    mapped_data[k] = [
                        {"r": v},
                    ]  # Convert to expected dict format
                else:
                    mapped_data[k] = v

            # Filter to only include valid fields
            filtered_data = {
                k: v for k, v in mapped_data.items() if k in valid_fields
            }

            return cls(**filtered_data)
        except json.JSONDecodeError as e:
            raise ConfigurationException("Invalid JSON format") from e
        except (TypeError, AttributeError) as e:
            raise ConfigurationException(
                f"Invalid JWK format: {e!s}",
            ) from e

    def to_json(self) -> str:
        """Convert the JWK to a JSON string"""
        data = {}
        for k, v in self.__dict__.items():
            if v is not None:
                # Map Python field names back to JWK parameter names
                if k == "x5t_s256":
                    data[JsonWebKeyParameterNames.X5T_S256.value] = v
                else:
                    data[k] = v
        return json.dumps(data)

    @property
    def has_private_key(self) -> bool:
        """Check if the key contains private key parts"""
        if self.kty == "RSA":
            return all([self.d, self.p, self.q, self.dp, self.dq, self.qi])
        if self.kty == "EC":
            return self.d is not None
        return False

    @property
    def key_size(self) -> int:
        """Calculate the key size in bits"""
        if self.kty == "RSA":
            return len(self._decode_base64url(self.n)) * 8 if self.n else 0
        if self.kty == "EC":
            return len(self._decode_base64url(self.x)) * 8 if self.x else 0
        if self.kty == "oct":
            return len(self._decode_base64url(self.k)) * 8 if self.k else 0
        return 0

    @staticmethod
    def _decode_base64url(input_str: str | None) -> bytes:
        """Decode a base64url-encoded string"""
        if not input_str:
            return b""
        from base64 import urlsafe_b64decode

        padding = "=" * (4 - len(input_str) % 4)
        return urlsafe_b64decode(input_str + padding)

    def as_dict(self):
        """Convert the JWK to a dictionary with all available properties"""
        # Add all non-None properties to the dictionary
        return {
            key: value
            for key, value in self.__dict__.items()
            if value is not None
        }


# ============================================================================
# Discovery Document Models - OpenID Connect Discovery 1.0
# ============================================================================


@dataclass
class DiscoveryDocumentRequest(BaseRequest):
    """Request for fetching an OpenID Connect discovery document.

    Attributes:
        address: The base URL of the identity provider
            (e.g. ``https://example.com``). The well-known path is
            appended automatically.
    """


@dataclass(repr=False, eq=False)
class DiscoveryDocumentResponse(BaseResponse):
    """Response from an OpenID Connect discovery document fetch.

    Check ``is_successful`` before accessing data fields. Accessing guarded
    fields on a failed response raises
    ``FailedResponseAccessError``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "issuer",
            "jwks_uri",
            "authorization_endpoint",
            "token_endpoint",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "userinfo_endpoint",
            "registration_endpoint",
            "scopes_supported",
            "response_modes_supported",
            "grant_types_supported",
            "acr_values_supported",
            "id_token_encryption_alg_values_supported",
            "id_token_encryption_enc_values_supported",
            "userinfo_signing_alg_values_supported",
            "userinfo_encryption_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "request_object_signing_alg_values_supported",
            "request_object_encryption_alg_values_supported",
            "request_object_encryption_enc_values_supported",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "display_values_supported",
            "claim_types_supported",
            "claims_supported",
            "claims_locales_supported",
            "ui_locales_supported",
            "claims_parameter_supported",
            "request_parameter_supported",
            "request_uri_parameter_supported",
            "require_request_uri_registration",
            "service_documentation",
            "op_policy_uri",
            "op_tos_uri",
        }
    )

    # Core OpenID Connect endpoints
    issuer: str | None = None
    jwks_uri: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None

    # Required properties from OpenID Connect Discovery 1.0 specification
    response_types_supported: list[str] | None = None
    subject_types_supported: list[str] | None = None
    id_token_signing_alg_values_supported: list[str] | None = None

    # Common optional properties
    userinfo_endpoint: str | None = None
    registration_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    acr_values_supported: list[str] | None = None

    # Cryptographic algorithm support
    id_token_encryption_alg_values_supported: list[str] | None = None
    id_token_encryption_enc_values_supported: list[str] | None = None
    userinfo_signing_alg_values_supported: list[str] | None = None
    userinfo_encryption_alg_values_supported: list[str] | None = None
    userinfo_encryption_enc_values_supported: list[str] | None = None
    request_object_signing_alg_values_supported: list[str] | None = None
    request_object_encryption_alg_values_supported: list[str] | None = None
    request_object_encryption_enc_values_supported: list[str] | None = None

    # Token endpoint authentication
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None

    # Display and UI
    display_values_supported: list[str] | None = None
    claim_types_supported: list[str] | None = None
    claims_supported: list[str] | None = None
    claims_locales_supported: list[str] | None = None
    ui_locales_supported: list[str] | None = None

    # Feature support flags
    claims_parameter_supported: bool | None = None
    request_parameter_supported: bool | None = None
    request_uri_parameter_supported: bool | None = None
    require_request_uri_registration: bool | None = None

    # Documentation and policy
    service_documentation: str | None = None
    op_policy_uri: str | None = None
    op_tos_uri: str | None = None


# ============================================================================
# JWKS Models - RFC 7517
# ============================================================================


@dataclass
class JwksRequest(BaseRequest):
    """Request for fetching a JSON Web Key Set.

    Attributes:
        address: The JWKS endpoint URL (typically from ``DiscoveryDocumentResponse.jwks_uri``).
    """


@dataclass(repr=False, eq=False)
class JwksResponse(BaseResponse):
    """Response from a JWKS endpoint fetch.

    Check ``is_successful`` before accessing ``keys``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"keys"})

    keys: list[JsonWebKey] | None = None


# ============================================================================
# Token Client Models
# ============================================================================


@dataclass
class ClientCredentialsTokenRequest(BaseRequest):
    """Request for an OAuth 2.0 client credentials token.

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        client_secret: The client secret.
        scope: Space-delimited list of requested scopes.
    """

    client_id: str
    client_secret: str
    scope: str


@dataclass(repr=False, eq=False)
class ClientCredentialsTokenResponse(BaseResponse):
    """Response from a client credentials token request.

    Check ``is_successful`` before accessing ``token``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None


# ============================================================================
# Authorization Code Token Models
# ============================================================================


@dataclass
class AuthorizationCodeTokenRequest(BaseRequest):
    """Request for exchanging an authorization code for tokens.

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        code: The authorization code received from the callback.
        redirect_uri: The same redirect URI used in the authorization request.
        code_verifier: PKCE code verifier (required when PKCE was used).
        client_secret: Client secret (optional for public clients per RFC 7636).
        scope: Space-delimited list of requested scopes (optional).
    """

    client_id: str
    code: str
    redirect_uri: str
    code_verifier: str | None = None
    client_secret: str | None = None
    scope: str | None = None


@dataclass(repr=False, eq=False)
class AuthorizationCodeTokenResponse(BaseResponse):
    """Response from an authorization code token exchange.

    Check ``is_successful`` before accessing ``token``.
    The token dict typically contains ``access_token``, ``token_type``,
    ``expires_in``, ``refresh_token``, and optionally ``id_token``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None


# ============================================================================
# Token Introspection Models - RFC 7662
# ============================================================================


@dataclass
class TokenIntrospectionRequest(BaseRequest):
    """Request for OAuth 2.0 Token Introspection (RFC 7662).

    Attributes:
        address: The introspection endpoint URL.
        token: The token to introspect.
        client_id: The client identifier for authentication.
        token_type_hint: Optional hint — ``"access_token"`` or ``"refresh_token"``.
        client_secret: Client secret for authentication (optional for public clients).
    """

    token: str
    client_id: str
    token_type_hint: str | None = None
    client_secret: str | None = None


@dataclass(repr=False, eq=False)
class TokenIntrospectionResponse(BaseResponse):
    """Response from a token introspection endpoint (RFC 7662).

    Check ``is_successful`` before accessing ``claims``.
    The ``claims`` dict contains at minimum ``active: bool``.
    When ``active`` is ``True``, additional claims like ``scope``,
    ``client_id``, ``username``, ``exp``, ``iat``, ``sub``, ``aud``,
    ``iss``, and ``jti`` may be present.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"claims"})

    claims: dict | None = None


# ============================================================================
# UserInfo Models - OpenID Connect Core 1.0 Section 5.3
# ============================================================================


@dataclass
class UserInfoRequest(BaseRequest):
    """Request for the OpenID Connect UserInfo endpoint.

    Attributes:
        address: The UserInfo endpoint URL.
        token: A valid access token with ``openid`` scope.
    """

    token: str


@dataclass(repr=False, eq=False)
class UserInfoResponse(BaseResponse):
    """Response from the UserInfo endpoint.

    Check ``is_successful`` before accessing ``claims`` or ``raw``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"claims", "raw"})

    claims: dict | None = None
    raw: str | None = None


# ============================================================================
# Token Validation Models
# ============================================================================


@dataclass
class TokenValidationConfig:
    """
    Configuration for JWT token validation.

    Attributes:
        perform_disco: Whether to perform discovery to fetch JWKS and issuer
        key: Public key for JWT verification (dict with 'kty', 'n', 'e' for RSA)
        audience: Expected audience claim(s) in the token
        algorithms: List of allowed signing algorithms (e.g., ['RS256'])
        issuer: Expected issuer claim.  A single string or a list of
            accepted issuers for multi-tenant validation.
        subject: Expected ``sub`` claim.  Validated after decoding.
        options: Additional PyJWT decode options (e.g., {'verify_exp': False})
        claims_validator: Optional callable for custom claims validation.
                         Can be sync: Callable[[dict], None]
                         or async: Callable[[dict], Awaitable[None]] (in async context)
                         Should raise an exception if validation fails.
                         The decoded token claims dict is passed as the only argument.
        leeway: Clock skew tolerance in seconds for ``exp`` and ``nbf``
            claims.  Useful when clocks between the issuer and this
            server are not perfectly synchronized.

    Examples:
        >>> # Multi-tenant with clock skew tolerance
        >>> config = TokenValidationConfig(
        ...     perform_disco=True,
        ...     audience="my-api",
        ...     issuer=[
        ...         "https://idp1.example.com",
        ...         "https://idp2.example.com",
        ...     ],
        ...     leeway=30,
        ... )

        >>> # Custom claims validation
        >>> def validate_custom_claims(claims: dict) -> None:
        ...     if claims.get("role") != "admin":
        ...         raise ValueError("User is not an admin")
        >>>
        >>> config = TokenValidationConfig(
        ...     perform_disco=True,
        ...     claims_validator=validate_custom_claims,
        ... )
    """

    perform_disco: bool
    key: dict | None = None
    audience: str | None = None
    algorithms: list[str] | None = None
    issuer: str | list[str] | None = None
    subject: str | None = None
    options: dict | None = None
    claims_validator: Callable | None = None
    leeway: float | None = None


__all__ = [
    # Authorization Code Token
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    # Base Classes
    "BaseRequest",
    "BaseResponse",
    # Token Client
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    # Discovery
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    # Token Introspection
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    # Token Validation
    "TokenValidationConfig",
    # UserInfo
    "UserInfoRequest",
    "UserInfoResponse",
]
