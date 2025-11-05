"""
Exception hierarchy for py-identity-model.

This module defines a comprehensive exception hierarchy for all errors
that can occur during OAuth 2.0 and OpenID Connect operations.
"""

from __future__ import annotations


class PyIdentityModelException(Exception):
    """Base exception for all py-identity-model errors."""

    def __init__(self, message: str, details: dict | None = None):
        """
        Initialize a PyIdentityModelException.

        Args:
            message: The error message.
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationException(PyIdentityModelException):
    """Raised when validation fails."""


class TokenValidationException(ValidationException):
    """Raised when token validation fails."""

    def __init__(
        self,
        message: str,
        token_part: str | None = None,
        details: dict | None = None,
    ):
        """
        Initialize a TokenValidationException.

        Args:
            message: The error message.
            token_part: The part of the token that failed validation
                       ('header', 'payload', or 'signature').
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message, details)
        self.token_part = token_part


class SignatureVerificationException(TokenValidationException):
    """Raised when token signature verification fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="signature", details=details)


class TokenExpiredException(TokenValidationException):
    """Raised when token has expired."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class InvalidAudienceException(TokenValidationException):
    """Raised when audience validation fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class InvalidIssuerException(TokenValidationException):
    """Raised when issuer validation fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class NetworkException(PyIdentityModelException):
    """Raised when network operations fail."""

    def __init__(
        self,
        message: str,
        url: str | None = None,
        status_code: int | None = None,
        details: dict | None = None,
    ):
        """
        Initialize a NetworkException.

        Args:
            message: The error message.
            url: The URL that was being accessed when the error occurred.
            status_code: The HTTP status code if available.
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message, details)
        self.url = url
        self.status_code = status_code


class DiscoveryException(NetworkException):
    """Raised when discovery document cannot be fetched or parsed."""


class JwksException(NetworkException):
    """Raised when JWKS cannot be fetched or parsed."""


class TokenRequestException(NetworkException):
    """Raised when token request fails."""


class ConfigurationException(PyIdentityModelException):
    """Raised when configuration is invalid or incomplete."""


__all__ = [
    "ConfigurationException",
    "DiscoveryException",
    "InvalidAudienceException",
    "InvalidIssuerException",
    "JwksException",
    "NetworkException",
    "PyIdentityModelException",
    "SignatureVerificationException",
    "TokenExpiredException",
    "TokenRequestException",
    "TokenValidationException",
    "ValidationException",
]
