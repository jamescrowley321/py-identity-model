"""
Token type identifiers per RFC 8693 Section 3.

Constants for use with :class:`TokenExchangeRequest` fields
``subject_token_type``, ``actor_token_type``, and ``requested_token_type``.
"""

ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
SAML1 = "urn:ietf:params:oauth:token-type:saml1"
SAML2 = "urn:ietf:params:oauth:token-type:saml2"
JWT = "urn:ietf:params:oauth:token-type:jwt"

__all__ = [
    "ACCESS_TOKEN",
    "ID_TOKEN",
    "JWT",
    "REFRESH_TOKEN",
    "SAML1",
    "SAML2",
]
