from dataclasses import dataclass
from typing import Optional, List

import requests


@dataclass
class DiscoveryDocumentRequest:
    address: str


@dataclass
class DiscoveryDocumentResponse:
    is_successful: bool
    # Core OpenID Connect endpoints
    issuer: Optional[str] = None
    jwks_uri: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None

    # Required properties from OpenID Connect Discovery 1.0 specification
    response_types_supported: Optional[List[str]] = None
    subject_types_supported: Optional[List[str]] = None
    id_token_signing_alg_values_supported: Optional[List[str]] = None

    # Common optional properties
    userinfo_endpoint: Optional[str] = None
    registration_endpoint: Optional[str] = None
    scopes_supported: Optional[List[str]] = None
    response_modes_supported: Optional[List[str]] = None
    grant_types_supported: Optional[List[str]] = None
    acr_values_supported: Optional[List[str]] = None

    # Cryptographic algorithm support
    id_token_encryption_alg_values_supported: Optional[List[str]] = None
    id_token_encryption_enc_values_supported: Optional[List[str]] = None
    userinfo_signing_alg_values_supported: Optional[List[str]] = None
    userinfo_encryption_alg_values_supported: Optional[List[str]] = None
    userinfo_encryption_enc_values_supported: Optional[List[str]] = None
    request_object_signing_alg_values_supported: Optional[List[str]] = None
    request_object_encryption_alg_values_supported: Optional[List[str]] = None
    request_object_encryption_enc_values_supported: Optional[List[str]] = None

    # Token endpoint authentication
    token_endpoint_auth_methods_supported: Optional[List[str]] = None
    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None

    # Display and UI
    display_values_supported: Optional[List[str]] = None
    claim_types_supported: Optional[List[str]] = None
    claims_supported: Optional[List[str]] = None
    claims_locales_supported: Optional[List[str]] = None
    ui_locales_supported: Optional[List[str]] = None

    # Feature support flags
    claims_parameter_supported: Optional[bool] = None
    request_parameter_supported: Optional[bool] = None
    request_uri_parameter_supported: Optional[bool] = None
    require_request_uri_registration: Optional[bool] = None

    # Documentation and policy
    service_documentation: Optional[str] = None
    op_policy_uri: Optional[str] = None
    op_tos_uri: Optional[str] = None

    # Internal properties
    error: Optional[str] = None


def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
) -> DiscoveryDocumentResponse:
    response = requests.get(disco_doc_req.address)
    # TODO: raise for status and handle exceptions
    if response.ok and "application/json" in response.headers.get("Content-Type", ""):
        response_json = response.json()
        return DiscoveryDocumentResponse(
            # Core OpenID Connect endpoints
            issuer=response_json.get("issuer"),
            jwks_uri=response_json.get("jwks_uri"),
            authorization_endpoint=response_json.get("authorization_endpoint"),
            token_endpoint=response_json.get("token_endpoint"),
            # Required properties from OpenID Connect Discovery 1.0 specification
            response_types_supported=response_json.get("response_types_supported"),
            subject_types_supported=response_json.get("subject_types_supported"),
            id_token_signing_alg_values_supported=response_json.get(
                "id_token_signing_alg_values_supported"
            ),
            # Common optional properties
            userinfo_endpoint=response_json.get("userinfo_endpoint"),
            registration_endpoint=response_json.get("registration_endpoint"),
            scopes_supported=response_json.get("scopes_supported"),
            response_modes_supported=response_json.get("response_modes_supported"),
            grant_types_supported=response_json.get("grant_types_supported"),
            acr_values_supported=response_json.get("acr_values_supported"),
            # Cryptographic algorithm support
            id_token_encryption_alg_values_supported=response_json.get(
                "id_token_encryption_alg_values_supported"
            ),
            id_token_encryption_enc_values_supported=response_json.get(
                "id_token_encryption_enc_values_supported"
            ),
            userinfo_signing_alg_values_supported=response_json.get(
                "userinfo_signing_alg_values_supported"
            ),
            userinfo_encryption_alg_values_supported=response_json.get(
                "userinfo_encryption_alg_values_supported"
            ),
            userinfo_encryption_enc_values_supported=response_json.get(
                "userinfo_encryption_enc_values_supported"
            ),
            request_object_signing_alg_values_supported=response_json.get(
                "request_object_signing_alg_values_supported"
            ),
            request_object_encryption_alg_values_supported=response_json.get(
                "request_object_encryption_alg_values_supported"
            ),
            request_object_encryption_enc_values_supported=response_json.get(
                "request_object_encryption_enc_values_supported"
            ),
            # Token endpoint authentication
            token_endpoint_auth_methods_supported=response_json.get(
                "token_endpoint_auth_methods_supported"
            ),
            token_endpoint_auth_signing_alg_values_supported=response_json.get(
                "token_endpoint_auth_signing_alg_values_supported"
            ),
            # Display and UI
            display_values_supported=response_json.get("display_values_supported"),
            claim_types_supported=response_json.get("claim_types_supported"),
            claims_supported=response_json.get("claims_supported"),
            claims_locales_supported=response_json.get("claims_locales_supported"),
            ui_locales_supported=response_json.get("ui_locales_supported"),
            # Feature support flags
            claims_parameter_supported=response_json.get("claims_parameter_supported"),
            request_parameter_supported=response_json.get(
                "request_parameter_supported"
            ),
            request_uri_parameter_supported=response_json.get(
                "request_uri_parameter_supported"
            ),
            require_request_uri_registration=response_json.get(
                "require_request_uri_registration"
            ),
            # Documentation and policy
            service_documentation=response_json.get("service_documentation"),
            op_policy_uri=response_json.get("op_policy_uri"),
            op_tos_uri=response_json.get("op_tos_uri"),
            is_successful=True,
        )
    else:
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=f"Discovery document request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}",
        )


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "get_discovery_document",
]
