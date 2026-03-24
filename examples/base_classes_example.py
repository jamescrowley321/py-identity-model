"""
Base Request/Response Classes Examples for py-identity-model

Demonstrates how BaseRequest and BaseResponse provide a consistent
interface across all API operations.
"""

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    DiscoveryDocumentRequest,
    JwksRequest,
    get_discovery_document,
    get_jwks,
)


def polymorphic_fetch(request: BaseRequest) -> BaseResponse:
    """Demonstrate polymorphic request handling.

    Any request that inherits from BaseRequest can be inspected
    for its target endpoint.
    """
    print(f"  Fetching: {request.address}")

    if isinstance(request, DiscoveryDocumentRequest):
        return get_discovery_document(request)
    if isinstance(request, JwksRequest):
        return get_jwks(request)
    msg = f"Unknown request type: {type(request).__name__}"
    raise TypeError(msg)


def check_response(response: BaseResponse, label: str) -> None:
    """Demonstrate uniform response checking via BaseResponse."""
    if response.is_successful:
        print(f"  {label}: success")
    else:
        print(f"  {label}: failed — {response.error}")


def main():
    """Run base class examples."""
    print("\n" + "=" * 60)
    print("BASE REQUEST/RESPONSE EXAMPLES")
    print("=" * 60)

    disco_url = (
        "https://demo.duendesoftware.com/.well-known/openid-configuration"
    )

    # All requests share a common BaseRequest interface
    disco_req = DiscoveryDocumentRequest(address=disco_url)
    print(
        f"\n  isinstance(disco_req, BaseRequest) = {isinstance(disco_req, BaseRequest)}"
    )

    # Polymorphic fetch
    disco_resp = polymorphic_fetch(disco_req)
    check_response(disco_resp, "Discovery")

    if disco_resp.is_successful and disco_resp.jwks_uri:
        jwks_req = JwksRequest(address=disco_resp.jwks_uri)
        jwks_resp = polymorphic_fetch(jwks_req)
        check_response(jwks_resp, "JWKS")

    print(
        f"\n  isinstance(disco_resp, BaseResponse) = {isinstance(disco_resp, BaseResponse)}"
    )

    print("\n" + "=" * 60)
    print("Base class examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
