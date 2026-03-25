"""
FAPI 2.0 Security Profile Compliance Example

Demonstrates validating OAuth 2.0 configurations against
FAPI 2.0 Security Profile requirements.
"""

from py_identity_model import (
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
)


def validate_authorization_example():
    """Check if an authorization request meets FAPI 2.0."""
    print("\n" + "=" * 60)
    print("FAPI 2.0 - Authorization Request Validation")
    print("=" * 60)

    # Compliant request
    result = validate_fapi_authorization_request(
        response_type="code",
        code_challenge="fapi_s256_challenge",
        code_challenge_method="S256",
        redirect_uri="https://bank.example.com/callback",
        use_par=True,
        algorithm="PS256",
    )
    print(f"\n  Compliant request: {result.is_compliant}")
    print(f"  Violations: {result.violations}")

    # Non-compliant request
    result = validate_fapi_authorization_request(
        response_type="code",
        code_challenge="challenge",
        code_challenge_method="plain",
        redirect_uri="http://app.example.com/cb",
        use_par=False,
        algorithm="RS256",
    )
    print(f"\n  Non-compliant request: {result.is_compliant}")
    for v in result.violations:
        print(f"    - {v}")


def validate_client_example():
    """Check if client configuration meets FAPI 2.0."""
    print("\n" + "=" * 60)
    print("FAPI 2.0 - Client Configuration Validation")
    print("=" * 60)

    result = validate_fapi_client_config(
        has_client_authentication=True,
        use_dpop=True,
    )
    print(f"\n  DPoP client: compliant = {result.is_compliant}")

    result = validate_fapi_client_config(
        has_client_authentication=False,
        use_dpop=False,
    )
    print(f"  Public client without DPoP: compliant = {result.is_compliant}")
    for v in result.violations:
        print(f"    - {v}")

    print(
        f"\n  Allowed algorithms: {sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS)}"
    )


def main():
    validate_authorization_example()
    validate_client_example()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
