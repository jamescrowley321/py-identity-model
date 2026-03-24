"""
Enhanced Token Validation Examples for py-identity-model

Demonstrates the three enhanced token validation features:
1. Clock skew tolerance (leeway)
2. Multiple issuers (multi-tenant)
3. Subject claim validation
"""

from py_identity_model import TokenValidationConfig


# =============================================================================
# Example 1: Clock Skew Tolerance (Leeway)
# =============================================================================


def leeway_example():
    """Configure clock skew tolerance for token expiration."""
    print("\n" + "=" * 60)
    print("Example 1: Clock Skew Tolerance (Leeway)")
    print("=" * 60)

    # Allow 30 seconds of clock skew between token issuer and this server
    config = TokenValidationConfig(
        perform_disco=True,
        leeway=30,  # seconds
        options={"verify_aud": False},
    )

    print(f"  Leeway: {config.leeway} seconds")
    print("  Tokens expired up to 30s ago will still be accepted")
    print("  Useful for distributed systems with imperfect clock sync")

    return config


# =============================================================================
# Example 2: Multiple Issuers (Multi-Tenant)
# =============================================================================


def multi_issuer_example():
    """Accept tokens from multiple identity providers."""
    print("\n" + "=" * 60)
    print("Example 2: Multiple Issuers (Multi-Tenant)")
    print("=" * 60)

    # Accept tokens from any of these issuers
    config = TokenValidationConfig(
        perform_disco=True,
        issuer=[
            "https://accounts.google.com",
            "https://login.microsoftonline.com/common/v2.0",
            "https://auth.example.com",
        ],
    )

    assert isinstance(config.issuer, list)
    print(f"  Accepted issuers: {len(config.issuer)}")
    for iss in config.issuer:
        print(f"    - {iss}")
    print("  Tokens from any listed issuer will pass validation")

    return config


# =============================================================================
# Example 3: Subject Claim Validation
# =============================================================================


def subject_validation_example():
    """Validate the sub claim matches an expected user."""
    print("\n" + "=" * 60)
    print("Example 3: Subject Claim Validation")
    print("=" * 60)

    # Ensure the token belongs to a specific user
    config = TokenValidationConfig(
        perform_disco=True,
        subject="user-12345",
    )

    print(f"  Expected subject: {config.subject}")
    print("  Token will be rejected if sub != 'user-12345'")
    print("  Useful for user-specific operations like account deletion")

    return config


# =============================================================================
# Example 4: Combined Configuration
# =============================================================================


def combined_example():
    """Combine all enhanced features."""
    print("\n" + "=" * 60)
    print("Example 4: Combined Configuration")
    print("=" * 60)

    config = TokenValidationConfig(
        perform_disco=True,
        audience="my-api",
        issuer=["https://idp1.example.com", "https://idp2.example.com"],
        subject="service-account-1",
        leeway=15,
    )

    print(f"  Audience: {config.audience}")
    print(f"  Issuers: {config.issuer}")
    print(f"  Subject: {config.subject}")
    print(f"  Leeway: {config.leeway}s")

    return config


# =============================================================================
# Main
# =============================================================================


def main():
    """Run all enhanced token validation examples."""
    print("\n" + "=" * 60)
    print("ENHANCED TOKEN VALIDATION EXAMPLES")
    print("=" * 60)

    leeway_example()
    multi_issuer_example()
    subject_validation_example()
    combined_example()

    print("\n" + "=" * 60)
    print("All enhanced token validation examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
