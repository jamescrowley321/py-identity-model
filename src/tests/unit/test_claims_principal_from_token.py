from py_identity_model.identity import (
    ClaimsIdentity,
    ClaimsPrincipal,
    to_principal,
)


def test_create_claims_principal_from_simple_token():
    """Test creating ClaimsPrincipal from a simple token dictionary"""
    token_claims = {
        "sub": "user123",
        "iss": "https://example.com",
        "aud": "my-app",
        "exp": 1234567890,
        "iat": 1234567800,
        "email": "user@example.com",
    }

    principal = to_principal(token_claims)

    assert isinstance(principal, ClaimsPrincipal)
    assert isinstance(principal.identity, ClaimsIdentity)
    assert principal.identity.is_authenticated()
    assert principal.identity.authentication_type == "Bearer"

    # Check that all claims were converted
    assert len(principal.claims) == 6
    assert principal.has_claim("sub", "user123")
    assert principal.has_claim("iss", "https://example.com")
    assert principal.has_claim("aud", "my-app")
    assert principal.has_claim("exp", "1234567890")
    assert principal.has_claim("iat", "1234567800")
    assert principal.has_claim("email", "user@example.com")


def test_create_claims_principal_with_custom_auth_type():
    """Test creating ClaimsPrincipal with custom authentication type"""
    token_claims = {"sub": "user123", "iss": "https://example.com"}

    principal = to_principal(token_claims, authentication_type="JWT")

    assert principal.identity is not None
    assert principal.identity.authentication_type == "JWT"
    assert principal.identity.is_authenticated()


def test_create_claims_principal_from_token_with_array_claims():
    """Test creating ClaimsPrincipal from token with array claims"""
    token_claims = {
        "sub": "user123",
        "roles": ["admin", "user", "editor"],
        "groups": ["group1", "group2"],
        "iss": "https://example.com",
    }

    principal = to_principal(token_claims)

    assert isinstance(principal, ClaimsPrincipal)
    # Should have 7 claims total: sub, iss, 3 roles, 2 groups
    assert len(principal.claims) == 7

    # Check individual role claims
    assert principal.has_claim("roles", "admin")
    assert principal.has_claim("roles", "user")
    assert principal.has_claim("roles", "editor")

    # Check individual group claims
    assert principal.has_claim("groups", "group1")
    assert principal.has_claim("groups", "group2")

    # Check other claims
    assert principal.has_claim("sub", "user123")
    assert principal.has_claim("iss", "https://example.com")


def test_create_claims_principal_from_empty_token():
    """Test creating ClaimsPrincipal from empty token dictionary"""
    token_claims = {}

    principal = to_principal(token_claims)

    assert isinstance(principal, ClaimsPrincipal)
    assert isinstance(principal.identity, ClaimsIdentity)
    assert principal.identity.is_authenticated()
    assert len(principal.claims) == 0


def test_create_claims_principal_handles_various_types():
    """Test that the function properly converts various claim value types to strings"""
    token_claims = {
        "string_claim": "test",
        "int_claim": 123,
        "float_claim": 45.67,
        "bool_claim": True,
        "none_claim": None,
    }

    principal = to_principal(token_claims)

    assert principal.has_claim("string_claim", "test")
    assert principal.has_claim("int_claim", "123")
    assert principal.has_claim("float_claim", "45.67")
    assert principal.has_claim("bool_claim", "True")
    assert principal.has_claim("none_claim", "None")


def test_find_claims_in_principal():
    """Test finding specific claims in the principal"""
    token_claims = {
        "sub": "user123",
        "email": "user@example.com",
        "roles": ["admin", "user"],
    }

    principal = to_principal(token_claims)

    # Test find_first
    sub_claim = principal.find_first("sub")
    assert sub_claim is not None
    assert sub_claim.value == "user123"

    email_claim = principal.find_first("email")
    assert email_claim is not None
    assert email_claim.value == "user@example.com"

    # Test find_all for multiple values
    role_claims = principal.find_all("roles")
    assert len(role_claims) == 2
    role_values = [claim.value for claim in role_claims]
    assert "admin" in role_values
    assert "user" in role_values

    # Test non-existent claim
    missing_claim = principal.find_first("missing")
    assert missing_claim is None
