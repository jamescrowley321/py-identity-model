"""Test module to verify the identity model implementation"""

from py_identity_model.identity import Claim, ClaimType, ClaimsIdentity, ClaimsPrincipal


class TestClaim:
    def test_claim_creation_basic(self):
        """Test basic claim creation"""
        claim = Claim(ClaimType.Name.value, "John Doe")
        assert claim.claim_type == ClaimType.Name.value
        assert claim.value == "John Doe"
        assert claim.issuer == "LOCAL AUTHORITY"
        assert str(claim) == f"{ClaimType.Name.value}: John Doe"

    def test_claim_creation_with_custom_issuer(self):
        """Test claim creation with custom issuer"""
        role_claim = Claim(ClaimType.Role.value, "Admin", issuer="MyApp")
        assert role_claim.claim_type == ClaimType.Role.value
        assert role_claim.value == "Admin"
        assert role_claim.issuer == "MyApp"
        assert role_claim.original_issuer == "MyApp"


class TestClaimsIdentity:
    def test_claims_identity_authenticated(self):
        """Test authenticated ClaimsIdentity functionality"""
        claims = [
            Claim(ClaimType.Name.value, "John Doe"),
            Claim(ClaimType.Email.value, "john@example.com"),
            Claim(ClaimType.Role.value, "User"),
        ]

        identity = ClaimsIdentity(claims, authentication_type="Bearer")

        assert identity.name == "John Doe"
        assert identity.authentication_type == "Bearer"
        assert identity.is_authenticated() is True
        assert len(identity.claims) == 3

    def test_claims_identity_unauthenticated(self):
        """Test unauthenticated ClaimsIdentity"""
        unauth_identity = ClaimsIdentity([])
        assert unauth_identity.is_authenticated() is False
        assert unauth_identity.authentication_type is None
        assert unauth_identity.name is None


class TestClaimsPrincipal:
    def test_claims_principal_functionality(self):
        """Test ClaimsPrincipal functionality"""
        claims = [
            Claim(ClaimType.Name.value, "Jane Smith"),
            Claim(ClaimType.Email.value, "jane@example.com"),
            Claim(ClaimType.Role.value, "Admin"),
            Claim(ClaimType.Role.value, "User"),
        ]

        identity = ClaimsIdentity(claims, authentication_type="Bearer")
        principal = ClaimsPrincipal(identity)

        assert principal.identity is not None
        assert principal.identity.name == "Jane Smith"
        assert len(principal.claims) == 4

    def test_claims_principal_has_claim(self):
        """Test has_claim functionality"""
        claims = [
            Claim(ClaimType.Name.value, "Jane Smith"),
            Claim(ClaimType.Email.value, "jane@example.com"),
        ]

        identity = ClaimsIdentity(claims, authentication_type="Bearer")
        principal = ClaimsPrincipal(identity)

        assert principal.has_claim(ClaimType.Name.value) is True
        assert principal.has_claim(ClaimType.Name.value, "Jane Smith") is True
        assert principal.has_claim(ClaimType.Country.value) is False

    def test_claims_principal_roles(self):
        """Test is_in_role functionality"""
        claims = [
            Claim(ClaimType.Name.value, "Jane Smith"),
            Claim(ClaimType.Role.value, "Admin"),
            Claim(ClaimType.Role.value, "User"),
        ]

        identity = ClaimsIdentity(claims, authentication_type="Bearer")
        principal = ClaimsPrincipal(identity)

        assert principal.is_in_role("Admin") is True
        assert principal.is_in_role("User") is True
        assert principal.is_in_role("Manager") is False

    def test_claims_principal_find_methods(self):
        """Test find_first and find_all methods"""
        claims = [
            Claim(ClaimType.Name.value, "Jane Smith"),
            Claim(ClaimType.Role.value, "Admin"),
            Claim(ClaimType.Role.value, "User"),
        ]

        identity = ClaimsIdentity(claims, authentication_type="Bearer")
        principal = ClaimsPrincipal(identity)

        name_claim = principal.find_first(ClaimType.Name.value)
        assert name_claim is not None
        assert name_claim.value == "Jane Smith"

        role_claims = principal.find_all(ClaimType.Role.value)
        assert len(role_claims) == 2
        role_values = [claim.value for claim in role_claims]
        assert "Admin" in role_values
        assert "User" in role_values

    def test_principal_with_additional_claims(self):
        """Test integration scenarios with additional claims"""
        extra_claims = [Claim(ClaimType.Country.value, "USA")]
        identity = ClaimsIdentity(
            [
                Claim(ClaimType.Name.value, "Bob Wilson"),
                Claim(ClaimType.Role.value, "Manager"),
            ],
            authentication_type="JWT",
        )

        principal = ClaimsPrincipal(identity, extra_claims)

        assert len(principal.claims) == 3
        assert principal.has_claim(ClaimType.Country.value) is True
        assert principal.is_in_role("Manager") is True
