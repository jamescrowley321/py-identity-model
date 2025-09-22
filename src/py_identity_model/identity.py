import abc
import enum
from typing import Optional, List


# TODO: real comments instead of AI generated ones
# TODO: rename from lame Base class name


class IdentityBase(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def is_authenticated(self) -> bool:
        """Returns a boolean authentication state"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def authentication_type(self) -> Optional[str]:
        """Returns the authentication type"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def name(self) -> Optional[str]:
        """Returns the name of the Identity"""
        raise NotImplementedError()


class PrincipalBase(metaclass=abc.ABCMeta):
    # TODO: check polymorphism and type hints to make sure LSP applies
    @property
    @abc.abstractmethod
    def identity(self) -> Optional[IdentityBase]:
        """Returns the identity"""
        raise NotImplementedError()

    @abc.abstractmethod
    def is_in_role(self, role: str) -> bool:
        """Determines whether the current principal belongs to the specified role"""
        raise NotImplementedError()

    @abc.abstractmethod
    def has_claim(self, claim_type: str, value: Optional[str] = None) -> bool:
        """Check if a claim exists in the principal context"""
        raise NotImplementedError()


class Claim:
    def __init__(
        self,
        claim_type: str,
        value: str,
        value_type: str = "http://www.w3.org/2001/XMLSchema#string",
        issuer: Optional[str] = None,
        original_issuer: Optional[str] = None,
    ):
        self.claim_type = claim_type
        self.value = value
        self.value_type = value_type
        self.issuer = issuer or "LOCAL AUTHORITY"
        self.original_issuer = original_issuer or self.issuer
        self.properties = {}

    def __str__(self) -> str:
        return f"{self.claim_type}: {self.value}"

    def __repr__(self) -> str:
        return f"Claim(claim_type='{self.claim_type}', value='{self.value}', issuer='{self.issuer}')"


class ClaimType(enum.Enum):
    """Standard claim types matching .NET's ClaimTypes"""

    Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    NameIdentifier = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
    )
    Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    GivenName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    Surname = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    DateOfBirth = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth"
    Country = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country"
    Gender = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender"
    HomePhone = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone"
    MobilePhone = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone"
    PostalCode = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode"
    StateOrProvince = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince"
    )
    StreetAddress = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress"
    )
    Webpage = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/webpage"


class ClaimsIdentity(IdentityBase):
    def __init__(
        self,
        claims: List[Claim],
        authentication_type: Optional[str] = None,
        name_type_claim: str = ClaimType.Name.value,
        role_type_claim: str = ClaimType.Role.value,
    ):
        self.claims = claims
        self.role_type_claim = role_type_claim
        self.name_type_claim = name_type_claim
        self._authentication_type = authentication_type

    @property
    def authentication_type(self) -> Optional[str]:
        return self._authentication_type

    @property
    def name(self) -> Optional[str]:
        # TODO: make this more robust
        name_claim = list(
            filter(lambda claim: claim.claim_type == ClaimType.Name.value, self.claims)
        )
        if name_claim and len(name_claim) > 0:
            return name_claim[0].value
        return None

    def is_authenticated(self) -> bool:
        return self._authentication_type is not None


class ClaimsPrincipal(PrincipalBase):
    def __init__(
        self,
        identity: Optional[IdentityBase] = None,
        claims: Optional[List[Claim]] = None,
    ):
        self._identity = identity
        self._claims = claims or []

        # If identity is a ClaimsIdentity, merge its claims
        if isinstance(identity, ClaimsIdentity):
            self._claims.extend(identity.claims)

    @property
    def identity(self) -> Optional[IdentityBase]:
        return self._identity

    @property
    def claims(self) -> List[Claim]:
        """Returns all claims for this principal"""
        return self._claims

    def add_identity(self, identity: IdentityBase) -> None:
        """Add an identity to this principal"""
        self._identity = identity
        if isinstance(identity, ClaimsIdentity):
            self._claims.extend(identity.claims)

    def has_claim(self, claim_type: str, value: Optional[str] = None) -> bool:
        """Check if a claim exists in the principal context"""
        for claim in self._claims:
            if claim.claim_type == claim_type:
                if value is None or claim.value == value:
                    return True
        return False

    def is_in_role(self, role: str) -> bool:
        """Determines whether the current principal belongs to the specified role"""
        return self.has_claim(ClaimType.Role.value, role)

    def find_first(self, claim_type: str) -> Optional[Claim]:
        """Find the first claim of the specified type"""
        for claim in self._claims:
            if claim.claim_type == claim_type:
                return claim
        return None

    def find_all(self, claim_type: str) -> List[Claim]:
        """Find all claims of the specified type"""
        return [claim for claim in self._claims if claim.claim_type == claim_type]
