import abc
import enum
from typing import List, Optional


class Identity(metaclass=abc.ABCMeta):
    """
    Abstract base class defining the interface for identity objects.

    Equivalent to .NET's IIdentity interface. Represents the identity
    of a user, including authentication status, authentication method,
    and identity name.
    """

    @abc.abstractmethod
    def is_authenticated(self) -> bool:
        """
        Indicates whether the identity has been authenticated.

        Returns:
            bool: True if the identity is authenticated, False otherwise.
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def authentication_type(self) -> Optional[str]:
        """
        Gets the type of authentication used.

        Returns:
            Optional[str]: The authentication type (e.g., "Bearer", "Basic"),
                          or None if not authenticated.
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def name(self) -> Optional[str]:
        """
        Gets the name of the current identity.

        Returns:
            Optional[str]: The identity name, or None if not available.
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def claims(self) -> List["Claim"]:
        """
        Gets the claims associated with this identity.

        Returns:
            List[Claim]: The claims for this identity.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def find_first(self, claim_type: str) -> Optional["Claim"]:
        """
        Find the first claim of the specified type.

        Args:
            claim_type: The type of claim to find.

        Returns:
            Optional[Claim]: The first matching claim, or None if not found.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def find_all(self, claim_type: str) -> List["Claim"]:
        """
        Find all claims of the specified type.

        Args:
            claim_type: The type of claims to find.

        Returns:
            List[Claim]: All matching claims.
        """
        raise NotImplementedError()


class Principal(metaclass=abc.ABCMeta):
    """
    Abstract base class defining the interface for principal objects.

    Equivalent to .NET's IPrincipal interface. Represents the security
    context under which code is running, including the user identity
    and roles.
    """

    @property
    @abc.abstractmethod
    def identity(self) -> Optional[Identity]:
        """
        Gets the identity of the current principal.

        Returns:
            Optional[Identity]: The identity associated with the principal.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def is_in_role(self, role: str) -> bool:
        """
        Determines whether the current principal belongs to the specified role.

        Args:
            role: The role name to check.

        Returns:
            bool: True if the principal is in the specified role, False otherwise.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def has_claim(self, claim_type: str, value: Optional[str] = None) -> bool:
        """
        Determines whether the principal has a claim with the specified type and value.

        Args:
            claim_type: The type of claim to search for.
            value: Optional value the claim must have. If None, checks only for claim type.

        Returns:
            bool: True if a matching claim exists, False otherwise.
        """
        raise NotImplementedError()


class Claim:
    """
    Represents a claim as a name-value pair with additional metadata.

    Equivalent to .NET's System.Security.Claims.Claim. A claim is a statement
    about an entity made by an issuer, consisting of a type, value, and
    additional properties.

    Attributes:
        claim_type: The claim type URI that identifies the claim.
        value: The value of the claim.
        value_type: The type of the value (default: XML Schema string).
        issuer: The entity that issued the claim.
        original_issuer: The original issuer if the claim was delegated.
        properties: Additional properties associated with the claim.
    """

    def __init__(
        self,
        claim_type: str,
        value: str,
        value_type: str = "http://www.w3.org/2001/XMLSchema#string",
        issuer: Optional[str] = None,
        original_issuer: Optional[str] = None,
    ):
        """
        Initialize a new Claim instance.

        Args:
            claim_type: The claim type URI.
            value: The claim value.
            value_type: The value type URI. Defaults to XML Schema string.
            issuer: The issuer of the claim. Defaults to "LOCAL AUTHORITY".
            original_issuer: The original issuer. Defaults to the issuer value.
        """
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
    Email = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    )
    GivenName = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    )
    Surname = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    DateOfBirth = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth"
    )
    Country = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country"
    Gender = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender"
    HomePhone = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone"
    )
    MobilePhone = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone"
    )
    PostalCode = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode"
    )
    StateOrProvince = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince"
    )
    StreetAddress = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress"
    )
    Webpage = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/webpage"


class ClaimsIdentity(Identity):
    """
    Represents a claims-based identity.

    Equivalent to .NET's System.Security.Claims.ClaimsIdentity. Contains
    a collection of claims that describe the identity.

    Attributes:
        claims: List of claims associated with this identity.
        role_type_claim: The claim type to use for role claims.
        name_type_claim: The claim type to use for the name claim.
    """

    def __init__(
        self,
        claims: List[Claim],
        authentication_type: Optional[str] = None,
        name_type_claim: str = ClaimType.Name.value,
        role_type_claim: str = ClaimType.Role.value,
    ):
        """
        Initialize a new ClaimsIdentity instance.

        Args:
            claims: The claims for this identity.
            authentication_type: The authentication method used.
            name_type_claim: The claim type for the identity name.
            role_type_claim: The claim type for roles.
        """
        self._claims = claims
        self.role_type_claim = role_type_claim
        self.name_type_claim = name_type_claim
        self._authentication_type = authentication_type

    @property
    def claims(self) -> List[Claim]:
        return self._claims

    @property
    def authentication_type(self) -> Optional[str]:
        return self._authentication_type

    @property
    def name(self) -> Optional[str]:
        """
        Gets the name of the identity from the name claim.

        Returns:
            Optional[str]: The name value from the first matching name claim,
                          or None if no name claim exists.
        """
        name_claim = next(
            (
                claim
                for claim in self._claims
                if claim.claim_type == self.name_type_claim
            ),
            None,
        )
        return name_claim.value if name_claim else None

    def is_authenticated(self) -> bool:
        return self._authentication_type is not None

    def find_first(self, claim_type: str) -> Optional[Claim]:
        """
        Find the first claim of the specified type.

        Args:
            claim_type: The type of claim to find.

        Returns:
            Optional[Claim]: The first matching claim, or None if not found.
        """
        return next(
            (claim for claim in self.claims if claim.claim_type == claim_type),
            None,
        )

    def find_all(self, claim_type: str) -> List[Claim]:
        """
        Find all claims of the specified type.

        Args:
            claim_type: The type of claims to find.

        Returns:
            List[Claim]: All matching claims.
        """
        return [
            claim for claim in self.claims if claim.claim_type == claim_type
        ]


class ClaimsPrincipal(Principal):
    """
    Represents a principal with a claims-based identity.

    Equivalent to .NET's System.Security.Claims.ClaimsPrincipal. Contains
    one or more identities and provides access to all claims across those
    identities.

    Attributes:
        claims: All claims associated with this principal's identities.
    """

    def __init__(
        self,
        identity: Optional[Identity] = None,
        claims: Optional[List[Claim]] = None,
    ):
        """
        Initialize a new ClaimsPrincipal instance.

        Args:
            identity: The primary identity for this principal.
            claims: Additional claims to associate with the principal.
        """
        self._identity = identity
        self._claims = claims or []

        # If identity is a ClaimsIdentity, merge its claims
        if isinstance(identity, ClaimsIdentity):
            self._claims.extend(identity.claims)

    @property
    def identity(self) -> Optional[Identity]:
        return self._identity

    @property
    def claims(self) -> List[Claim]:
        """
        Gets all claims for this principal.

        Returns:
            List[Claim]: All claims from the principal's identity and additional claims.
        """
        return self._claims

    def add_identity(self, identity: Identity) -> None:
        """
        Add an identity to this principal.

        Args:
            identity: The identity to add.
        """
        self._identity = identity
        if isinstance(identity, ClaimsIdentity):
            self._claims.extend(identity.claims)

    def has_claim(self, claim_type: str, value: Optional[str] = None) -> bool:
        """
        Check if a claim exists in the principal context.

        Args:
            claim_type: The type of claim to search for.
            value: Optional value the claim must have.

        Returns:
            bool: True if a matching claim exists, False otherwise.
        """
        return any(
            claim.claim_type == claim_type
            and (value is None or claim.value == value)
            for claim in self._claims
        )

    def is_in_role(self, role: str) -> bool:
        """
        Determines whether the current principal belongs to the specified role.

        Args:
            role: The role name to check.

        Returns:
            bool: True if the principal has a role claim with the specified value.
        """
        return self.has_claim(ClaimType.Role.value, role)

    def find_first(self, claim_type: str) -> Optional[Claim]:
        """
        Find the first claim of the specified type.

        Args:
            claim_type: The type of claim to find.

        Returns:
            Optional[Claim]: The first matching claim, or None if not found.
        """
        return next(
            (
                claim
                for claim in self._claims
                if claim.claim_type == claim_type
            ),
            None,
        )

    def find_all(self, claim_type: str) -> List[Claim]:
        """
        Find all claims of the specified type.

        Args:
            claim_type: The type of claims to find.

        Returns:
            List[Claim]: All matching claims.
        """
        return [
            claim for claim in self._claims if claim.claim_type == claim_type
        ]
