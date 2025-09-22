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
    def has_claim(self):
        """Check if a claim exists in the principal context"""
        raise NotImplementedError()


class Claim:
    def __init__(self, claim_type: str, value: str):
        self.claim_type = claim_type
        self.value = value


class ClaimType(enum.Enum):
    Name = "name"
    Role = "role"


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
            filter(lambda claim: claim.name == ClaimType.Name, self.claims)
        )
        if name_claim and len(name_claim) > 0:
            return name_claim[0].value
        return None

    def is_authenticated(self) -> bool:
        return self._authentication_type is not None
