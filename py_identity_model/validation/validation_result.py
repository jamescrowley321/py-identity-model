from enum import Enum


class ValidationResult(Enum):
    NotSet = ("NotSet",)
    StatesDoNotMatch = ("StatesDoNotMatch",)
    SignatureFailed = ("SignatureFailed",)
    IncorrectNonce = ("IncorrectNonce",)
    RequiredPropertyMissing = ("RequiredPropertyMissing",)
    MaxOffsetExpired = ("MaxOffsetExpired",)
    IssDoesNotMatchIssuer = ("IssDoesNotMatchIssuer",)
    NoAuthWellKnownEndPoints = ("NoAuthWellKnownEndPoints",)
    IncorrectAud = ("IncorrectAud",)
    IncorrectIdTokenClaimsAfterRefresh = (
        "IncorrectIdTokenClaimsAfterRefresh",
    )
    IncorrectAzp = ("IncorrectAzp",)
    TokenExpired = ("TokenExpired",)
    IncorrectAtHash = ("IncorrectAtHash",)
    Ok = ("Ok",)
    LoginRequired = ("LoginRequired",)
    SecureTokenServerError = ("SecureTokenServerError",)
