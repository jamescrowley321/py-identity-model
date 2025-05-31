from dataclasses import dataclass
from typing import Optional

from .validation_result import ValidationResult


@dataclass
class StateValidationResult:
    access_token: str = ""
    id_token: str = ""
    auth_response_is_valid: bool = False
    state: ValidationResult = ValidationResult.NotSet
    decoded_id_token: Optional[dict] = None
