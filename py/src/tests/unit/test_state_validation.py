"""Unit tests for authorization callback state validation."""

from urllib.parse import quote

import pytest

from py_identity_model import aio
from py_identity_model.core.authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from py_identity_model.core.state_validation import (
    AuthorizeCallbackValidationResult,
    validate_authorize_callback_issuer,
    validate_authorize_callback_state,
)


CALLBACK = "https://app.example.com/callback"


def _parse(params: str) -> AuthorizeCallbackResponse:
    sep = "#" if params.startswith("#") else "?"
    return parse_authorize_callback_response(f"{CALLBACK}{sep}{params}")


@pytest.mark.unit
class TestValidateAuthorizeCallbackState:
    """Tests for validate_authorize_callback_state."""

    @pytest.mark.parametrize(
        ("params", "expected_state", "want_result"),
        [
            (
                "code=abc&state=s1",
                "s1",
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
            (
                "#access_token=tok&state=s2&token_type=Bearer",
                "s2",
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
            (
                f"code=c&state={'a' * 1024}",
                "a" * 1024,
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
            (
                f"code=c&state={quote('abc+def/ghi=jkl&mno', safe='')}",
                "abc+def/ghi=jkl&mno",
                AuthorizeCallbackValidationResult.SUCCESS,
            ),
        ],
        ids=["code-flow", "implicit-flow", "long-state", "special-chars"],
    )
    def test_valid_state(
        self,
        params: str,
        expected_state: str,
        want_result: AuthorizeCallbackValidationResult,
    ):
        response = _parse(params)
        result = validate_authorize_callback_state(response, expected_state)

        assert result.is_valid is True
        assert result.result is want_result
        assert result.error is None

    def test_state_mismatch(self):
        result = validate_authorize_callback_state(
            _parse("code=abc&state=wrong"), "expected"
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.STATE_MISMATCH
        assert result.error == "state_mismatch"
        assert result.error_description is not None

    def test_missing_state(self):
        result = validate_authorize_callback_state(_parse("code=abc"), "expected")

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE
        assert result.error == "missing_state"

    def test_empty_state_treated_as_missing(self):
        """Empty state value preserved by parse_qs but caught by validator."""
        result = validate_authorize_callback_state(_parse("code=c&state="), "expected")

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE

    def test_error_response_propagates_error_fields(self):
        result = validate_authorize_callback_state(
            _parse("error=access_denied&error_description=User+denied&state=s"),
            "s",
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE
        assert result.error == "access_denied"
        assert result.error_description == "User denied"

    def test_error_response_takes_precedence_over_state(self):
        """Error detection runs before state comparison."""
        result = validate_authorize_callback_state(_parse("error=server_error"), "any")

        assert result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE

    def test_expected_state_none_returns_missing_state(self):
        """[M1] expected_state=None must not crash with TypeError in hmac.compare_digest."""
        result = validate_authorize_callback_state(_parse("code=abc&state=valid"), None)

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE
        assert result.error == "missing_state"
        assert result.error_description is not None

    def test_expected_state_empty_string_returns_missing_state(self):
        """[BLOCK] Empty string expected_state must not pass hmac.compare_digest."""
        result = validate_authorize_callback_state(_parse("code=abc&state=valid"), "")

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE
        assert result.error == "missing_state"

    def test_both_states_empty_string_rejected(self):
        """[BLOCK] hmac.compare_digest('', '') bypass must be prevented."""
        response = AuthorizeCallbackResponse(
            is_successful=True,
            raw="",
            values={},
            state="",
        )
        result = validate_authorize_callback_state(response, "")

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE

    def test_expected_state_non_string_type_returns_missing(self):
        """Non-string expected_state must be treated as missing, not crash."""
        result = validate_authorize_callback_state(
            _parse("code=abc&state=valid"),
            12345,  # type: ignore
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_STATE


ISSUER = "https://as.example.com"


@pytest.mark.unit
class TestValidateAuthorizeCallbackIssuer:
    """Tests for validate_authorize_callback_issuer (RFC 9207)."""

    def test_issuer_match(self):
        """A present iss matching the expected issuer passes."""
        result = validate_authorize_callback_issuer(
            _parse(f"code=abc&iss={quote(ISSUER, safe='')}"),
            ISSUER,
        )

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS
        assert result.error is None

    def test_issuer_match_when_advertised(self):
        """Match still succeeds when the AS advertises iss support."""
        result = validate_authorize_callback_issuer(
            _parse(f"code=abc&iss={quote(ISSUER, safe='')}"),
            ISSUER,
            iss_parameter_supported=True,
        )

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS

    def test_issuer_mismatch(self):
        """A present iss that differs from expected fails (mix-up defense)."""
        result = validate_authorize_callback_issuer(
            _parse(f"code=abc&iss={quote('https://evil.example.com', safe='')}"),
            ISSUER,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH
        assert result.error == "issuer_mismatch"
        assert result.error_description is not None

    def test_issuer_present_validated_even_when_not_advertised(self):
        """A present iss is ALWAYS validated, regardless of metadata flag."""
        result = validate_authorize_callback_issuer(
            _parse(f"code=abc&iss={quote('https://evil.example.com', safe='')}"),
            ISSUER,
            iss_parameter_supported=False,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH

    def test_issuer_present_but_expected_none_fails_closed(self):
        """iss present but no expected issuer known -> mismatch (cannot verify)."""
        result = validate_authorize_callback_issuer(
            _parse(f"code=abc&iss={quote(ISSUER, safe='')}"),
            None,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH

    def test_missing_issuer_when_advertised(self):
        """Absent iss fails when the AS advertised iss support."""
        result = validate_authorize_callback_issuer(
            _parse("code=abc"),
            ISSUER,
            iss_parameter_supported=True,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_ISSUER
        assert result.error == "missing_issuer"
        assert result.error_description is not None

    def test_missing_issuer_when_required(self):
        """Absent iss fails when the caller opts into strict mode."""
        result = validate_authorize_callback_issuer(
            _parse("code=abc"),
            ISSUER,
            require=True,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.MISSING_ISSUER

    def test_missing_issuer_not_advertised_not_required_ok(self):
        """Absent iss passes when neither advertised nor required (no downgrade surprise)."""
        result = validate_authorize_callback_issuer(
            _parse("code=abc"),
            ISSUER,
        )

        assert result.is_valid is True
        assert result.result is AuthorizeCallbackValidationResult.SUCCESS

    def test_error_response_takes_precedence_over_issuer(self):
        """Error detection runs before issuer checks."""
        result = validate_authorize_callback_issuer(
            _parse("error=access_denied&error_description=User+denied"),
            ISSUER,
            require=True,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ERROR_RESPONSE
        assert result.error == "access_denied"
        assert result.error_description == "User denied"

    def test_present_but_empty_issuer_is_mismatch(self):
        """A present-but-empty iss (``&iss=``) is malformed, not absent.

        The parser preserves ``iss=`` as "" (distinct from an absent param),
        so it must be validated and rejected rather than downgraded to the
        MISSING_ISSUER/absent branch where a non-enforcing caller would pass.
        """
        response = _parse("code=abc&iss=")
        assert response.issuer == ""  # present, empty (not None)

        result = validate_authorize_callback_issuer(response, ISSUER)

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH

    def test_empty_issuer_not_treated_as_absent_even_when_unenforced(self):
        """Empty iss must not slip through the permissive absent path."""
        result = validate_authorize_callback_issuer(
            _parse("code=abc&iss="),
            ISSUER,
            iss_parameter_supported=False,
            require=False,
        )

        assert result.is_valid is False
        assert result.result is AuthorizeCallbackValidationResult.ISSUER_MISMATCH


@pytest.mark.unit
def test_issuer_validator_exported_from_async_surface():
    """The validator is re-exported from the aio surface (async-context AC).

    It is a single pure function shared across sync/aio/core; assert the aio
    package exposes the same callable so async callers can import it there.
    """
    assert hasattr(aio, "validate_authorize_callback_issuer")
    assert aio.validate_authorize_callback_issuer is validate_authorize_callback_issuer

    # Exercise it through the aio-imported reference to cover the async surface.
    result = aio.validate_authorize_callback_issuer(
        _parse(f"code=abc&iss={quote(ISSUER, safe='')}"),
        ISSUER,
        iss_parameter_supported=True,
    )
    assert result.is_valid is True
    assert result.result is AuthorizeCallbackValidationResult.SUCCESS
