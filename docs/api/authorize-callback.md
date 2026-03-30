# Authorize Callback

Parse OAuth 2.0 / OIDC authorization callback redirect URIs and validate the `state` parameter for CSRF protection.

These functions are pure (no I/O) and available identically from both sync and async modules.

## Response Model

::: py_identity_model.core.authorize_response.AuthorizeCallbackResponse

## Parsing

::: py_identity_model.core.authorize_response.parse_authorize_callback_response

## State Validation

::: py_identity_model.core.state_validation.AuthorizeCallbackValidationResult

::: py_identity_model.core.state_validation.StateValidationResult

::: py_identity_model.core.state_validation.validate_authorize_callback_state
