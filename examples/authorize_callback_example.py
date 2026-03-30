"""
Authorization Callback Examples for py-identity-model

Demonstrates parsing OAuth 2.0 / OpenID Connect authorization callback URLs
and validating the state parameter for CSRF protection.

These operations are pure (no HTTP I/O) and work identically in sync and async contexts.
"""

import secrets

from py_identity_model import (
    AuthorizeCallbackValidationResult,
    parse_authorize_callback_response,
    validate_authorize_callback_state,
)


# =============================================================================
# Example 1: Parse Authorization Code Flow Callback
# =============================================================================


def parse_code_flow_callback():
    """Parse a callback URL from the authorization code flow."""
    print("\n" + "=" * 60)
    print("Example 1: Authorization Code Flow Callback")
    print("=" * 60)

    # This URL is what your app receives after the user authorizes
    callback_url = (
        "https://app.example.com/callback"
        "?code=SplxlOBeZQQYbYS6WxSbIA"
        "&state=af0ifjsldkj"
    )

    response = parse_authorize_callback_response(callback_url)

    if response.is_successful:
        print("Authorization successful!")
        print(f"  Code: {response.code}")
        print(f"  State: {response.state}")
        # Next step: exchange the code for tokens at the token endpoint
    else:
        print(f"Authorization failed: {response.error}")

    return response


# =============================================================================
# Example 2: CSRF Protection with State Validation
# =============================================================================


def state_validation_example():
    """Demonstrate state parameter validation for CSRF protection."""
    print("\n" + "=" * 60)
    print("Example 2: State Validation (CSRF Protection)")
    print("=" * 60)

    # Step 1: Generate state before redirecting user to authorize
    original_state = secrets.token_urlsafe(32)
    print(f"  Generated state: {original_state[:20]}...")

    # Step 2: Store state in session (simulated)
    session = {"oauth_state": original_state}

    # Step 3: User authorizes and is redirected back
    callback_url = (
        f"https://app.example.com/callback"
        f"?code=authorization_code_here"
        f"&state={original_state}"
    )

    # Step 4: Parse and validate
    response = parse_authorize_callback_response(callback_url)
    result = validate_authorize_callback_state(
        response, session["oauth_state"]
    )

    if result.is_valid:
        print("State validation passed - safe to proceed")
        print(f"  Result: {result.result.value}")
    else:
        print(f"State validation failed: {result.error}")
        print(f"  Description: {result.error_description}")

    return result


# =============================================================================
# Example 3: Handle Error Responses
# =============================================================================


def handle_error_response():
    """Handle authorization error responses from the identity provider."""
    print("\n" + "=" * 60)
    print("Example 3: Error Response Handling")
    print("=" * 60)

    # Authorization server denied the request
    callback_url = (
        "https://app.example.com/callback"
        "?error=access_denied"
        "&error_description=The+resource+owner+denied+the+request"
        "&state=af0ifjsldkj"
    )

    response = parse_authorize_callback_response(callback_url)

    if not response.is_successful:
        print(f"Authorization error: {response.error}")
        print(f"  Description: {response.error_description}")
        # state is still accessible on error responses (RFC 6749 Section 4.1.2.1)
        print(f"  State: {response.state}")
        # Use state to look up the original request and clean up session
    else:
        print("Unexpected success")

    return response


# =============================================================================
# Example 4: Detect CSRF Attack
# =============================================================================


def detect_csrf_attack():
    """Demonstrate detection of a CSRF attack via state mismatch."""
    print("\n" + "=" * 60)
    print("Example 4: CSRF Attack Detection")
    print("=" * 60)

    # Legitimate state stored in user's session
    legitimate_state = secrets.token_urlsafe(32)

    # Attacker crafts a callback with a different state
    attacker_state = secrets.token_urlsafe(32)
    malicious_callback = (
        f"https://app.example.com/callback"
        f"?code=stolen_code&state={attacker_state}"
    )

    response = parse_authorize_callback_response(malicious_callback)
    result = validate_authorize_callback_state(response, legitimate_state)

    if not result.is_valid:
        if result.result is AuthorizeCallbackValidationResult.STATE_MISMATCH:
            print("CSRF attack detected! State does not match.")
            print("  Action: Reject this callback and log the incident.")
        else:
            print(f"Validation failed: {result.error}")
    else:
        print("Unexpected: validation passed")

    return result


# =============================================================================
# Example 5: Implicit Flow (Fragment-Based)
# =============================================================================


def parse_implicit_flow_callback():
    """Parse a callback from the implicit flow (tokens in URL fragment)."""
    print("\n" + "=" * 60)
    print("Example 5: Implicit Flow Callback (Fragment)")
    print("=" * 60)

    # Implicit flow returns tokens in the URL fragment
    callback_url = (
        "https://app.example.com/callback"
        "#access_token=eyJhbGciOi..."
        "&token_type=Bearer"
        "&expires_in=3600"
        "&state=af0ifjsldkj"
    )

    response = parse_authorize_callback_response(callback_url)

    if response.is_successful:
        print("Tokens received via implicit flow:")
        access_token = response.access_token or ""
        print(f"  Access Token: {access_token[:20]}...")
        print(f"  Token Type: {response.token_type}")
        print(f"  Expires In: {response.expires_in}")
        print(f"  State: {response.state}")
    else:
        print(f"Error: {response.error}")

    return response


# =============================================================================
# Example 6: Web Framework Integration Pattern
# =============================================================================


def web_framework_pattern():
    """Demonstrate integration pattern for web frameworks (Flask/FastAPI)."""
    print("\n" + "=" * 60)
    print("Example 6: Web Framework Integration Pattern")
    print("=" * 60)

    # Simulated session store
    sessions: dict[str, str] = {}

    def start_login() -> str:
        """Step 1: Generate state and redirect to authorize endpoint."""
        state = secrets.token_urlsafe(32)
        sessions["oauth_state"] = state

        # Build authorization URL (would redirect user here)
        authorize_url = (
            "https://auth.example.com/authorize"
            "?response_type=code"
            "&client_id=my_app"
            f"&state={state}"
            "&redirect_uri=https://app.example.com/callback"
            "&scope=openid+profile+email"
        )
        print(f"  Redirect user to: {authorize_url[:60]}...")
        return state

    def handle_callback(callback_url: str) -> dict:
        """Step 2: Handle the callback and validate state."""
        response = parse_authorize_callback_response(callback_url)

        if not response.is_successful:
            return {"error": response.error, "status": 400}

        result = validate_authorize_callback_state(
            response, sessions["oauth_state"]
        )

        if not result.is_valid:
            return {"error": result.error, "status": 403}

        # State valid — exchange code for tokens
        return {
            "message": "Login successful",
            "code": response.code,
            "status": 200,
        }

    # Simulate the flow
    state = start_login()
    callback = (
        f"https://app.example.com/callback?code=auth_code_123&state={state}"
    )
    result = handle_callback(callback)
    print(f"  Result: {result}")

    return result


# =============================================================================
# Main: Run All Examples
# =============================================================================


def main():
    """Run all authorization callback examples."""
    print("\n" + "=" * 60)
    print("PY-IDENTITY-MODEL AUTHORIZATION CALLBACK EXAMPLES")
    print("=" * 60)
    print(
        "\nThese examples demonstrate OAuth 2.0 / OIDC callback parsing"
        "\nand state validation for CSRF protection.\n"
    )

    parse_code_flow_callback()
    state_validation_example()
    handle_error_response()
    detect_csrf_attack()
    parse_implicit_flow_callback()
    web_framework_pattern()

    print("\n" + "=" * 60)
    print("All authorization callback examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
