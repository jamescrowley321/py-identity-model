"""Typed configuration for the FastAPI OIDC integration."""

from __future__ import annotations

from dataclasses import dataclass, field
import os


def _default_excluded_paths() -> list[str]:
    return ["/docs", "/openapi.json", "/health"]


@dataclass
class OIDCSettings:
    """Configuration shared by the RP login router and the resource-server middleware.

    Attributes:
        discovery_url: OpenID Connect discovery document URL of the provider.
        client_id: OAuth2 client identifier.
        redirect_uri: Absolute callback URL registered with the provider
            (must match the router's ``/callback`` route).
        client_secret: Client secret; omit for public/PKCE clients.
        scope: Space-delimited scopes requested at authorization.
        audience: Expected ``aud`` for the resource-server middleware. Defaults
            to ``client_id`` when not set.
        post_login_redirect: Where ``/callback`` redirects after a successful login.
        post_logout_redirect: Where ``/logout`` redirects after clearing the session.
        excluded_paths: Paths the resource-server middleware skips (health/docs).
    """

    discovery_url: str
    client_id: str
    redirect_uri: str
    client_secret: str | None = None
    scope: str = "openid profile email"
    audience: str | None = None
    post_login_redirect: str = "/"
    post_logout_redirect: str = "/"
    excluded_paths: list[str] = field(default_factory=_default_excluded_paths)

    def __post_init__(self) -> None:
        # The middleware validates the ID/access token audience; default it to
        # the client_id, which is the audience Descope and most OPs mint.
        if self.audience is None:
            self.audience = self.client_id

    @classmethod
    def from_env(cls, prefix: str = "OIDC_") -> OIDCSettings:
        """Build settings from environment variables (e.g. ``OIDC_DISCOVERY_URL``).

        Required: ``{prefix}DISCOVERY_URL``, ``{prefix}CLIENT_ID``,
        ``{prefix}REDIRECT_URI``. Others fall back to the dataclass defaults.
        """

        def _req(name: str) -> str:
            value = os.environ.get(f"{prefix}{name}")
            if not value:
                raise ValueError(f"Missing required env var {prefix}{name}")
            return value

        excluded = os.environ.get(f"{prefix}EXCLUDED_PATHS")
        return cls(
            discovery_url=_req("DISCOVERY_URL"),
            client_id=_req("CLIENT_ID"),
            redirect_uri=_req("REDIRECT_URI"),
            client_secret=os.environ.get(f"{prefix}CLIENT_SECRET"),
            scope=os.environ.get(f"{prefix}SCOPE", "openid profile email"),
            audience=os.environ.get(f"{prefix}AUDIENCE"),
            post_login_redirect=os.environ.get(f"{prefix}POST_LOGIN_REDIRECT", "/"),
            post_logout_redirect=os.environ.get(f"{prefix}POST_LOGOUT_REDIRECT", "/"),
            excluded_paths=(
                [p.strip() for p in excluded.split(",") if p.strip()]
                if excluded
                else _default_excluded_paths()
            ),
        )
