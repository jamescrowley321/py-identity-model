"""
Managed async HTTP client for dependency injection.

Wraps ``httpx.AsyncClient`` with lifecycle management and context manager
support.  Pass an ``AsyncHTTPClient`` instance to any public async function
via the ``http_client`` parameter to use a custom client instead of the
module-level singleton.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from ..core.http_utils import get_timeout
from ..ssl_config import get_ssl_verify


if TYPE_CHECKING:
    from types import TracebackType


class AsyncHTTPClient:
    """Managed async HTTP client with optional lifecycle ownership.

    When constructed without an explicit *client*, a new
    ``httpx.AsyncClient`` is created and **owned** by this instance —
    calling :meth:`close` (or exiting the context manager) will close it.

    When an existing *client* is provided, this instance acts as a
    non-owning wrapper and :meth:`close` is a no-op.

    Args:
        client: Existing ``httpx.AsyncClient`` to wrap.  If ``None``, a new
            client is created with the given *timeout* and *verify* settings.
        timeout: Request timeout in seconds.  Defaults to the
            ``HTTP_TIMEOUT`` environment variable or 30.0.
        verify: SSL verification.  Defaults to environment-based
            configuration (see :mod:`py_identity_model.ssl_config`).
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        timeout: float | None = None,
        verify: bool | str = True,
    ) -> None:
        if client is not None:
            self._client = client
            self._owned = False
        else:
            self._client = httpx.AsyncClient(
                verify=verify if verify is not True else get_ssl_verify(),
                timeout=timeout if timeout is not None else get_timeout(),
                follow_redirects=True,
            )
            self._owned = True

    @property
    def client(self) -> httpx.AsyncClient:
        """The underlying ``httpx.AsyncClient``."""
        return self._client

    async def close(self) -> None:
        """Close the client if this instance owns it."""
        if self._owned:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncHTTPClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()


__all__ = ["AsyncHTTPClient"]
