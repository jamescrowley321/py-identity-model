# HTTP Client Management

Optional dependency injection for HTTP client lifecycle management.

All public I/O functions accept an optional `http_client` parameter. When omitted (default), the library uses its built-in client management (module-level singleton for async, thread-local for sync). When provided, the injected client is used instead.

## Sync Client

```python
from py_identity_model import HTTPClient, get_discovery_document, DiscoveryDocumentRequest

with HTTPClient() as client:
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address="https://..."),
        http_client=client,
    )
```

::: py_identity_model.sync.managed_client.HTTPClient

## Async Client

```python
from py_identity_model.aio import AsyncHTTPClient, get_discovery_document

async with AsyncHTTPClient() as client:
    disco = await get_discovery_document(
        DiscoveryDocumentRequest(address="https://..."),
        http_client=client,
    )
```

::: py_identity_model.aio.managed_client.AsyncHTTPClient
