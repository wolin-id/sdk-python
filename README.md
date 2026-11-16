# wolin-id — Official Python SDK for Wolin (月印千江)

[![CI](https://github.com/wolin-id/sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/wolin-id/sdk-python/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-informational.svg)](#license)

`wolin-id` is the official async Python SDK for **[Wolin (月印千江)](https://wolin.id)** — the Sovereign Solid Pod Cloud & Native AI Agent Semantic Mesh built on W3C Solid standards.

It is fully interoperable with Wolin Solid Pod Engine, Inrupt Enterprise Solid Server (ESS), and Community Solid Server (CSS).

## Features

- **RFC 9449 DPoP (`ES256`) Proof-of-Possession**: Ephemeral or PEM-backed NIST P-256 (`SECP256R1`) keypairs, IEEE P1363 compact JWT signatures, RFC 7638 SHA-256 JWK thumbprints (`jkt`), `ath` access-token binding, and automatic `DPoP-Nonce` challenge retry.
- **Solid-OIDC & WebID Discovery**: Built-in zero-dependency W3C Turtle / N-Triples parser for WebID Profile dereferencing (`pim:storage`, `solid:oidcIssuer`, `ldp:inbox`, `foaf:name`) and `solid:oidcIssuer` trust-chain verification.
- **Async Solid LDP CRUD with ETag Concurrency Control**: `GET`, `HEAD`, `PUT`, `PATCH` (`application/sparql-update`), and `DELETE` over `httpx.AsyncClient` with `ETag`, `If-Match`, `If-None-Match`, `Link` (`rel="type"`, `rel="acl"`), and `WAC-Allow` metadata extraction.
- **Safe Signed-Asset Offload Redirects (`302 Found`)**: Automatically follows short-lived HMAC-signed Edge/R2/CDN redirects on `GET` / `HEAD` **without** leaking `Authorization` or `DPoP` headers across origins.
- **`pod_id` Handle Validation & Provisioning**: First-class `is_valid_pod_id()` / `validate_pod_id()` helpers (`3..32` chars, lowercase `[a-z0-9-]`, starts/ends with `[a-z0-9]`, no `--`, reserved-handle blocklist) and `provision_pod()` (`POST /api/pods`).
- **Strictly Typed**: PEP 561 `py.typed` package targeting Python `>=3.11`.

## Official Production Endpoints

| Service | Endpoint | Constant |
| :--- | :--- | :--- |
| Solid-OIDC Provider & Passport | `https://auth.wolin.id` | `DEFAULT_AUTH_URL` |
| Sovereign Solid Pod Engine | `https://pod.wolin.id` | `DEFAULT_POD_URL` |

## Installation

```bash
pip install wolin-id
```

## Quick Start

```python
import asyncio
import os
from wolin_id import (
    DEFAULT_AUTH_URL,
    DEFAULT_POD_URL,
    DpopSigner,
    WolinClient,
    is_valid_pod_id,
)


async def main() -> None:
    assert is_valid_pod_id("alice")  # 3..32 chars, lowercase [a-z0-9-], no '--'
    signer = DpopSigner.generate()

    async with WolinClient(
        base_url=DEFAULT_POD_URL,  # https://pod.wolin.id
        access_token=os.environ["WOLIN_ACCESS_TOKEN"],
        dpop_signer=signer,
    ) as client:
        # 1. Discover Pod storage from a W3C WebID Profile
        profile = await client.fetch_webid_profile(
            "https://alice.wolin.id/profile/card#me"
        )
        profile.verify_oidc_issuer(DEFAULT_AUTH_URL)  # https://auth.wolin.id
        storage_url = profile.primary_storage
        assert storage_url is not None

        # 2. Create a new RDF resource (fails with 412 if it already exists)
        note_url = f"{storage_url}private/note.ttl"
        created = await client.put(
            note_url,
            '@prefix dc: <http://purl.org/dc/terms/> .\n<> dc:title "Hello Wolin" .\n',
            content_type="text/turtle",
            create_only=True,
        )

        # 3. Read resource & ETag (safely follows 302 signed R2/CDN asset redirects without leaking DPoP)
        res = await client.get(note_url)
        print(res.text, res.etag)

        # 4. Safe optimistic update using If-Match
        updated = await client.put(
            note_url,
            '@prefix dc: <http://purl.org/dc/terms/> .\n<> dc:title "Updated safely" .\n',
            content_type="text/turtle",
            if_match=created.etag,
        )

        # 5. Conditional delete with If-Match
        await client.delete(note_url, if_match=updated.etag)


if __name__ == "__main__":
    asyncio.run(main())
```

## `pod_id` Format Rules

Wolin Pod handles (`{pod_id}.wolin.id` and `https://pod.wolin.id/pods/{pod_id}/`) enforce strict DNS-label & anti-spoofing rules:

- Length: `3..32` characters
- Characters: lowercase ASCII `[a-z0-9-]`, starting and ending with `[a-z0-9]`
- No consecutive hyphens (`--`)
- Reserved system/infrastructure handles (e.g., `auth`, `pod`, `pods`, `api`, `admin`, `wolin`, `www`) are rejected

```python
from wolin_id import InvalidPodIdError, is_valid_pod_id, validate_pod_id

assert is_valid_pod_id("alice-01") is True
assert is_valid_pod_id("ab") is False          # < 3 chars
assert is_valid_pod_id("alice--dev") is False  # consecutive '--'
assert is_valid_pod_id("auth") is False        # reserved system handle

validated = validate_pod_id("alice-01")  # raises InvalidPodIdError on violation
```

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
ruff check src tests
mypy src
```

## License

Dual-licensed under either of:

- **Apache License, Version 2.0** ([`LICENSE-APACHE`](./LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- **MIT License** ([`LICENSE-MIT`](./LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Copyright © 2026 [Entropy Paradox, Inc.](https://wolin.id) and Wolin Contributors.
