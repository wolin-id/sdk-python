# wolin-id — Official Python SDK for Wolin Solid Pod Engine

[![CI](https://github.com/wolin-id/sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/wolin-id/sdk-python/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-informational.svg)](#license)

`wolin-id` is the official async Python SDK for **[Wolin](https://wolin.id)** — the Sovereign Solid Pod Cloud & Native AI Agent Semantic Mesh built on W3C Solid standards.

It is fully interoperable with Wolin Solid Pod Engine, Inrupt Enterprise Solid Server (ESS), and Community Solid Server (CSS).

## Features

- **RFC 9449 DPoP (`ES256`) Proof-of-Possession**: Ephemeral or PEM-backed NIST P-256 (`SECP256R1`) keypairs, IEEE P1363 compact JWT signatures, RFC 7638 SHA-256 JWK thumbprints (`jkt`), `ath` access-token binding, and automatic `DPoP-Nonce` challenge retry.
- **Solid-OIDC & WebID Discovery**: Built-in zero-dependency W3C Turtle / N-Triples parser for WebID Profile dereferencing (`pim:storage`, `solid:oidcIssuer`, `ldp:inbox`, `foaf:name`) and `solid:oidcIssuer` trust-chain verification.
- **Async Solid LDP CRUD with ETag Concurrency Control**: `GET`, `HEAD`, `PUT`, `PATCH` (`application/sparql-update`), and `DELETE` over `httpx.AsyncClient` with `ETag`, `If-Match`, `If-None-Match`, `Link` (`rel="type"`, `rel="acl"`), and `WAC-Allow` metadata extraction.
- **Zero-Config Wolin Pod Provisioning**: First-class `provision_pod()` helper for `POST /pods` multi-tenant Pod seeding.
- **Strictly Typed**: PEP 561 `py.typed` package targeting Python `>=3.11`.

## Installation

```bash
pip install wolin-id
```

## Quick Start

```python
import asyncio
import os
from wolin_id import DpopSigner, WolinClient


async def main() -> None:
    signer = DpopSigner.generate()

    async with WolinClient(
        base_url="https://pod.wolin.cloud",
        access_token=os.environ["WOLIN_ACCESS_TOKEN"],
        dpop_signer=signer,
    ) as client:
        # 1. Discover Pod storage from a W3C WebID Profile
        profile = await client.fetch_webid_profile(
            "https://alice.wolin.cloud/profile/card#me"
        )
        profile.verify_oidc_issuer("https://id.wolin.id")
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

        # 3. Read resource & ETag
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
