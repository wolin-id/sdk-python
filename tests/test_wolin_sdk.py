"""Comprehensive unit and async integration tests for the Wolin Python SDK (`wolin-id`)."""

from __future__ import annotations

import hashlib
import json
import unittest
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import ec

from wolin_id import (
    LDP_RDF_SOURCE_IRI,
    LDP_RESOURCE_IRI,
    DpopSigner,
    DpopValidationError,
    TurtleParseError,
    WolinAuthError,
    WolinClient,
    WolinNotFoundError,
    WolinPreconditionError,
    b64url_decode,
    b64url_encode,
    compute_access_token_hash,
    compute_jwk_thumbprint,
    normalize_htu,
    parse_turtle_triples,
    parse_webid_turtle,
    verify_dpop_es256,
)


def _etag_for(payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()[:32]
    return f'"{digest}"'


class TestDpopCrypto(unittest.TestCase):
    """Tests for RFC 9449 ES256 DPoP signing, JWK thumbprints, and verification."""

    def test_generate_pem_roundtrip_and_jwk_thumbprint(self) -> None:
        signer = DpopSigner.generate()
        jwk = signer.public_jwk.to_dict()
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "P-256")
        self.assertNotIn("d", jwk)
        self.assertEqual(len(b64url_decode(jwk["x"])), 32)
        self.assertEqual(len(b64url_decode(jwk["y"])), 32)

        # Canonical RFC 7638 thumbprint matches manual lexicographic JSON SHA-256
        canonical = json.dumps(
            {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected_jkt = b64url_encode(hashlib.sha256(canonical).digest())
        self.assertEqual(signer.jwk_thumbprint, expected_jkt)

        # PEM round-trip preserves public JWK and thumbprint
        restored = DpopSigner.from_pem(signer.to_pem())
        self.assertEqual(restored.public_jwk, signer.public_jwk)
        self.assertEqual(restored.jwk_thumbprint, signer.jwk_thumbprint)

    def test_rejects_non_p256_curve_and_private_jwk_fields(self) -> None:
        p384_key = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaises(DpopValidationError):
            DpopSigner(p384_key)

        signer = DpopSigner.generate()
        bad_jwk = dict(signer.public_jwk.to_dict(), d="secret")
        with self.assertRaises(DpopValidationError):
            compute_jwk_thumbprint(bad_jwk)

    def test_sign_and_verify_es256_with_ath_and_query_stripping(self) -> None:
        signer = DpopSigner.generate()
        token = "mock-solid-oidc-token"
        proof = signer.sign_proof(
            "get",
            "HTTPS://Alice.Wolin.Cloud:443/private/notes.ttl?draft=1#top",
            access_token=token,
            nonce="srv-nonce-42",
            iat=1_760_000_000,
            jti="proof-1",
        )

        # Verify raw IEEE P1363 64-byte signature format
        _, _, sig_seg = proof.split(".")
        self.assertEqual(len(b64url_decode(sig_seg)), 64)

        claims = verify_dpop_es256(
            proof,
            expected_htm="GET",
            expected_htu="https://alice.wolin.cloud/private/notes.ttl",
            access_token=token,
            now=1_760_000_010,
        )
        self.assertEqual(claims.jti, "proof-1")
        self.assertEqual(claims.htm, "GET")
        self.assertEqual(claims.htu, "https://alice.wolin.cloud/private/notes.ttl")
        self.assertEqual(claims.jkt, signer.jwk_thumbprint)
        self.assertEqual(claims.ath, compute_access_token_hash(token))
        self.assertEqual(claims.nonce, "srv-nonce-42")

        # Mismatched HTTP method, URI, timestamp, or access token must fail closed
        with self.assertRaises(DpopValidationError):
            verify_dpop_es256(
                proof,
                expected_htm="PUT",
                expected_htu="https://alice.wolin.cloud/private/notes.ttl",
                access_token=token,
                now=1_760_000_010,
            )

        with self.assertRaises(DpopValidationError):
            verify_dpop_es256(
                proof,
                expected_htm="GET",
                expected_htu="https://alice.wolin.cloud/private/other.ttl",
                access_token=token,
                now=1_760_000_010,
            )

        with self.assertRaises(DpopValidationError):
            verify_dpop_es256(
                proof,
                expected_htm="GET",
                expected_htu="https://alice.wolin.cloud/private/notes.ttl",
                access_token="wrong-token",
                now=1_760_000_010,
            )

        with self.assertRaises(DpopValidationError):
            verify_dpop_es256(
                proof,
                expected_htm="GET",
                expected_htu="https://alice.wolin.cloud/private/notes.ttl",
                access_token=token,
                now=1_760_001_000,
                max_skew_secs=60,
            )

    def test_htu_normalization_rules(self) -> None:
        self.assertEqual(
            normalize_htu("http://Example.COM:80/pods/alice/?x=1#me"),
            "http://example.com/pods/alice/",
        )
        self.assertEqual(
            normalize_htu("https://pod.wolin.cloud:8443/pods/alice"),
            "https://pod.wolin.cloud:8443/pods/alice",
        )
        with self.assertRaises(DpopValidationError):
            normalize_htu("https://pod.wolin.cloud/a?b=1", allow_query_or_fragment_input=False)
        with self.assertRaises(DpopValidationError):
            normalize_htu("ftp://pod.wolin.cloud/a")


class TestWebIdTurtleParser(unittest.TestCase):
    """Tests for W3C Turtle parsing and Solid WebID Profile extraction."""

    def test_parse_wolin_webid_profile_card(self) -> None:
        turtle = """
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix solid: <http://www.w3.org/ns/solid/terms#> .
        @prefix pim: <http://www.w3.org/ns/pim/space#> .
        @prefix ldp: <http://www.w3.org/ns/ldp#> .
        @prefix vcard: <http://www.w3.org/2006/vcard/ns#> .

        <> a foaf:PersonalProfileDocument ;
           foaf:maker <#me> ;
           foaf:primaryTopic <#me> .

        <#me>
            a foaf:Person, vcard:Individual ;
            foaf:name "Alice Kim"@en ;
            pim:storage </pods/alice/>, <https://alice.wolin.cloud/> ;
            ldp:inbox </pods/alice/inbox/> ;
            solid:oidcIssuer <https://id.wolin.id> ;
            vcard:hasAddress [
                a vcard:Home ;
                vcard:country-name "Korea"
            ] .
        """
        webid = "https://pod.wolin.cloud/pods/alice/profile/card#me"
        profile = parse_webid_turtle(
            turtle,
            webid,
            base_iri="https://pod.wolin.cloud/pods/alice/profile/card",
        )
        self.assertEqual(profile.webid, webid)
        self.assertEqual(profile.name, "Alice Kim")
        self.assertEqual(
            profile.storages,
            ("https://pod.wolin.cloud/pods/alice/", "https://alice.wolin.cloud/"),
        )
        self.assertEqual(profile.primary_storage, "https://pod.wolin.cloud/pods/alice/")
        self.assertEqual(profile.primary_inbox, "https://pod.wolin.cloud/pods/alice/inbox/")
        self.assertEqual(profile.primary_oidc_issuer, "https://id.wolin.id")

        profile.verify_oidc_issuer("https://id.wolin.id")
        with self.assertRaises(DpopValidationError):
            profile.verify_oidc_issuer("https://evil.example")

    def test_sparql_directives_collections_and_literals(self) -> None:
        turtle = '''
        BASE <https://alice.wolin.cloud/profile/>
        PREFIX : <#>
        PREFIX solid: <http://www.w3.org/ns/solid/terms#>
        PREFIX pim: <http://www.w3.org/ns/pim/space#>
        PREFIX foaf: <http://xmlns.com/foaf/0.1/>

        <card#me> a foaf:Person ;
            foaf:name """Alice
Wolin""" ;
            pim:storage <../> ;
            solid:oidcIssuer <https://login.inrupt.com> ;
            :scores ( 10 20.5 true ) .
        '''
        profile = parse_webid_turtle(
            turtle,
            "https://alice.wolin.cloud/profile/card#me",
        )
        self.assertEqual(profile.name, "Alice\nWolin")
        self.assertEqual(profile.primary_storage, "https://alice.wolin.cloud/")
        self.assertEqual(profile.primary_oidc_issuer, "https://login.inrupt.com")

        triples = parse_turtle_triples(turtle)
        self.assertGreaterEqual(len(triples), 10)

    def test_malformed_turtle_raises_parse_error(self) -> None:
        with self.assertRaises(TurtleParseError):
            parse_webid_turtle("<#me> unknown:pred <https://wolin.id> .", "https://x.test/card#me")

        with self.assertRaises(TurtleParseError):
            parse_webid_turtle('<#me> <http://ex/p> "unterminated .', "https://x.test/card#me")


class _MockSolidPodServer:
    """In-memory Solid LDP + RFC 9449 DPoP verification server for httpx.MockTransport."""

    def __init__(self, expected_token: str, *, require_nonce: str | None = None) -> None:
        self.expected_token = expected_token
        self.require_nonce = require_nonce
        self.seen_jtis: set[str] = set()
        self.resources: dict[str, tuple[bytes, str]] = {
            "/pods/alice/profile/card": (
                (
                    b"@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n"
                    b"@prefix pim: <http://www.w3.org/ns/pim/space#> .\n"
                    b"@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n"
                    b"@prefix ldp: <http://www.w3.org/ns/ldp#> .\n"
                    b"<#me> a foaf:Person ;\n"
                    b'  foaf:name "Alice" ;\n'
                    b"  pim:storage </pods/alice/> ;\n"
                    b"  ldp:inbox </pods/alice/inbox/> ;\n"
                    b"  solid:oidcIssuer <https://id.wolin.id> .\n"
                ),
                "text/turtle",
            )
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        full_url = str(request.url)

        # Public WebID card endpoint (no auth required)
        if path == "/pods/alice/profile/card" and request.method == "GET":
            body, ct = self.resources[path]
            return httpx.Response(
                200,
                content=body,
                headers={
                    "Content-Type": ct,
                    "ETag": _etag_for(body),
                    "Link": f'<{LDP_RESOURCE_IRI}>; rel="type", <card.acl>; rel="acl"',
                },
            )

        # Authenticate DPoP on protected endpoints
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("DPoP "):
            return httpx.Response(401, text="Missing DPoP Authorization")
        token = auth[len("DPoP ") :].strip()
        if token != self.expected_token:
            return httpx.Response(401, text="Invalid access token")

        dpop_jwt = request.headers.get("DPoP", "")
        try:
            claims = verify_dpop_es256(
                dpop_jwt,
                expected_htm=request.method,
                expected_htu=full_url,
                access_token=token,
            )
        except DpopValidationError as exc:
            return httpx.Response(401, text=str(exc))

        if claims.jti in self.seen_jtis:
            return httpx.Response(401, text="DPoP replay detected")
        self.seen_jtis.add(claims.jti)

        if self.require_nonce and claims.nonce != self.require_nonce:
            return httpx.Response(
                401,
                text="use_dpop_nonce",
                headers={
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                    "DPoP-Nonce": self.require_nonce,
                },
            )

        # Pod provisioning endpoint
        if path == "/pods" and request.method == "POST":
            req_json: dict[str, Any] = json.loads(request.content.decode("utf-8"))
            pod_id = req_json["pod_id"]
            return httpx.Response(
                201,
                json={
                    "pod_id": pod_id,
                    "pod_url": f"https://pod.wolin.cloud/pods/{pod_id}/",
                    "subdomain_url": f"https://{pod_id}.wolin.cloud/",
                    "webid": f"https://pod.wolin.cloud/pods/{pod_id}/profile/card#me",
                    "owner_webid": req_json.get(
                        "owner_webid",
                        f"https://pod.wolin.cloud/pods/{pod_id}/profile/card#me",
                    ),
                    "display_name": req_json.get("display_name", pod_id),
                    "storage": f"https://pod.wolin.cloud/pods/{pod_id}/",
                    "inbox": f"https://pod.wolin.cloud/pods/{pod_id}/inbox/",
                    "seeded_resources": [
                        f"/pods/{pod_id}/",
                        f"/pods/{pod_id}/profile/card",
                    ],
                },
            )

        existing = self.resources.get(path)
        current_etag = _etag_for(existing[0]) if existing else None

        if request.method in ("GET", "HEAD"):
            if existing is None:
                return httpx.Response(404, text="Not Found")
            assert current_etag is not None
            inm = request.headers.get("If-None-Match")
            if inm and inm == current_etag:
                return httpx.Response(304, headers={"ETag": current_etag})
            body, ct = existing
            return httpx.Response(
                200,
                content=b"" if request.method == "HEAD" else body,
                headers={
                    "Content-Type": ct,
                    "ETag": current_etag,
                    "WAC-Allow": 'user="read write control",public=""',
                    "Link": (
                        f'<{LDP_RESOURCE_IRI}>; rel="type", '
                        f'<{LDP_RDF_SOURCE_IRI}>; rel="type", '
                        f'<note.ttl.acl>; rel="acl"'
                    ),
                },
            )

        if request.method == "PUT":
            inm = request.headers.get("If-None-Match")
            if inm == "*" and existing is not None:
                return httpx.Response(412, text="Resource already exists")
            if_match = request.headers.get("If-Match")
            if if_match and if_match != current_etag:
                return httpx.Response(412, text="ETag precondition failed")

            ct = request.headers.get("Content-Type", "application/octet-stream")
            new_etag = _etag_for(request.content)
            status = 204 if existing is not None else 201
            self.resources[path] = (request.content, ct)
            headers = {"ETag": new_etag}
            if status == 201:
                headers["Location"] = full_url
            return httpx.Response(status, headers=headers)

        if request.method == "PATCH":
            if request.headers.get("Content-Type") != "application/sparql-update":
                return httpx.Response(415, text="Unsupported Media Type")
            if_match = request.headers.get("If-Match")
            if if_match and if_match != current_etag:
                return httpx.Response(412, text="ETag precondition failed")
            prev_bytes = existing[0] if existing else b""
            merged = prev_bytes + b"\n# patched\n" + request.content
            new_etag = _etag_for(merged)
            self.resources[path] = (merged, "text/turtle")
            return httpx.Response(204 if existing else 201, headers={"ETag": new_etag})

        if request.method == "DELETE":
            if existing is None:
                return httpx.Response(404, text="Not Found")
            if_match = request.headers.get("If-Match")
            if if_match and if_match != current_etag:
                return httpx.Response(412, text="ETag precondition failed")
            del self.resources[path]
            return httpx.Response(204)

        return httpx.Response(405, text="Method Not Allowed")


class TestWolinClientAsync(unittest.IsolatedAsyncioTestCase):
    """End-to-end async tests for WolinClient LDP CRUD, ETag locking, and DPoP-Nonce retry."""

    async def test_webid_discovery_and_ldp_crud_with_etags(self) -> None:
        token = "solid-oidc-access-token-xyz"
        pod_server = _MockSolidPodServer(expected_token=token)
        transport = httpx.MockTransport(pod_server.handle)
        signer = DpopSigner.generate()

        async with httpx.AsyncClient(transport=transport) as http_client:
            async with WolinClient(
                base_url="https://pod.wolin.cloud",
                access_token=token,
                dpop_signer=signer,
                http_client=http_client,
            ) as client:
                # 1. Dereference WebID & discover pim:storage
                webid = "https://pod.wolin.cloud/pods/alice/profile/card#me"
                profile = await client.fetch_webid_profile(webid)
                self.assertEqual(profile.name, "Alice")
                profile.verify_oidc_issuer("https://id.wolin.id")
                storage_root = await client.discover_storage(webid)
                self.assertEqual(storage_root, "https://pod.wolin.cloud/pods/alice/")

                # 2. Create RDF resource with If-None-Match: *
                note_url = f"{storage_root}private/note.ttl"
                v1_turtle = '<#note> <http://purl.org/dc/terms/title> "Initial" .\n'
                write_v1 = await client.put(note_url, v1_turtle, create_only=True)
                self.assertTrue(write_v1.created)
                self.assertEqual(write_v1.status_code, 201)
                self.assertIsNotNone(write_v1.etag)

                # Duplicate create_only fails with 412 WolinPreconditionError
                with self.assertRaises(WolinPreconditionError) as ctx:
                    await client.put(note_url, v1_turtle, create_only=True)
                self.assertEqual(ctx.exception.status_code, 412)

                # 3. GET resource + verify Link, ACL, WAC-Allow, and ETag
                fetched = await client.get(note_url)
                self.assertEqual(fetched.text, v1_turtle)
                self.assertEqual(fetched.etag, write_v1.etag)
                self.assertIn(LDP_RDF_SOURCE_IRI, fetched.link_types)
                self.assertEqual(
                    fetched.acl_url,
                    "https://pod.wolin.cloud/pods/alice/private/note.ttl.acl",
                )
                self.assertIsNotNone(fetched.wac_allow)

                # Conditional GET with matching ETag returns 304 Not Modified
                cached = await client.get(note_url, if_none_match=fetched.etag)
                self.assertTrue(cached.not_modified)
                self.assertEqual(cached.status_code, 304)

                # HEAD returns metadata without payload
                head_res = await client.head(note_url)
                self.assertEqual(head_res.etag, write_v1.etag)
                self.assertEqual(head_res.content, b"")

                # 4. Optimistic concurrency control on PUT
                with self.assertRaises(WolinPreconditionError):
                    await client.put(note_url, "stale write", if_match='"wrong-etag"')

                v2_turtle = '<#note> <http://purl.org/dc/terms/title> "Updated" .\n'
                write_v2 = await client.put(note_url, v2_turtle, if_match=write_v1.etag)
                self.assertFalse(write_v2.created)
                self.assertEqual(write_v2.status_code, 204)
                self.assertNotEqual(write_v2.etag, write_v1.etag)

                # 5. SPARQL-Update PATCH with If-Match
                patched = await client.patch_sparql(
                    note_url,
                    'INSERT DATA { <#note> <http://purl.org/dc/terms/ subject> "Solid" . }',
                    if_match=write_v2.etag,
                )
                self.assertEqual(patched.status_code, 204)
                self.assertIsNotNone(patched.etag)

                # 6. Conditional DELETE with If-Match
                with self.assertRaises(WolinPreconditionError):
                    await client.delete(note_url, if_match=write_v1.etag)

                await client.delete(note_url, if_match=patched.etag)

                with self.assertRaises(WolinNotFoundError):
                    await client.get(note_url)

    async def test_dpop_nonce_challenge_retry_and_pod_provisioning(self) -> None:
        token = "provision-admin-token"
        pod_server = _MockSolidPodServer(
            expected_token=token,
            require_nonce="wolin-nonce-epoch-99",
        )
        transport = httpx.MockTransport(pod_server.handle)

        async with httpx.AsyncClient(transport=transport) as http_client:
            async with WolinClient(
                base_url="https://pod.wolin.cloud",
                access_token=token,
                http_client=http_client,
            ) as client:
                pod = await client.provision_pod("bob", display_name="Bob Sovereign")
                self.assertEqual(pod.pod_id, "bob")
                self.assertEqual(pod.subdomain_url, "https://bob.wolin.cloud/")
                self.assertEqual(len(pod_server.seen_jtis), 2)

                # Second request reuses cached DPoP-Nonce on first attempt (only 1 new jti)
                await client.put("/pods/bob/public/hello.txt", b"hi", content_type="text/plain")
                self.assertEqual(len(pod_server.seen_jtis), 3)

    async def test_unauthorized_raises_wolin_auth_error(self) -> None:
        pod_server = _MockSolidPodServer(expected_token="expected-secret")
        transport = httpx.MockTransport(pod_server.handle)

        async with httpx.AsyncClient(transport=transport) as http_client:
            async with WolinClient(
                base_url="https://pod.wolin.cloud",
                access_token="wrong-secret",
                http_client=http_client,
            ) as client:
                with self.assertRaises(WolinAuthError) as ctx:
                    await client.get("/pods/alice/private/secret.ttl")
                self.assertEqual(ctx.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
