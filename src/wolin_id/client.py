"""Async HTTP client for Wolin (月印千江) Solid Pods (Solid-OIDC + RFC 9449 DPoP + LDP CRUD)."""

from __future__ import annotations

import json
import re
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from wolin_id.dpop import DpopSigner
from wolin_id.models import (
    DEFAULT_AUTH_URL,
    DEFAULT_POD_URL,
    LdpResource,
    ProvisionPodResult,
    WebIdProfile,
    WolinAuthError,
    WolinHttpError,
    WolinNotFoundError,
    WolinPreconditionError,
    WriteResult,
    validate_pod_id,
)
from wolin_id.webid import parse_webid_turtle

_LINK_PART_RE = re.compile(r"<([^>]+)>\s*;\s*(.*)")
_REL_PARAM_RE = re.compile(r'rel\s*=\s*(?:"([^"]+)"|([^\s;]+))', re.IGNORECASE)
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_SAFE_REDIRECTS = 5


def _parse_link_headers(raw_links: list[str]) -> tuple[tuple[str, ...], str | None]:
    """Extract `rel="type"` IRIs and `rel="acl"` URL from HTTP `Link` headers."""
    link_types: list[str] = []
    acl_url: str | None = None
    for header_val in raw_links:
        for item in _split_link_values(header_val):
            match = _LINK_PART_RE.match(item.strip())
            if not match:
                continue
            target_uri, params = match.group(1), match.group(2)
            rel_match = _REL_PARAM_RE.search(params)
            if not rel_match:
                continue
            rels = (rel_match.group(1) or rel_match.group(2) or "").split()
            if "type" in rels and target_uri not in link_types:
                link_types.append(target_uri)
            if "acl" in rels and acl_url is None:
                acl_url = target_uri
    return tuple(link_types), acl_url


def _split_link_values(header_val: str) -> list[str]:
    """Split comma-separated RFC 8288 `Link` header values while respecting `<...>` and quotes."""
    parts: list[str] = []
    start = 0
    in_angle = False
    in_quote = False
    for idx, ch in enumerate(header_val):
        if ch == "<" and not in_quote:
            in_angle = True
        elif ch == ">" and not in_quote:
            in_angle = False
        elif ch == '"' and not in_angle:
            in_quote = not in_quote
        elif ch == "," and not in_angle and not in_quote:
            parts.append(header_val[start:idx])
            start = idx + 1
    parts.append(header_val[start:])
    return parts


def _origin_key(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    default_port = 80 if scheme == "http" else (443 if scheme == "https" else None)
    host_fmt = f"[{host}]" if ":" in host else host
    if port is not None and port != default_port:
        return f"{scheme}://{host_fmt}:{port}"
    return f"{scheme}://{host_fmt}"


def _validate_redirect_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise WolinHttpError(
            f"Unsupported or malformed redirect target URL '{url}'",
            status_code=302,
            url=url,
        )
    if parts.username is not None or parts.password is not None:
        raise WolinHttpError(
            "Redirect target URL must not include userinfo credentials",
            status_code=302,
            url=url,
        )
    return url


class WolinClient:
    """Async Solid LDP & Wolin (月印千江) Pod Cloud client with native RFC 9449 DPoP."""

    DEFAULT_AUTH_URL: str = DEFAULT_AUTH_URL
    DEFAULT_POD_URL: str = DEFAULT_POD_URL

    def __init__(
        self,
        base_url: str | None = None,
        *,
        access_token: str | None = None,
        dpop_signer: DpopSigner | None = None,
        auth_scheme: Literal["DPoP", "Bearer"] = "DPoP",
        timeout: float = 15.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.access_token = access_token
        self.auth_scheme: Literal["DPoP", "Bearer"] = auth_scheme
        if auth_scheme == "DPoP" and access_token and dpop_signer is None:
            self.dpop_signer: DpopSigner | None = DpopSigner.generate()
        else:
            self.dpop_signer = dpop_signer

        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        self._dpop_nonces: dict[str, str] = {}

    async def __aenter__(self) -> WolinClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying `httpx.AsyncClient` if owned by this `WolinClient`."""
        if self._owns_client:
            await self._client.aclose()

    def resolve_url(self, url_or_path: str) -> str:
        """Resolve an absolute `http(s)://` URL or a Pod-relative path against `base_url`."""
        trimmed = url_or_path.strip()
        if not trimmed:
            raise ValueError("Resource URL or path must not be empty")
        if trimmed.startswith(("http://", "https://")):
            return trimmed
        if not self.base_url:
            raise ValueError(
                f"Cannot resolve relative path '{trimmed}' without WolinClient(base_url=...)"
            )
        rel = trimmed if trimmed.startswith("/") else f"/{trimmed}"
        return f"{self.base_url}{rel}"

    def _build_auth_headers(self, method: str, target_url: str) -> dict[str, str]:
        if not self.access_token:
            return {}
        if self.auth_scheme == "Bearer":
            return {"Authorization": f"Bearer {self.access_token}"}
        if self.dpop_signer is None:
            self.dpop_signer = DpopSigner.generate()
        nonce = self._dpop_nonces.get(_origin_key(target_url))
        return self.dpop_signer.build_headers(
            method,
            target_url,
            self.access_token,
            nonce=nonce,
        )

    async def _send(
        self,
        method: str,
        target_url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        include_auth: bool = True,
    ) -> httpx.Response:
        req_headers = dict(headers) if headers else {}
        if include_auth:
            req_headers.update(self._build_auth_headers(method, target_url))

        resp = await self._client.request(
            method,
            target_url,
            headers=req_headers,
            content=content,
            follow_redirects=False,
        )

        origin = _origin_key(target_url)
        new_nonce = resp.headers.get("dpop-nonce")
        prev_nonce = self._dpop_nonces.get(origin)
        if new_nonce:
            self._dpop_nonces[origin] = new_nonce

        # RFC 9449 §8 automatic single retry when resource server issues a fresh DPoP-Nonce on 401
        if (
            include_auth
            and resp.status_code == 401
            and self.access_token
            and self.auth_scheme == "DPoP"
            and new_nonce
            and new_nonce != prev_nonce
        ):
            retry_headers = dict(headers) if headers else {}
            retry_headers.update(self._build_auth_headers(method, target_url))
            resp = await self._client.request(
                method,
                target_url,
                headers=retry_headers,
                content=content,
                follow_redirects=False,
            )
            latest_nonce = resp.headers.get("dpop-nonce")
            if latest_nonce:
                self._dpop_nonces[origin] = latest_nonce

        return resp

    async def _send_safe_read(
        self,
        method: Literal["GET", "HEAD"],
        target_url: str,
        *,
        headers: dict[str, str] | None = None,
        include_auth: bool = True,
        follow_redirects: bool = True,
    ) -> tuple[httpx.Response, httpx.Headers | None]:
        """Execute a `GET` or `HEAD` request with safe `302` signed-asset redirect handling.

        When Wolin Engine offloads large `NonRDFSource` blobs via `302 Found` to a short-lived
        HMAC-signed Edge/R2/CDN URL, cross-origin redirects are followed **without**
        `Authorization` or `DPoP` headers so credentials are never leaked to external hosts.
        """
        resp = await self._send(method, target_url, headers=headers, include_auth=include_auth)
        if not follow_redirects or resp.status_code not in _REDIRECT_STATUS_CODES:
            return resp, None

        pod_redirect_headers = resp.headers
        initial_origin = _origin_key(target_url)
        current_url = target_url

        for _ in range(_MAX_SAFE_REDIRECTS):
            location = resp.headers.get("location")
            if not location:
                return resp, pod_redirect_headers

            next_url = _validate_redirect_url(urljoin(current_url, location.strip()))
            same_origin = _origin_key(next_url) == initial_origin

            redirect_headers: dict[str, str] = {}
            if headers and "Accept" in headers:
                redirect_headers["Accept"] = headers["Accept"]

            resp = await self._send(
                method,
                next_url,
                headers=redirect_headers,
                include_auth=(include_auth and same_origin),
            )
            current_url = next_url
            if resp.status_code not in _REDIRECT_STATUS_CODES:
                return resp, pod_redirect_headers

        raise WolinHttpError(
            f"Exceeded maximum redirect hops ({_MAX_SAFE_REDIRECTS}) while reading {target_url}",
            status_code=resp.status_code,
            url=target_url,
            headers=dict(resp.headers),
            body=resp.content,
        )

    def _raise_for_ldp_error(self, resp: httpx.Response, target_url: str) -> None:
        status = resp.status_code
        if 200 <= status < 300:
            return
        detail = resp.text.strip() or f"HTTP {status}"
        msg = f"Solid LDP request failed ({status}) for {target_url}: {detail}"
        hdrs = dict(resp.headers)
        if status in (401, 403):
            raise WolinAuthError(
                msg,
                status_code=status,
                url=target_url,
                headers=hdrs,
                body=resp.content,
            )
        if status == 404:
            raise WolinNotFoundError(
                msg,
                status_code=status,
                url=target_url,
                headers=hdrs,
                body=resp.content,
            )
        if status in (409, 412):
            raise WolinPreconditionError(
                msg,
                status_code=status,
                url=target_url,
                headers=hdrs,
                body=resp.content,
            )
        raise WolinHttpError(
            msg,
            status_code=status,
            url=target_url,
            headers=hdrs,
            body=resp.content,
        )

    def _to_ldp_resource(
        self,
        resp: httpx.Response,
        target_url: str,
        *,
        fallback_headers: httpx.Headers | None = None,
    ) -> LdpResource:
        raw_links = resp.headers.get_list("link")
        if not raw_links and fallback_headers is not None:
            raw_links = fallback_headers.get_list("link")
        link_types, acl_rel = _parse_link_values_from_headers(raw_links)
        acl_url = urljoin(target_url, acl_rel) if acl_rel else None
        content_type = resp.headers.get("content-type", "application/octet-stream")
        media_type = content_type.split(";", 1)[0].strip()
        etag = resp.headers.get("etag") or (
            fallback_headers.get("etag") if fallback_headers is not None else None
        )
        wac_allow = resp.headers.get("wac-allow") or (
            fallback_headers.get("wac-allow") if fallback_headers is not None else None
        )
        return LdpResource(
            url=target_url,
            status_code=resp.status_code,
            content=resp.content,
            content_type=media_type,
            etag=etag,
            wac_allow=wac_allow,
            acl_url=acl_url,
            link_types=link_types,
            headers=dict(resp.headers),
        )

    async def fetch_webid_profile(
        self,
        webid: str,
        *,
        authenticated: bool = False,
    ) -> WebIdProfile:
        """Dereference a W3C WebID URI over HTTP(S) and parse its Turtle profile document."""
        trimmed_webid = webid.strip()
        if not trimmed_webid:
            raise ValueError("WebID URI must not be empty")
        doc_url, _ = urldefrag(trimmed_webid)
        if not doc_url.startswith(("http://", "https://")):
            raise ValueError(f"WebID must be an HTTP(S) URI, got '{trimmed_webid}'")

        resp, _ = await self._send_safe_read(
            "GET",
            doc_url,
            headers={"Accept": "text/turtle, application/n-triples;q=0.9"},
            include_auth=authenticated,
        )
        self._raise_for_ldp_error(resp, doc_url)
        return parse_webid_turtle(resp.content, trimmed_webid, base_iri=doc_url)

    async def discover_storage(self, webid: str, *, authenticated: bool = False) -> str:
        """Dereference `webid` and return its primary `pim:storage` Solid Pod root URL."""
        profile = await self.fetch_webid_profile(webid, authenticated=authenticated)
        if profile.primary_storage is None:
            raise WolinNotFoundError(
                f"WebID '{webid}' profile does not advertise a pim:storage root",
                status_code=404,
                url=webid,
            )
        return profile.primary_storage

    async def head(self, url_or_path: str) -> LdpResource:
        """Issue an LDP `HEAD` request to inspect `ETag`, `Link` types, and `WAC-Allow`."""
        target_url = self.resolve_url(url_or_path)
        resp, fallback_hdrs = await self._send_safe_read("HEAD", target_url)
        self._raise_for_ldp_error(resp, target_url)
        return self._to_ldp_resource(resp, target_url, fallback_headers=fallback_hdrs)

    async def get(
        self,
        url_or_path: str,
        *,
        accept: str | None = None,
        if_none_match: str | None = None,
        if_match: str | None = None,
        follow_redirects: bool = True,
    ) -> LdpResource:
        """Fetch a Solid LDP resource or container with conditional `ETag` & safe `302` offload."""
        target_url = self.resolve_url(url_or_path)
        headers: dict[str, str] = {}
        if accept:
            headers["Accept"] = accept
        if if_none_match:
            headers["If-None-Match"] = if_none_match
        if if_match:
            headers["If-Match"] = if_match

        resp, fallback_hdrs = await self._send_safe_read(
            "GET",
            target_url,
            headers=headers,
            follow_redirects=follow_redirects,
        )
        if resp.status_code == 304:
            return self._to_ldp_resource(resp, target_url, fallback_headers=fallback_hdrs)
        self._raise_for_ldp_error(resp, target_url)
        return self._to_ldp_resource(resp, target_url, fallback_headers=fallback_hdrs)

    async def put(
        self,
        url_or_path: str,
        content: bytes | str,
        *,
        content_type: str = "text/turtle",
        if_match: str | None = None,
        if_none_match: str | None = None,
        create_only: bool = False,
        link_type: str | None = None,
    ) -> WriteResult:
        """Create or replace a Solid LDP resource with ETag preconditions."""
        target_url = self.resolve_url(url_or_path)
        payload = content.encode("utf-8") if isinstance(content, str) else content

        headers: dict[str, str] = {"Content-Type": content_type}
        if if_match:
            headers["If-Match"] = if_match
        if create_only:
            headers["If-None-Match"] = "*"
        elif if_none_match:
            headers["If-None-Match"] = if_none_match
        if link_type:
            headers["Link"] = f'<{link_type}>; rel="type"'

        resp = await self._send("PUT", target_url, headers=headers, content=payload)
        self._raise_for_ldp_error(resp, target_url)
        return WriteResult(
            url=target_url,
            status_code=resp.status_code,
            created=resp.status_code == 201,
            etag=resp.headers.get("etag"),
            location=resp.headers.get("location"),
        )

    async def patch_sparql(
        self,
        url_or_path: str,
        sparql_update: str,
        *,
        if_match: str | None = None,
    ) -> WriteResult:
        """Mutate an RDF resource via Solid `PATCH` (`application/sparql-update`)."""
        target_url = self.resolve_url(url_or_path)
        headers: dict[str, str] = {"Content-Type": "application/sparql-update"}
        if if_match:
            headers["If-Match"] = if_match

        resp = await self._send(
            "PATCH",
            target_url,
            headers=headers,
            content=sparql_update.encode("utf-8"),
        )
        self._raise_for_ldp_error(resp, target_url)
        return WriteResult(
            url=target_url,
            status_code=resp.status_code,
            created=resp.status_code == 201,
            etag=resp.headers.get("etag"),
            location=resp.headers.get("location"),
        )

    async def delete(
        self,
        url_or_path: str,
        *,
        if_match: str | None = None,
    ) -> None:
        """Delete a Solid LDP resource, optionally guarded by `If-Match` optimistic locking."""
        target_url = self.resolve_url(url_or_path)
        headers: dict[str, str] = {}
        if if_match:
            headers["If-Match"] = if_match

        resp = await self._send("DELETE", target_url, headers=headers)
        self._raise_for_ldp_error(resp, target_url)

    async def provision_pod(
        self,
        pod_id: str,
        *,
        owner_webid: str | None = None,
        display_name: str | None = None,
        oidc_issuer: str | None = None,
    ) -> ProvisionPodResult:
        """Provision a zero-config Wolin Sovereign Pod (`POST /api/pods`)."""
        validated_pod_id = validate_pod_id(pod_id)
        target_url = self.resolve_url("/api/pods")
        body_obj: dict[str, Any] = {"pod_id": validated_pod_id}
        if owner_webid is not None:
            body_obj["owner_webid"] = owner_webid
        if display_name is not None:
            body_obj["display_name"] = display_name
        if oidc_issuer is not None:
            body_obj["oidc_issuer"] = oidc_issuer

        resp = await self._send(
            "POST",
            target_url,
            headers={"Content-Type": "application/json"},
            content=json.dumps(body_obj).encode("utf-8"),
        )
        self._raise_for_ldp_error(resp, target_url)
        data = resp.json()
        return ProvisionPodResult(
            pod_id=str(data["pod_id"]),
            pod_url=str(data["pod_url"]),
            subdomain_url=str(data["subdomain_url"]),
            webid=str(data["webid"]),
            owner_webid=str(data["owner_webid"]),
            display_name=str(data["display_name"]),
            storage=str(data["storage"]),
            inbox=str(data["inbox"]),
            seeded_resources=tuple(str(item) for item in data.get("seeded_resources", ())),
        )


def _parse_link_values_from_headers(
    raw_links: list[str],
) -> tuple[tuple[str, ...], str | None]:
    return _parse_link_headers(raw_links)
