"""Typed domain models, RDF constants, and exceptions for the Wolin Python SDK."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

# W3C Solid / RDF Vocabulary IRIs
RDF_TYPE_IRI = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
SOLID_OIDC_ISSUER_IRI = "http://www.w3.org/ns/solid/terms#oidcIssuer"
PIM_STORAGE_IRI = "http://www.w3.org/ns/pim/space#storage"
PIM_STORAGE_CLASS_IRI = "http://www.w3.org/ns/pim/space#Storage"
LDP_INBOX_IRI = "http://www.w3.org/ns/ldp#inbox"
LDP_RESOURCE_IRI = "http://www.w3.org/ns/ldp#Resource"
LDP_RDF_SOURCE_IRI = "http://www.w3.org/ns/ldp#RDFSource"
LDP_NON_RDF_SOURCE_IRI = "http://www.w3.org/ns/ldp#NonRDFSource"
LDP_CONTAINER_IRI = "http://www.w3.org/ns/ldp#Container"
LDP_BASIC_CONTAINER_IRI = "http://www.w3.org/ns/ldp#BasicContainer"
LDP_CONTAINS_IRI = "http://www.w3.org/ns/ldp#contains"
FOAF_NAME_IRI = "http://xmlns.com/foaf/0.1/name"
VCARD_FN_IRI = "http://www.w3.org/2006/vcard/ns#fn"


class WolinError(Exception):
    """Base exception for all Wolin SDK errors."""


class TurtleParseError(WolinError):
    """Raised when a Solid Turtle / N-Triples RDF document is malformed."""


class DpopValidationError(WolinError):
    """Raised when RFC 9449 DPoP proof generation or verification fails."""


class WolinHttpError(WolinError):
    """Raised when an HTTP request to a Solid Pod or Wolin endpoint fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        url: str,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url
        self.headers: dict[str, str] = dict(headers) if headers is not None else {}
        self.body = body


class WolinAuthError(WolinHttpError):
    """Raised on 401 Unauthorized, 403 Forbidden, or Solid-OIDC trust chain failure."""


class WolinNotFoundError(WolinHttpError):
    """Raised when a requested Solid LDP resource or storage root does not exist (404)."""


class WolinPreconditionError(WolinHttpError):
    """Raised on ETag optimistic concurrency precondition failure (412) or state conflict (409)."""


@dataclass(frozen=True, slots=True)
class PublicJwk:
    """Public EC P-256 JWK representation per RFC 7517 / RFC 7638."""

    kty: str
    crv: str
    x: str
    y: str

    def to_dict(self) -> dict[str, str]:
        """Serialize public key parameters without any private key material."""
        return {
            "crv": self.crv,
            "kty": self.kty,
            "x": self.x,
            "y": self.y,
        }


@dataclass(frozen=True, slots=True)
class DpopProofClaims:
    """Verified RFC 9449 DPoP proof claims and RFC 7638 JWK thumbprint."""

    jti: str
    htm: str
    htu: str
    iat: int
    jkt: str
    ath: str | None = None
    nonce: str | None = None


@dataclass(frozen=True, slots=True)
class WebIdProfile:
    """Parsed W3C Solid WebID Profile metadata."""

    webid: str
    oidc_issuers: tuple[str, ...] = ()
    storages: tuple[str, ...] = ()
    inboxes: tuple[str, ...] = ()
    name: str | None = None

    @property
    def primary_storage(self) -> str | None:
        """Return the first advertised `pim:storage` Pod root IRI, if present."""
        return self.storages[0] if self.storages else None

    @property
    def primary_oidc_issuer(self) -> str | None:
        """Return the first advertised `solid:oidcIssuer` IRI, if present."""
        return self.oidc_issuers[0] if self.oidc_issuers else None

    @property
    def primary_inbox(self) -> str | None:
        """Return the first advertised `ldp:inbox` IRI, if present."""
        return self.inboxes[0] if self.inboxes else None

    def verify_oidc_issuer(self, expected_issuer: str) -> None:
        """Verify Solid-OIDC trust chain `<webid> solid:oidcIssuer <expected_issuer>`."""
        normalized = expected_issuer.strip()
        if not normalized:
            raise DpopValidationError("Solid-OIDC expected_issuer must not be empty")
        if normalized not in self.oidc_issuers:
            raise DpopValidationError(
                f"WebID '{self.webid}' does not authorize solid:oidcIssuer '{normalized}'"
            )


@dataclass(frozen=True, slots=True)
class LdpResource:
    """Solid LDP resource response with ETag, Link types, and WAC metadata."""

    url: str
    status_code: int
    content: bytes
    content_type: str
    etag: str | None = None
    wac_allow: str | None = None
    acl_url: str | None = None
    link_types: tuple[str, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """Decode the resource payload as UTF-8 text."""
        return self.content.decode("utf-8")

    @property
    def not_modified(self) -> bool:
        """Return True when the server returned `304 Not Modified` for `If-None-Match`."""
        return self.status_code == 304


@dataclass(frozen=True, slots=True)
class WriteResult:
    """Result of a Solid LDP mutation (`PUT` or `PATCH`)."""

    url: str
    status_code: int
    created: bool
    etag: str | None = None
    location: str | None = None


@dataclass(frozen=True, slots=True)
class ProvisionPodResult:
    """Response returned by Wolin Pod Cloud zero-config provisioning (`POST /pods`)."""

    pod_id: str
    pod_url: str
    subdomain_url: str
    webid: str
    owner_webid: str
    display_name: str
    storage: str
    inbox: str
    seeded_resources: tuple[str, ...] = ()
