"""RFC 9449 OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) ES256 signer and verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from wolin_id.models import DpopProofClaims, DpopValidationError, PublicJwk

_FORBIDDEN_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_P256_COORD_LEN = 32
_ES256_RAW_SIG_LEN = 64


def b64url_encode(data: bytes) -> str:
    """Encode raw bytes using unpadded RFC 7515 Base64URL."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """Strictly decode an unpadded RFC 7515 Base64URL string."""
    if not segment or any(ch in segment for ch in ("=", "+", "/", " ", "\t", "\r", "\n")):
        raise DpopValidationError("Invalid unpadded Base64URL segment")
    rem = len(segment) % 4
    if rem == 1:
        raise DpopValidationError("Malformed Base64URL segment length")
    padded = segment + ("=" * ((4 - rem) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise DpopValidationError(f"Base64URL decoding failed: {exc}") from exc
    if b64url_encode(raw) != segment:
        raise DpopValidationError("Non-canonical Base64URL padding bits rejected")
    return raw


def sha256_base64url(data: bytes) -> str:
    """Compute SHA-256 digest and encode as unpadded Base64URL."""
    return b64url_encode(hashlib.sha256(data).digest())


def compute_access_token_hash(access_token: str) -> str:
    """Compute RFC 9449 §4.2 `ath` claim (Base64URL-encoded SHA-256 of ASCII access token)."""
    if not access_token or not access_token.isascii():
        raise DpopValidationError("Access token for DPoP 'ath' must be non-empty ASCII")
    return sha256_base64url(access_token.encode("ascii"))


def compute_jwk_thumbprint(jwk: PublicJwk | Mapping[str, Any]) -> str:
    """Compute RFC 7638 §3.1 canonical SHA-256 JWK thumbprint (`jkt`) for EC P-256 keys."""
    raw_map: Mapping[str, Any] = jwk.to_dict() if isinstance(jwk, PublicJwk) else jwk
    for priv_field in _FORBIDDEN_PRIVATE_JWK_FIELDS:
        if priv_field in raw_map:
            raise DpopValidationError(
                f"Public JWK must not contain private parameter '{priv_field}'"
            )

    kty = raw_map.get("kty")
    crv = raw_map.get("crv")
    x = raw_map.get("x")
    y = raw_map.get("y")
    if kty != "EC" or crv != "P-256" or not isinstance(x, str) or not isinstance(y, str):
        raise DpopValidationError("ES256 JWK thumbprint requires kty='EC', crv='P-256', x, y")

    x_bytes = b64url_decode(x)
    y_bytes = b64url_decode(y)
    if len(x_bytes) != _P256_COORD_LEN or len(y_bytes) != _P256_COORD_LEN:
        raise DpopValidationError("EC P-256 JWK coordinates must be exactly 32 bytes")

    canonical_json = json.dumps(
        {"crv": crv, "kty": "EC", "x": x, "y": y},
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256_base64url(canonical_json.encode("utf-8"))


def normalize_htu(url: str, *, allow_query_or_fragment_input: bool = True) -> str:
    """Normalize an HTTP target URI into an RFC 9449 §4.2 `htu` claim (scheme://authority/path)."""
    if not url or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        raise DpopValidationError("DPoP target URI must not be empty or contain whitespace")
    if not allow_query_or_fragment_input and ("?" in url or "#" in url):
        raise DpopValidationError("DPoP 'htu' claim must not contain query or fragment components")

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise DpopValidationError(f"Unsupported DPoP URI scheme '{parsed.scheme}'")
    if parsed.username is not None or parsed.password is not None:
        raise DpopValidationError("DPoP URI must not include userinfo credentials")
    hostname = parsed.hostname
    if not hostname:
        raise DpopValidationError("DPoP URI is missing host")

    try:
        port = parsed.port
    except ValueError as exc:
        raise DpopValidationError(f"Invalid port in DPoP URI: {exc}") from exc

    host_str = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    default_port = 80 if scheme == "http" else 443
    authority = f"{host_str}:{port}" if port is not None and port != default_port else host_str
    path = parsed.path if parsed.path else "/"
    return f"{scheme}://{authority}{path}"


class DpopSigner:
    """ES256 (ECDSA P-256 + SHA-256) RFC 9449 DPoP proof signer."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise DpopValidationError("DpopSigner requires an NIST P-256 (SECP256R1) private key")
        self._private_key = private_key
        numbers = private_key.public_key().public_numbers()
        self._public_jwk = PublicJwk(
            kty="EC",
            crv="P-256",
            x=b64url_encode(numbers.x.to_bytes(_P256_COORD_LEN, "big")),
            y=b64url_encode(numbers.y.to_bytes(_P256_COORD_LEN, "big")),
        )
        self._jkt = compute_jwk_thumbprint(self._public_jwk)

    @classmethod
    def generate(cls) -> DpopSigner:
        """Generate a fresh ephemeral NIST P-256 keypair for Solid-OIDC DPoP."""
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes | str, password: bytes | None = None) -> DpopSigner:
        """Load an EC P-256 private key from PKCS#8 or SEC1 PEM bytes."""
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        loaded = serialization.load_pem_private_key(pem_bytes, password=password)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise DpopValidationError("PEM does not contain an EllipticCurvePrivateKey")
        return cls(loaded)

    def to_pem(self) -> bytes:
        """Export the private key in unencrypted PKCS#8 PEM format."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_jwk(self) -> PublicJwk:
        """Return the public EC P-256 JWK embedded in DPoP proof headers."""
        return self._public_jwk

    @property
    def jwk_thumbprint(self) -> str:
        """Return the RFC 7638 SHA-256 JWK thumbprint (`jkt`)."""
        return self._jkt

    def sign_proof(
        self,
        htm: str,
        htu: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
        iat: int | None = None,
        jti: str | None = None,
    ) -> str:
        """Create a compact-serialized ES256 `dpop+jwt` proof per RFC 9449."""
        method = htm.strip().upper()
        if not method or any(ord(ch) <= 0x20 for ch in method):
            raise DpopValidationError("HTTP method 'htm' must not be empty")

        normalized_htu = normalize_htu(htu, allow_query_or_fragment_input=True)
        issued_at = int(time.time()) if iat is None else int(iat)
        proof_jti = str(uuid.uuid4()) if jti is None else jti.strip()
        if not proof_jti:
            raise DpopValidationError("DPoP 'jti' must not be empty")

        header = {
            "alg": "ES256",
            "jwk": self._public_jwk.to_dict(),
            "typ": "dpop+jwt",
        }
        payload: dict[str, Any] = {
            "htm": method,
            "htu": normalized_htu,
            "iat": issued_at,
            "jti": proof_jti,
        }
        if access_token is not None and access_token != "":
            payload["ath"] = compute_access_token_hash(access_token)
        if nonce is not None and nonce != "":
            payload["nonce"] = nonce

        header_b64 = b64url_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        payload_b64 = b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        der_signature = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(_P256_COORD_LEN, "big") + s.to_bytes(_P256_COORD_LEN, "big")
        sig_b64 = b64url_encode(raw_signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def build_headers(
        self,
        htm: str,
        htu: str,
        access_token: str | None = None,
        *,
        nonce: str | None = None,
    ) -> dict[str, str]:
        """Build `DPoP` (and `Authorization: DPoP <token>` when present) HTTP headers."""
        proof = self.sign_proof(htm, htu, access_token=access_token, nonce=nonce)
        headers = {"DPoP": proof}
        if access_token:
            headers["Authorization"] = f"DPoP {access_token}"
        return headers


def verify_dpop_es256(
    dpop_jwt: str,
    *,
    expected_htm: str,
    expected_htu: str,
    access_token: str | None = None,
    now: int | None = None,
    max_skew_secs: int = 300,
) -> DpopProofClaims:
    """Verify an ES256 RFC 9449 DPoP proof JWT and return its validated claims."""
    if not dpop_jwt or any(ord(ch) <= 0x20 for ch in dpop_jwt):
        raise DpopValidationError("DPoP JWT must be non-empty and free of whitespace")

    parts = dpop_jwt.split(".")
    if len(parts) != 3 or not all(parts):
        raise DpopValidationError("Invalid compact DPoP JWT structure")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DpopValidationError(f"Malformed DPoP JSON segment: {exc}") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise DpopValidationError("DPoP header and payload must be JSON objects")
    if "crit" in header:
        raise DpopValidationError("Unsupported 'crit' header parameter in DPoP JWT")

    typ = header.get("typ")
    alg = header.get("alg")
    jwk = header.get("jwk")
    if not isinstance(typ, str) or typ.lower() != "dpop+jwt":
        raise DpopValidationError(f"Unexpected DPoP typ '{typ}': expected 'dpop+jwt'")
    if alg != "ES256":
        raise DpopValidationError(f"Unsupported DPoP alg '{alg}': expected 'ES256'")
    if not isinstance(jwk, dict):
        raise DpopValidationError("DPoP header 'jwk' must be an object")

    jkt = compute_jwk_thumbprint(jwk)
    x_bytes = b64url_decode(jwk["x"])
    y_bytes = b64url_decode(jwk["y"])
    sig_bytes = b64url_decode(sig_b64)
    if len(sig_bytes) != _ES256_RAW_SIG_LEN:
        raise DpopValidationError("ES256 signature must be 64 raw P1363 bytes")

    r = int.from_bytes(sig_bytes[:_P256_COORD_LEN], "big")
    s = int.from_bytes(sig_bytes[_P256_COORD_LEN:], "big")
    der_sig = encode_dss_signature(r, s)
    pub_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x_bytes, "big"),
        int.from_bytes(y_bytes, "big"),
        ec.SECP256R1(),
    ).public_key()

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        pub_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise DpopValidationError("DPoP ES256 cryptographic signature verification failed") from exc

    jti = payload.get("jti")
    htm = payload.get("htm")
    htu = payload.get("htu")
    iat = payload.get("iat")
    if not isinstance(jti, str) or not jti.strip():
        raise DpopValidationError("Missing or empty DPoP 'jti' claim")
    if not isinstance(htm, str) or htm.upper() != expected_htm.strip().upper():
        raise DpopValidationError(f"DPoP 'htm' mismatch: expected '{expected_htm}', got '{htm}'")
    if not isinstance(htu, str):
        raise DpopValidationError("Missing DPoP 'htu' claim")

    norm_proof_htu = normalize_htu(htu, allow_query_or_fragment_input=False)
    norm_expected_htu = normalize_htu(expected_htu, allow_query_or_fragment_input=True)
    if norm_proof_htu != norm_expected_htu:
        raise DpopValidationError(
            f"DPoP 'htu' mismatch: expected '{norm_expected_htu}', got '{norm_proof_htu}'"
        )

    if not isinstance(iat, int) or isinstance(iat, bool):
        raise DpopValidationError("Missing or non-integer DPoP 'iat' claim")

    now_ts = int(time.time()) if now is None else int(now)
    skew = max(1, int(max_skew_secs))
    if iat < now_ts - skew or iat > now_ts + skew:
        raise DpopValidationError("DPoP 'iat' timestamp outside freshness window")

    ath = payload.get("ath")
    if ath is not None and not isinstance(ath, str):
        raise DpopValidationError("DPoP 'ath' claim must be a string")

    if access_token:
        expected_ath = compute_access_token_hash(access_token)
        if ath != expected_ath:
            raise DpopValidationError("DPoP 'ath' claim does not match access token")
    elif ath == "":
        raise DpopValidationError("DPoP 'ath' claim must not be empty")

    nonce = payload.get("nonce")
    if nonce is not None and not isinstance(nonce, str):
        raise DpopValidationError("DPoP 'nonce' claim must be a string")

    return DpopProofClaims(
        jti=jti,
        htm=htm,
        htu=htu,
        iat=iat,
        jkt=jkt,
        ath=ath,
        nonce=nonce,
    )
