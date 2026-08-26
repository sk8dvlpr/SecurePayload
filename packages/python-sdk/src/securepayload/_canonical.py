"""Kanonisasi wire-format SecurePayload — port semantik persis dari
``src/Protocol/{Canonical,Digest,Messages,Aead,Hkdf}.php``.

Fungsi-fungsi di sini adalah sumber kebenaran byte-exactness SDK Python
terhadap protokol v3. Setiap perubahan wajib tetap lolos fixture
``docs/fixtures/v3/primitive/*.json`` (hex/b64 compare).
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Optional, Union
from urllib.parse import quote

from ._crypto import b64_decode_strict, b64_encode, hkdf_sha256

BytesLike = Union[bytes, str]

# Panjang nonce XChaCha20-Poly1305 (SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES).
_XCHACHA_NONCE_LEN = 24


def normalize_path(path: str) -> str:
    """Normalisasi path URL: selalu berawalan '/', tanpa '/' akhir (kecuali root).

    Port Canonical::normalizePath.
    """
    if path == "":
        return "/"
    prefixed = "/" + path.lstrip("/")
    if len(prefixed) > 1:
        prefixed = prefixed.rstrip("/")
    return prefixed


def _php_str(value: Any) -> str:
    """Konversi skalar ke string ala PHP (string cast): true→'1', false/null→''."""
    if value is True:
        return "1"
    if value is False or value is None:
        return ""
    return str(value)


def canonical_query(q: Mapping[str, Any]) -> str:
    """Kanonisasi query string: kunci urut ASC, encode RFC 3986.

    Port Canonical::canonicalQuery. Array digabung koma. ``quote(..., safe='')``
    identik dengan ``rawurlencode`` PHP — BUKAN encodeURIComponent JS
    (yang membiarkan ``!'()*`` tanpa escape).
    """
    if not q:
        return ""
    parts = []
    for key in sorted(q.keys()):
        value = q[key]
        if isinstance(value, (list, tuple)):
            joined = ",".join(_php_str(v) for v in value)
        else:
            joined = _php_str(value)
        parts.append(quote(str(key), safe="") + "=" + quote(joined, safe=""))
    return "&".join(parts)


def body_digest_b64(body: BytesLike) -> str:
    """SHA-256 body dalam base64 standar (Digest::bodyDigestB64)."""
    return b64_encode(hashlib.sha256(body.encode("utf-8") if isinstance(body, str) else body).digest())


def hmac_message(
    ver: str,
    client_id: str,
    key_id: str,
    ts: str,
    nonce_b64: str,
    method: str,
    path: str,
    q_str: str,
    digest_b64: str,
) -> str:
    """Pesan kanonik tanda tangan HMAC/Ed25519 request (Messages::hmacMessage)."""
    return "\n".join([
        "v" + ver,
        "client=" + client_id,
        "key=" + key_id,
        "ts=" + ts,
        "nonce=" + nonce_b64,
        "m=" + method,
        "p=" + path,
        "q=" + q_str,
        "bd=sha256:" + digest_b64,
        "",  # newline akhir
    ])


def resp_message(ver: str, req_nonce_b64: str, resp_ts: str, resp_nonce_b64: str, digest_b64: str) -> str:
    """Pesan kanonik response, terikat ke nonce request asal (Messages::respMessage)."""
    return "\n".join([
        "resp-v" + ver,
        "req-nonce=" + req_nonce_b64,
        "resp-ts=" + resp_ts,
        "resp-nonce=" + resp_nonce_b64,
        "bd=sha256:" + digest_b64,
        "",
    ])


def build_request_aead_aad(version: str, ts: str, bound_headers: Optional[Mapping[str, str]] = None) -> str:
    """AAD request AEAD: versi, timestamp, lalu header terikat terurut nama (Aead::buildRequestAeadAad).

    Nama header harus sudah lowercase + terurut (lihat ``collect_bound_headers``).
    """
    parts = ["v" + version, "ts=" + ts]
    bound = dict(bound_headers or {})
    for name in sorted(bound):
        parts.append("h:" + name + "=" + bound[name])
    return "\n".join(parts)


def build_response_aead_aad(version: str, req_nonce_b64: str, resp_ts: str) -> str:
    """AAD response AEAD (Aead::buildResponseAeadAad)."""
    return f"resp-v{version}|req={req_nonce_b64}|ts={resp_ts}"


def aead_nonce_from(nonce_b64: str, method: str, path: str, q_str: str) -> bytes:
    """Turunkan nonce AEAD 24-byte terikat konteks request (Aead::aeadNonceFrom).

    msg = METHOD\\npath\\nqStr\\nseed(binary); sha256 → potong 24 byte.
    Seed gagal decode → 16 zero byte (fallback identik PHP).
    """
    seed = b64_decode_strict(nonce_b64) or b"\x00" * 16
    msg = "\n".join([method.upper(), normalize_path(path), q_str]).encode("utf-8")
    return hashlib.sha256(msg + b"\n" + seed).digest()[:_XCHACHA_NONCE_LEN]


def resp_aead_nonce_from(resp_nonce_b64: str, req_nonce_b64: str) -> bytes:
    """Nonce AEAD response, binding dua arah resp-nonce ↔ req-nonce (Aead::respAeadNonceFrom)."""
    seed = b64_decode_strict(resp_nonce_b64) or b"\x00" * 16
    msg = ("response\n" + req_nonce_b64).encode("utf-8")
    return hashlib.sha256(msg + b"\n" + seed).digest()[:_XCHACHA_NONCE_LEN]


def derive_subkey(master: bytes, purpose: str, version: str, enabled: bool, length: int = 32) -> bytes:
    """Subkey HKDF label ``purpose|v{version}`` bila aktif; no-op bila nonaktif.

    Mirror SecurePayloadConfig::deriveSubkey + Hkdf::deriveKey.
    """
    if not enabled:
        return master
    if len(master) == 0:
        raise ValueError("Master key kosong untuk derivasi HKDF")
    return hkdf_sha256(master, purpose + "|v" + version, length)


def collect_bound_headers(headers: Mapping[str, str], bind_names: "list[str]") -> dict:
    """Nilai header terikat AAD: nama lowercase, terurut, missing → ''.

    Mirror SecurePayloadConfig::collectBoundHeaders (ksort SORT_STRING).
    """
    norm = {str(k).lower(): str(v) for k, v in headers.items()}
    out = {name.lower(): norm.get(name.lower(), "") for name in bind_names}
    return dict(sorted(out.items()))
