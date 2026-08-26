"""Client-side SecurePayload: build request aman + verifikasi response.

Port semantik persis dari:
- ``src/Client/RequestBuilder.php``     → build_headers_and_body()
- ``src/Response/ResponseVerifier.php`` → verify_response() / verify_response_or_throw()

Invarian keamanan yang dipertahankan:
- HMAC menandatangani PLAINTEXT pada mode ``both`` (bukan ciphertext).
- Nonce AEAD diturunkan deterministik dari konteks request (anti nonce-reuse).
- signAlg response mengikuti config client (anti-downgrade).
- Semua perbandingan secret/signature memakai constant-time compare.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from ._canonical import (
    aead_nonce_from,
    body_digest_b64,
    build_request_aead_aad,
    build_response_aead_aad,
    canonical_query,
    collect_bound_headers,
    derive_subkey,
    hmac_message,
    normalize_path,
    resp_aead_nonce_from,
    resp_message,
)
from ._crypto import (
    AEAD_ALG,
    ED25519_ALG,
    HMAC_ALG,
    KDF_PURPOSE_AEAD_REQ,
    KDF_PURPOSE_AEAD_RESP,
    KDF_PURPOSE_SIGN_REQ,
    KDF_PURPOSE_SIGN_RESP,
    aead_decrypt,
    aead_encrypt,
    b64_decode_strict,
    b64_encode,
    ed25519_sign,
    ed25519_verify,
    json_encode_compact,
    secure_compare,
    sign_hmac_b64,
)
from .errors import BAD_REQUEST, UNAUTHORIZED, UNPROCESSABLE, SecurePayloadError
from .types import (
    HX_AEAD_ALG,
    HX_AEAD_NONCE,
    HX_BODY_DIGEST,
    HX_CANON_REQ,
    HX_CLIENT_ID,
    HX_KEY_ID,
    HX_NONCE,
    HX_RESP_AEAD_ALG,
    HX_RESP_AEAD_NONCE,
    HX_RESP_BODY_DIGEST,
    HX_RESP_NONCE,
    HX_RESP_SIG_ALG,
    HX_RESP_SIG_VER,
    HX_RESP_SIGNATURE,
    HX_RESP_TIMESTAMP,
    HX_SIG_ALG,
    HX_SIG_VER,
    HX_SIGNATURE,
    HX_TIMESTAMP,
    Options,
    VerifyResult,
)

_TS_RE = re.compile(r"[0-9]+")


def _parse_json_or_none(text: str) -> Any:
    """json_decode PHP-style: None saat bukan JSON valid."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _upper_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    return {str(k).upper(): str(v) for k, v in headers.items()}


class SecurePayloadClient:
    """SDK sisi client protokol SecurePayload v3."""

    def __init__(self, options: Optional[Options] = None) -> None:
        self._o = options or Options()

    # ------------------------------------------------------------------
    # Request build (port RequestBuilder.php)
    # ------------------------------------------------------------------

    def build_headers_and_body(
        self,
        url: str,
        method: str,
        payload: Any,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Tuple[Dict[str, str], str]:
        """Bangun header keamanan + body request keluar; return ``(headers, body)``."""
        o = self._o
        client_id = o.client_id or ""
        key_id = o.key_id or ""
        if not client_id or not key_id:
            raise SecurePayloadError(BAD_REQUEST, "clientId & keyId wajib diisi untuk mode client")

        m = method.upper()
        try:
            parts = urlsplit(url)
        except ValueError:
            raise SecurePayloadError(BAD_REQUEST, "Format URL tidak valid") from None

        # method/path/query kanonik dihitung di sini; server nanti menghitung
        # ulang dari input request, BUKAN membaca X-Canonical-Request.
        path = normalize_path(parts.path or "/")
        q_obj = dict(parse_qsl(parts.query, keep_blank_values=True))
        q_str = canonical_query(q_obj)

        ts = str(o.clock())
        nonce_b64 = o.nonce_generator()

        extra = dict(extra_headers or {})
        bound = collect_bound_headers(extra, o.bind_headers)

        headers: Dict[str, str] = {
            **extra,
            HX_CLIENT_ID: client_id,
            HX_KEY_ID: key_id,
            HX_TIMESTAMP: ts,
            HX_NONCE: nonce_b64,
            HX_SIG_VER: o.version,
            # Hint debugging saja; BUKAN sumber kebenaran keamanan server.
            HX_CANON_REQ: b64_encode(f"{m}\n{path}\n{q_str}".encode("utf-8")),
        }

        plain = json_encode_compact(payload)

        if o.mode in ("aead", "both"):
            raw_key = b64_decode_strict(o.aead_key_b64 or "")
            if raw_key is None or len(raw_key) != 32:
                raise SecurePayloadError(BAD_REQUEST, "Kunci AEAD tidak valid (harus 32 byte base64)")
            key = derive_subkey(raw_key, KDF_PURPOSE_AEAD_REQ, o.version, o.derive_keys)
            nonce24 = aead_nonce_from(nonce_b64, m, path, q_str)
            ciphertext = aead_encrypt(key, nonce24, plain, build_request_aead_aad(o.version, ts, bound))

            headers[HX_AEAD_ALG] = AEAD_ALG
            headers[HX_AEAD_NONCE] = b64_encode(nonce24)
            wrapped = json_encode_compact({"__aead_b64": b64_encode(ciphertext)})

            if o.mode == "aead":
                return headers, wrapped

            # Mode both: digest & signature atas PLAINTEXT pra-AEAD.
            digest = body_digest_b64(plain)
            sig, alg = self._sign_request(
                hmac_message(o.version, client_id, key_id, ts, nonce_b64, m, path, q_str, digest)
            )
            headers[HX_SIG_ALG] = alg
            headers[HX_BODY_DIGEST] = "sha256=" + digest
            headers[HX_SIGNATURE] = sig
            return headers, wrapped

        # Mode hmac: tanda tangan saja, body plaintext JSON.
        digest = body_digest_b64(plain)
        sig, alg = self._sign_request(
            hmac_message(o.version, client_id, key_id, ts, nonce_b64, m, path, q_str, digest)
        )
        headers[HX_SIG_ALG] = alg
        headers[HX_BODY_DIGEST] = "sha256=" + digest
        headers[HX_SIGNATURE] = sig
        return headers, plain

    def _sign_request(self, msg: str) -> Tuple[str, str]:
        """Tanda tangani pesan kanonik request (mirror SecurePayloadConfig::signCanonical).

        Ed25519 request memakai keypair CLIENT (``ed25519_secret_key_b64``).
        """
        o = self._o
        if o.sign_alg == "ed25519":
            sk_raw = b64_decode_strict(o.ed25519_secret_key_b64 or "")
            if sk_raw is None or len(sk_raw) != 64:
                raise SecurePayloadError(
                    BAD_REQUEST, "Secret key Ed25519 tidak valid/tersedia (harus base64 dari 64 byte)"
                )
            return b64_encode(ed25519_sign(msg, sk_raw)), ED25519_ALG

        master = o.hmac_secret_raw or ""
        if len(master) < 32:
            raise SecurePayloadError(BAD_REQUEST, "HMAC Secret terlalu pendek. Minimum 32 karakter.")
        sign_key = derive_subkey(master.encode("utf-8"), KDF_PURPOSE_SIGN_REQ, o.version, o.derive_keys)
        return sign_hmac_b64(msg, sign_key), HMAC_ALG

    # ------------------------------------------------------------------
    # Response verify (port ResponseVerifier.php)
    # ------------------------------------------------------------------

    def verify_response(self, headers: Mapping[str, str], raw_body: str, req_nonce_b64: str) -> VerifyResult:
        """Verifikasi response tanpa melempar; selalu kembalikan VerifyResult."""
        try:
            data = self.verify_response_or_throw(headers, raw_body, req_nonce_b64)
        except SecurePayloadError as err:
            return VerifyResult(ok=False, status=err.status, error=err.message, debug=err.context)
        return VerifyResult(ok=True, mode=data["mode"], body_plain=data["body_plain"], json=data["json"])

    def verify_response_or_throw(
        self, headers: Mapping[str, str], raw_body: str, req_nonce_b64: str
    ) -> Dict[str, Any]:
        """Verifikasi response; lempar SecurePayloadError jika tidak valid."""
        if not req_nonce_b64:
            raise SecurePayloadError(BAD_REQUEST, "Nonce request asal wajib diisi untuk verifikasi response")
        o = self._o

        H = _upper_headers(headers)
        ver = H.get(HX_RESP_SIG_VER.upper(), "")
        resp_ts = H.get(HX_RESP_TIMESTAMP.upper(), "")
        resp_nonce_b64 = H.get(HX_RESP_NONCE.upper(), "")
        if not (ver and resp_ts and resp_nonce_b64):
            raise SecurePayloadError(BAD_REQUEST, "Header response tidak lengkap")
        if ver != o.version:
            raise SecurePayloadError(BAD_REQUEST, "Versi protokol response tidak didukung")

        # Kesegaran timestamp response (anti replay response usang).
        if _TS_RE.fullmatch(resp_ts) is None:
            raise SecurePayloadError(BAD_REQUEST, "Format timestamp response salah")
        ts = int(resp_ts)
        now = o.clock()
        if ts > now + o.clock_skew or ts < now - (o.replay_ttl + o.clock_skew):
            raise SecurePayloadError(UNAUTHORIZED, "Timestamp response di luar batas wajar")

        body_for_sig = raw_body

        # Anti-downgrade: mode aead/both WAJIB response terenkripsi.
        aead_alg = H.get(HX_RESP_AEAD_ALG.upper(), "")
        if o.mode in ("aead", "both") and aead_alg != AEAD_ALG:
            raise SecurePayloadError(
                UNAUTHORIZED,
                f"Mode {o.mode} mewajibkan enkripsi AEAD pada response, "
                "namun header AEAD tidak ada/tidak dikenal",
            )

        if o.mode in ("aead", "both"):
            parsed = _parse_json_or_none(raw_body)
            blob_b64 = parsed.get("__aead_b64", "") if isinstance(parsed, dict) else ""
            if not blob_b64:
                raise SecurePayloadError(BAD_REQUEST, "Payload AEAD response tidak ditemukan")

            key_raw = b64_decode_strict(o.aead_key_b64 or "")
            if key_raw is None or len(key_raw) != 32:
                raise SecurePayloadError(BAD_REQUEST, "Kunci AEAD client tidak valid/tersedia")
            key_raw = derive_subkey(key_raw, KDF_PURPOSE_AEAD_RESP, o.version, o.derive_keys)

            nonce_calc = resp_aead_nonce_from(resp_nonce_b64, req_nonce_b64)
            nonce_hdr = b64_decode_strict(H.get(HX_RESP_AEAD_NONCE.upper(), "")) or b""
            if not secure_compare(nonce_hdr, nonce_calc):
                raise SecurePayloadError(UNAUTHORIZED, "Nonce response mismatch (integritas invalid)")

            ct = b64_decode_strict(blob_b64)
            if ct is None:
                raise SecurePayloadError(BAD_REQUEST, "Format base64 body response rusak")

            plain_bytes = aead_decrypt(
                key_raw, nonce_calc, ct, build_response_aead_aad(ver, req_nonce_b64, resp_ts)
            )
            if plain_bytes is None:
                raise SecurePayloadError(UNAUTHORIZED, "Gagal mendekripsi response (kunci salah atau data rusak)")
            body_for_sig = plain_bytes.decode("utf-8", errors="replace")

            if o.mode == "aead":
                return {"mode": "AEAD", "body_plain": body_for_sig, "json": _parse_json_or_none(body_for_sig)}

        # --- Verifikasi tanda tangan response (hmac / both) ---
        expected_alg = ED25519_ALG if o.sign_alg == "ed25519" else HMAC_ALG
        alg = H.get(HX_RESP_SIG_ALG.upper(), "")
        sig_in = H.get(HX_RESP_SIGNATURE.upper(), "")
        dig_h = H.get(HX_RESP_BODY_DIGEST.upper(), "")
        if alg != expected_alg or not sig_in or not dig_h:
            raise SecurePayloadError(BAD_REQUEST, "Header tanda tangan response tidak lengkap/salah algoritma")

        dig_val = dig_h[len("sha256="):] if dig_h.startswith("sha256=") else ""
        if not dig_val:
            raise SecurePayloadError(BAD_REQUEST, "Format digest response salah (harus sha256=...)")

        calc_dig = body_digest_b64(body_for_sig)
        if not secure_compare(dig_val.encode(), calc_dig.encode()):
            raise SecurePayloadError(UNPROCESSABLE, "Integritas Body Digest response gagal")

        msg = resp_message(o.version, req_nonce_b64, resp_ts, resp_nonce_b64, calc_dig)

        if o.sign_alg == "ed25519":
            pub_raw = b64_decode_strict(o.ed25519_public_key_server_b64 or "")
            if pub_raw is None or len(pub_raw) != 32:
                raise SecurePayloadError(BAD_REQUEST, "Public key Ed25519 server tidak valid/tersedia di client")
            sig_raw = b64_decode_strict(sig_in)
            if sig_raw is None or len(sig_raw) != 64:
                raise SecurePayloadError(BAD_REQUEST, "Format signature Ed25519 response rusak")
            if not ed25519_verify(msg, sig_raw, pub_raw):
                raise SecurePayloadError(UNAUTHORIZED, "Tanda Tangan response (Ed25519) tidak valid")
        else:
            master = o.hmac_secret_raw or ""
            if not master:
                raise SecurePayloadError(BAD_REQUEST, "Secret Key HMAC response tidak tersedia di client")
            sign_key = derive_subkey(master.encode("utf-8"), KDF_PURPOSE_SIGN_RESP, o.version, o.derive_keys)
            if not secure_compare(sign_hmac_b64(msg, sign_key).encode(), sig_in.encode()):
                raise SecurePayloadError(UNAUTHORIZED, "Tanda Tangan response tidak valid")

        return {
            "mode": "BOTH" if o.mode == "both" else "HMAC",
            "body_plain": body_for_sig,
            "json": _parse_json_or_none(body_for_sig),
        }
