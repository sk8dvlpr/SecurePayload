"""Server-side SecurePayload: verifikasi request + build response.

Port semantik persis dari:
- ``src/Server/RequestVerifier.php``  → verify()/verify_or_throw()
- ``src/Server/ReplayGuard.php``      → proteksi replay
- ``src/Response/ResponseBuilder.php`` → build_response()

Invarian keamanan yang dipertahankan:
- method/path/query kanonik diturunkan dari INPUT SERVER, BUKAN dari
  header X-Canonical-Request (anti signature spoofing).
- Kunci replay replay TIDAK menyertakan timestamp; TTL = replayTtl + clockSkew.
- Anti-downgrade: mode aead/both menolak request tanpa AEAD valid, dan
  signAlg ditentukan config server (header hanya boleh cocok).
- Verifikasi Ed25519 request memakai PUBLIC KEY CLIENT dari keyLoader.
- Semua perbandingan secret/signature/nonce memakai constant-time compare.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Mapping, Optional, Tuple

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
    replay_cache_key,
    secure_compare,
    sign_hmac_b64,
)
from .errors import BAD_REQUEST, SERVER_ERROR, UNAUTHORIZED, UNPROCESSABLE, SecurePayloadError
from .types import (
    HX_AEAD_ALG,
    HX_AEAD_NONCE,
    HX_BODY_DIGEST,
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
    KeyLoader,
    Options,
    VerifyResult,
)

_TS_RE = re.compile(r"[0-9]+")

_SUPPORTED_MODES = ("hmac", "aead", "both")
_SUPPORTED_SIGN_ALGS = ("hmac", "ed25519")  # hybrid PQ belum didukung SDK v1


def _parse_json_or_none(text: str) -> Any:
    """json_decode PHP-style: None saat bukan JSON valid."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


class _MemoryReplayStore:
    """Replay store in-process sederhana (fallback bila ``replay_store`` tak diinjeksi).

    Paritas perilaku dengan ReplayGuard PHP untuk satu proses: nonce diingat
    selama TTL (= replayTtl + clockSkew). Untuk multi-proses produksi gunakan
    Redis/Memcached via opsi ``replay_store``.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}

    def __call__(self, cache_key: str, ttl: int) -> bool:
        now = time.monotonic()
        # Prune entitas kedaluwarsa agar dict tidak tumbuh tanpa batas.
        expired = [k for k, ts in self._seen.items() if now - ts >= ttl]
        for k in expired:
            del self._seen[k]
        if cache_key in self._seen:
            return False
        self._seen[cache_key] = now
        return True


class SecurePayloadServer:
    """SDK sisi server protokol SecurePayload v3."""

    def __init__(self, options: Optional[Options] = None) -> None:
        o = options or Options()
        if o.mode not in _SUPPORTED_MODES:
            raise SecurePayloadError(BAD_REQUEST, f"Mode tidak valid: {o.mode}")
        if o.sign_alg not in _SUPPORTED_SIGN_ALGS:
            raise SecurePayloadError(
                BAD_REQUEST,
                f"signAlg tidak didukung SDK Python v1: {o.sign_alg} "
                "(hybrid-mldsa44-ed25519 menyusul)",
            )
        self._o = o
        self._memory_replay = _MemoryReplayStore()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_keys(self, client_id: str, key_id: str) -> Dict[str, Optional[str]]:
        loader: Optional[KeyLoader] = self._o.key_loader
        if loader is not None:
            loaded = loader(client_id, key_id)
            return dict(loaded or {})
        return {}

    def _kv(self, keys: Mapping[str, Optional[str]], name: str, fallback: Optional[str]) -> Optional[str]:
        """Nilai kunci: keyLoader lebih dulu, fallback ke kunci instance."""
        value = keys.get(name)
        if value is not None and value != "":
            return value
        return fallback

    def _check_replay(self, client_id: str, key_id: str, nonce_b64: str) -> None:
        """Proteksi replay; kunci TIDAK menyertakan timestamp (mirror ReplayGuard.php)."""
        o = self._o
        ttl = o.replay_ttl + o.clock_skew
        cache_key = replay_cache_key(client_id, key_id, nonce_b64)
        store = o.replay_store if o.replay_store is not None else self._memory_replay
        if not store(cache_key, ttl):
            raise SecurePayloadError(UNAUTHORIZED, "Replay detected")

    @staticmethod
    def _query_dict(query) -> Dict[str, Any]:
        """Normalisasi input query (string atau Mapping) ke dict."""
        from urllib.parse import parse_qsl

        if isinstance(query, str):
            return dict(parse_qsl(query, keep_blank_values=True))
        if isinstance(query, Mapping):
            return dict(query)
        raise SecurePayloadError(BAD_REQUEST, "Parameter query tidak valid")

    # ------------------------------------------------------------------
    # Request verify (port RequestVerifier.php)
    # ------------------------------------------------------------------

    def verify(self, headers: Mapping[str, str], raw_body: str, method: str, path: str, query) -> VerifyResult:
        """Verifikasi request tanpa melempar; selalu kembalikan VerifyResult."""
        try:
            data = self.verify_or_throw(headers, raw_body, method, path, query)
        except SecurePayloadError as err:
            return VerifyResult(ok=False, status=err.status, error=err.message, debug=err.context)
        return VerifyResult(ok=True, mode=data["mode"], body_plain=data["body_plain"], json=data["json"])

    def verify_or_throw(self, headers: Mapping[str, str], raw_body: str, method: str, path: str, query) -> Dict[str, Any]:
        """Verifikasi request masuk; lempar SecurePayloadError jika gagal.

        Return ``{"mode": "AEAD"|"HMAC"|"BOTH", "body_plain": str|None, "json": any}``.
        """
        o = self._o
        H = {str(k).upper(): str(v) for k, v in headers.items()}

        ver = H.get(HX_SIG_VER.upper(), "")
        cid = H.get(HX_CLIENT_ID.upper(), "")
        kid = H.get(HX_KEY_ID.upper(), "")
        ts_str = H.get(HX_TIMESTAMP.upper(), "")
        nonce_b64 = H.get(HX_NONCE.upper(), "")

        # 1. Kelengkapan & versi header.
        if not (ver and cid and kid and ts_str and nonce_b64):
            raise SecurePayloadError(BAD_REQUEST, "Header keamanan tidak lengkap")
        if ver != o.version:
            raise SecurePayloadError(BAD_REQUEST, "Versi protokol tidak didukung")

        # 2. Validasi timestamp (tidak masa depan; tidak kadaluarsa).
        if _TS_RE.fullmatch(ts_str) is None:
            raise SecurePayloadError(BAD_REQUEST, "Format timestamp salah")
        ts = int(ts_str)
        now = o.clock()
        if ts > now + o.clock_skew or ts < now - (o.replay_ttl + o.clock_skew):
            raise SecurePayloadError(UNAUTHORIZED, "Timestamp di luar batas wajar (kadaluarsa atau jam salah)")

        # 3. Proteksi replay.
        self._check_replay(cid, kid, nonce_b64)

        # Parameter kanonik dari input server — BUKAN dari X-Canonical-Request.
        m = method.upper()
        p = normalize_path(path or "/")
        q_str = canonical_query(self._query_dict(query))

        keys = self._load_keys(cid, kid)
        raw_body_for_hmac: Optional[str] = None

        aead_alg = H.get(HX_AEAD_ALG.upper(), "")

        # Mode aead/both WAJIB terenkripsi — tolak jika header AEAD absen/salah
        # (mencegah downgrade both → hmac sehingga plaintext bocor).
        if o.mode in ("aead", "both") and aead_alg != AEAD_ALG:
            raise SecurePayloadError(
                UNAUTHORIZED,
                f"Mode {o.mode} mewajibkan enkripsi AEAD, "
                "namun header AEAD tidak ada atau algoritmanya tidak dikenal",
            )

        # --- Verifikasi AEAD / BOTH ---
        if o.mode in ("aead", "both"):
            parsed = _parse_json_or_none(raw_body)
            blob_b64 = parsed.get("__aead_b64", "") if isinstance(parsed, dict) else ""
            if not blob_b64:
                raise SecurePayloadError(BAD_REQUEST, "Payload AEAD tidak ditemukan")

            key_raw = b64_decode_strict(self._kv(keys, "aead_key_b64", o.aead_key_b64) or "")
            if key_raw is None or len(key_raw) != 32:
                raise SecurePayloadError(SERVER_ERROR, "Kunci AEAD server tidak valid/tersedia")
            key_raw = derive_subkey(key_raw, KDF_PURPOSE_AEAD_REQ, o.version, o.derive_keys)

            # Nonce dihitung ulang lalu dibandingkan constant-time dengan header
            # (integritas binding konteks; cegah pemindahan nonce antar-konteks).
            nonce_calc = aead_nonce_from(nonce_b64, m, p, q_str)
            nonce_hdr = b64_decode_strict(H.get(HX_AEAD_NONCE.upper(), "")) or b""
            if not secure_compare(nonce_hdr, nonce_calc):
                raise SecurePayloadError(UNAUTHORIZED, "Nonce mismatch (Integritas request invalid)")

            ct = b64_decode_strict(blob_b64)
            if ct is None:
                raise SecurePayloadError(BAD_REQUEST, "Format base64 body rusak")

            # AAD dibaca dari header request masuk (yang bisa dimanipulasi
            # penyerang) — perubahan apa pun menggagalkan dekripsi.
            bound = collect_bound_headers(headers, o.bind_headers)
            plain_bytes = aead_decrypt(key_raw, nonce_calc, ct, build_request_aead_aad(ver, ts_str, bound))
            if plain_bytes is None:
                raise SecurePayloadError(UNAUTHORIZED, "Gagal mendekripsi (Kunci salah atau data rusak)")

            plain_text = plain_bytes.decode("utf-8", errors="replace")

            if o.mode == "aead":
                return {"mode": "AEAD", "body_plain": plain_text, "json": _parse_json_or_none(plain_text)}

            # BOTH: plaintext hasil dekripsi jadi input verifikasi HMAC/digest.
            raw_body_for_hmac = plain_text
            digest_hdr = H.get(HX_BODY_DIGEST.upper(), "")
            calc = "sha256=" + body_digest_b64(raw_body_for_hmac)
            if not secure_compare(digest_hdr.encode(), calc.encode()):
                raise SecurePayloadError(UNPROCESSABLE, "Integritas Body Digest gagal")

        # --- Verifikasi tanda tangan (hmac / both) ---
        if o.mode in ("hmac", "both"):
            alg = H.get(HX_SIG_ALG.upper(), "")
            sig_in = H.get(HX_SIGNATURE.upper(), "")
            dig_h = H.get(HX_BODY_DIGEST.upper(), "")

            # Algoritma ditentukan config server; header tak cocok = penalti downgrade.
            expected_alg = ED25519_ALG if o.sign_alg == "ed25519" else HMAC_ALG
            if alg != expected_alg or not sig_in or not dig_h:
                raise SecurePayloadError(BAD_REQUEST, "Header tanda tangan tidak lengkap/salah algoritma")

            dig_val = dig_h[len("sha256="):] if dig_h.startswith("sha256=") else ""
            if not dig_val:
                raise SecurePayloadError(BAD_REQUEST, "Format digest salah (harus sha256=...)")

            body_for_hmac = raw_body_for_hmac if raw_body_for_hmac is not None else raw_body

            # 1. Integritas digest body.
            calc_dig = body_digest_b64(body_for_hmac)
            if not secure_compare(dig_val.encode(), calc_dig.encode()):
                raise SecurePayloadError(UNPROCESSABLE, "Integritas Body Digest HMAC gagal")

            # 2. Verifikasi signature atas pesan kanonik.
            msg = hmac_message(o.version, cid, kid, ts_str, nonce_b64, m, p, q_str, calc_dig)

            if o.sign_alg == "ed25519":
                pub_raw = b64_decode_strict(self._kv(keys, "ed25519_public_key_b64", o.ed25519_public_key_b64) or "")
                if pub_raw is None or len(pub_raw) != 32:
                    raise SecurePayloadError(SERVER_ERROR, "Public key Ed25519 server tidak valid/tersedia")
                sig_raw = b64_decode_strict(sig_in)
                if sig_raw is None or len(sig_raw) != 64:
                    raise SecurePayloadError(BAD_REQUEST, "Format signature Ed25519 rusak")
                if not ed25519_verify(msg, sig_raw, pub_raw):
                    raise SecurePayloadError(UNAUTHORIZED, "Tanda Tangan (Ed25519) tidak valid")
            else:
                hmac_raw = self._kv(keys, "hmac_secret", o.hmac_secret_raw)
                if hmac_raw is not None and len(hmac_raw) < 32:
                    raise SecurePayloadError(
                        SERVER_ERROR, "HMAC Secret yang dimuat dari keyLoader terlalu pendek (minimum 32 karakter)."
                    )
                if not hmac_raw:
                    raise SecurePayloadError(SERVER_ERROR, "Secret Key HMAC tidak ditemukan di server")
                sign_key = derive_subkey(hmac_raw.encode("utf-8"), KDF_PURPOSE_SIGN_REQ, o.version, o.derive_keys)
                if not secure_compare(sign_hmac_b64(msg, sign_key).encode(), sig_in.encode()):
                    raise SecurePayloadError(UNAUTHORIZED, "Tanda Tangan (Signature) tidak valid")

            final_mode = "BOTH" if (o.mode == "both" and raw_body_for_hmac is not None) else "HMAC"
            return {
                "mode": final_mode,
                "body_plain": body_for_hmac,
                "json": _parse_json_or_none(body_for_hmac),
            }

        raise SecurePayloadError(BAD_REQUEST, "Tidak ditemukan header keamanan yang valid")

    # ------------------------------------------------------------------
    # Response build (port ResponseBuilder.php)
    # ------------------------------------------------------------------

    def build_response(self, request_headers: Mapping[str, str], payload: Any) -> Tuple[Dict[str, str], str]:
        """Bangun response aman terikat ke request; return ``(headers, body)``.

        Ed25519 response memakai keypair SERVER (``ed25519_secret_key_server_b64``).
        """
        o = self._o
        H = {str(k).upper(): str(v) for k, v in request_headers.items()}

        cid = H.get(HX_CLIENT_ID.upper(), "")
        kid = H.get(HX_KEY_ID.upper(), "")
        req_nonce_b64 = H.get(HX_NONCE.upper(), "")
        if not req_nonce_b64:
            raise SecurePayloadError(BAD_REQUEST, "Nonce request tidak ditemukan untuk binding response")

        keys = self._load_keys(cid, kid)

        ver = o.version
        resp_ts = str(o.clock())
        resp_nonce_b64 = o.resp_nonce_generator()

        resp_headers: Dict[str, str] = {
            HX_RESP_TIMESTAMP: resp_ts,
            HX_RESP_NONCE: resp_nonce_b64,
            HX_RESP_SIG_VER: ver,
        }

        plain = json_encode_compact(payload)
        body_out = plain

        # --- Enkripsi response (mode aead / both) ---
        if o.mode in ("aead", "both"):
            key_raw = b64_decode_strict(self._kv(keys, "aead_key_b64", o.aead_key_b64) or "")
            if key_raw is None or len(key_raw) != 32:
                raise SecurePayloadError(SERVER_ERROR, "Kunci AEAD response tidak valid/tersedia")
            key_raw = derive_subkey(key_raw, KDF_PURPOSE_AEAD_RESP, o.version, o.derive_keys)

            nonce24 = resp_aead_nonce_from(resp_nonce_b64, req_nonce_b64)
            ciphertext = aead_encrypt(key_raw, nonce24, plain, build_response_aead_aad(ver, req_nonce_b64, resp_ts))

            body_out = json_encode_compact({"__aead_b64": b64_encode(ciphertext)})
            resp_headers[HX_RESP_AEAD_ALG] = AEAD_ALG
            resp_headers[HX_RESP_AEAD_NONCE] = b64_encode(nonce24)

        # --- Tanda tangan response (mode hmac / both) ---
        if o.mode in ("hmac", "both"):
            digest = body_digest_b64(plain)
            msg = resp_message(ver, req_nonce_b64, resp_ts, resp_nonce_b64, digest)

            if o.sign_alg == "ed25519":
                sk_b64 = self._kv(keys, "ed25519_secret_key_server_b64", o.ed25519_secret_key_server_b64)
                sk_raw = b64_decode_strict(sk_b64 or "")
                if sk_raw is None or len(sk_raw) != 64:
                    raise SecurePayloadError(
                        SERVER_ERROR, "Secret key Ed25519 server tidak valid/tersedia (harus base64 dari 64 byte)"
                    )
                resp_headers[HX_RESP_SIG_ALG] = ED25519_ALG
                resp_headers[HX_RESP_SIGNATURE] = b64_encode(ed25519_sign(msg, sk_raw))
            else:
                hmac_raw = self._kv(keys, "hmac_secret", o.hmac_secret_raw)
                if not hmac_raw:
                    raise SecurePayloadError(SERVER_ERROR, "Secret Key HMAC response tidak tersedia di server")
                if len(hmac_raw) < 32:
                    raise SecurePayloadError(SERVER_ERROR, "HMAC Secret response terlalu pendek (minimum 32 karakter)")
                sign_key = derive_subkey(hmac_raw.encode("utf-8"), KDF_PURPOSE_SIGN_RESP, o.version, o.derive_keys)
                resp_headers[HX_RESP_SIG_ALG] = HMAC_ALG
                resp_headers[HX_RESP_SIGNATURE] = sign_hmac_b64(msg, sign_key)

            resp_headers[HX_RESP_BODY_DIGEST] = "sha256=" + digest

        return resp_headers, body_out
