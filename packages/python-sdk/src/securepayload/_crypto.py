"""Primitif kripto tingkat rendah SecurePayload (port dari ext-sodium PHP).

Sumber kebenaran: ``src/Protocol/{Aead,Hkdf}.php``, ``SecurePayloadConfig.php``,
``RequestVerifier.php``. Semua operasi memakai pynacl (binding libsodium —
primitif identik ext-sodium) + stdlib ``hashlib``/``hmac`` agar hasil
byte-exact identik dengan implementasi PHP.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_mod
import json
from typing import Any, Optional, Union

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

BytesLike = Union[bytes, str]

# Nama algoritma untuk header X-*-Algorithm (mirror konstanta SecurePayload.php).
HMAC_ALG = "HMAC-SHA256"
ED25519_ALG = "ED25519"
AEAD_ALG = "XCHACHA20-POLY1305-IETF"

# Label HKDF pemisahan domain kunci (mirror SecurePayload::KDF_PURPOSE_*).
KDF_PURPOSE_AEAD_REQ = "sp-aead-req"
KDF_PURPOSE_SIGN_REQ = "sp-sign-req"
KDF_PURPOSE_AEAD_RESP = "sp-aead-resp"
KDF_PURPOSE_SIGN_RESP = "sp-sign-resp"


def to_bytes(value: BytesLike) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def b64_encode(data: bytes) -> str:
    """Base64 STANDAR (bukan urlsafe) — format semua header X-*."""
    return base64.b64encode(data).decode("ascii")


def b64_decode_strict(value: str) -> Optional[bytes]:
    """Decode base64 standar secara ketat; ``None`` jika rusak.

    Setara ``base64_decode($v, true)`` PHP (strict): karakter di luar alfabet
    atau panjang/padding salah mengembalikan null, bukan data parsial.
    """
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return None


def secure_compare(a: bytes, b: bytes) -> bool:
    """Perbandingan constant-time (invarian keamanan: setara ``hash_equals``)."""
    return _hmac_mod.compare_digest(a, b)


def hmac_sha256(key: bytes, message: BytesLike) -> bytes:
    return _hmac_mod.new(key, to_bytes(message), hashlib.sha256).digest()


def sign_hmac_b64(message: BytesLike, key: bytes) -> str:
    """HMAC-SHA256 atas pesan kanonik, base64 standar."""
    return b64_encode(hmac_sha256(key, message))


def sha256_hex(message: BytesLike) -> str:
    return hashlib.sha256(to_bytes(message)).hexdigest()


def replay_cache_key(client_id: str, key_id: str, nonce_b64: str) -> str:
    """Kunci replay 'sp_' + 48 char hex pertama sha256(cid|kid|nonce).

    Timestamp SENGAJA tidak masuk kunci (mirror ReplayGuard.php): nonce wajib
    sekali-pakai mutlak; pada mode aead ts tidak terautentikasi sehingga jika
    ts ikut dalam kunci, replay cukup memutasi timestamp.
    """
    digest = sha256_hex(f"{client_id}|{key_id}|{nonce_b64}")
    return "sp_" + digest[:48]


def aead_encrypt(key: bytes, nonce: bytes, plaintext: BytesLike, aad: BytesLike) -> bytes:
    """XChaCha20-Poly1305-IETF (combined ciphertext+tag), identik sodium_crypto_aead_..._encrypt PHP."""
    return crypto_aead_xchacha20poly1305_ietf_encrypt(to_bytes(plaintext), to_bytes(aad), nonce, key)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: BytesLike) -> Optional[bytes]:
    """Dekripsi AEAD; ``None`` saat tag/AAD/kunci tidak cocok (jangan lempar)."""
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, to_bytes(aad), nonce, key)
    except (CryptoError, ValueError):
        return None


def ed25519_sign(message: BytesLike, secret_key_raw: bytes) -> bytes:
    """Signature detached Ed25519.

    PHP menyimpan secret key 64-byte ``(seed || public)``; SigningKey PyNaCl
    menerima seed 32-byte pertama — hasil signature identik.
    """
    if len(secret_key_raw) != 64:
        raise ValueError("Secret key Ed25519 harus 64 byte (seed || public)")
    signing_key = SigningKey(secret_key_raw[:32])
    return signing_key.sign(to_bytes(message)).signature


def ed25519_verify(message: BytesLike, signature: bytes, public_key_raw: bytes) -> bool:
    """Verifikasi signature detached Ed25519; False saat tidak valid."""
    if len(public_key_raw) != 32 or len(signature) != 64:
        return False
    try:
        VerifyKey(public_key_raw).verify(to_bytes(message), signature)
        return True
    except Exception:
        return False


def hkdf_sha256(ikm: bytes, info: BytesLike, length: int = 32) -> bytes:
    """HKDF-SHA256 RFC 5869 (extract+expand manual via hashlib+hmac).

    Salt kosong = 32 zero byte — semantik sama dengan ``hash_hkdf('sha256', ...)`` PHP
    dan ``hkdfSync('sha256', ..., Buffer.alloc(0), ...)`` Node.
    """
    prk = _hmac_mod.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = _hmac_mod.new(prk, block + to_bytes(info) + bytes([counter]), hashlib.sha256).digest()
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def json_encode_compact(obj: Any) -> str:
    """JSON compact tanpa spasi, unicode/slash apa adanya.

    Setara ``json_encode($o, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)`` PHP;
    krusial untuk byte-exactness body wire.
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
