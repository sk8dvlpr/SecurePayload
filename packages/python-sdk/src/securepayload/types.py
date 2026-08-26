"""Tipe publik SDK Python SecurePayload.

Paritas opsi dengan ``packages/node-sdk/src/types.ts`` (SecurePayloadNodeOptions).
Penamaan snake_case mengikuti konvensi Python.
"""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Union

# Mode keamanan protokol.
Mode = Literal["hmac", "aead", "both"]
# Algoritma tanda tangan; ditentukan config SERVER (anti-downgrade).
SignAlg = Literal["hmac", "ed25519"]

# Kunci yang dimuat keyLoader(clientId, keyId) → dict (snake_case).
LoadedKeys = Dict[str, Optional[str]]
KeyLoader = Callable[[str, str], LoadedKeys]
# replay_store(cache_key, ttl_detik) → True jika nonce BARU (belum pernah dipakai).
ReplayStore = Callable[[str, int], bool]

# Nama header protokol (mirror SecurePayload::HX_* di PHP core).
HX_CLIENT_ID = "X-Client-Id"
HX_KEY_ID = "X-Key-Id"
HX_TIMESTAMP = "X-Timestamp"
HX_NONCE = "X-Nonce"
HX_SIG_VER = "X-Signature-Version"
HX_SIG_ALG = "X-Signature-Algorithm"
HX_SIGNATURE = "X-Signature"
HX_BODY_DIGEST = "X-Body-Digest"
HX_CANON_REQ = "X-Canonical-Request"  # hint debugging, BUKAN sumber kebenaran server
HX_AEAD_NONCE = "X-AEAD-Nonce"
HX_AEAD_ALG = "X-AEAD-Algorithm"

HX_RESP_TIMESTAMP = "X-Resp-Timestamp"
HX_RESP_NONCE = "X-Resp-Nonce"
HX_RESP_SIG_VER = "X-Resp-Signature-Version"
HX_RESP_SIG_ALG = "X-Resp-Signature-Algorithm"
HX_RESP_SIGNATURE = "X-Resp-Signature"
HX_RESP_BODY_DIGEST = "X-Resp-Body-Digest"
HX_RESP_AEAD_ALG = "X-Resp-AEAD-Algorithm"
HX_RESP_AEAD_NONCE = "X-Resp-AEAD-Nonce"


def _default_clock() -> int:
    return int(time.time())


def _gen_nonce_b64() -> str:
    """Nonce acak 16 byte base64 standar (mirror Digest::genNonceB64)."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


@dataclass
class Options:
    """Opsi SDK SecurePayload (client & server).

    Ed25519 binding keypair:
    - Request ditandatangani keypair CLIENT (``ed25519_secret_key_b64``).
    - Response ditandatangani keypair SERVER (``ed25519_secret_key_server_b64``,
      diverifikasi client via ``ed25519_public_key_server_b64``).
    """

    mode: Mode = "both"
    sign_alg: SignAlg = "hmac"
    # SDK v1 menargetkan protocol v3; v4 menyusul di iterasi berikutnya.
    version: str = "3"

    # Kredensial client (wajib untuk build_headers_and_body).
    client_id: Optional[str] = None
    key_id: Optional[str] = None
    hmac_secret_raw: Optional[str] = None
    aead_key_b64: Optional[str] = None

    # Ed25519 (base64 standar).
    ed25519_secret_key_b64: Optional[str] = None  # client: signing request (64 byte = seed||pub)
    ed25519_public_key_server_b64: Optional[str] = None  # client: verifikasi response (32 byte)
    ed25519_secret_key_server_b64: Optional[str] = None  # server: signing response (64 byte)
    ed25519_public_key_b64: Optional[str] = None  # server fallback: verifikasi request (biasanya via key_loader)

    derive_keys: bool = False
    bind_headers: List[str] = field(default_factory=list)

    # Proteksi replay (server).
    replay_ttl: int = 120
    clock_skew: int = 60
    clock: Callable[[], int] = _default_clock
    replay_store: Optional[ReplayStore] = None
    key_loader: Optional[KeyLoader] = None

    # Generator injektabel (untuk test/fixtures deterministik).
    nonce_generator: Callable[[], str] = _gen_nonce_b64
    resp_nonce_generator: Callable[[], str] = _gen_nonce_b64


@dataclass
class VerifyResult:
    """Hasil verify()/verify_response() non-lempar (mirror VerifyResult node-sdk).

    ``json`` dapat ``None`` saat body bukan JSON valid — paritas json_decode PHP.
    """

    ok: bool
    status: Optional[int] = None
    error: Optional[str] = None
    debug: Dict[str, Any] = field(default_factory=dict)
    mode: str = ""
    body_plain: Optional[str] = None
    json: Any = None


VerifyData = Dict[str, Union[str, None]]
