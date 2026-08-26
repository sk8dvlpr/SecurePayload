"""SecurePayload Python SDK — protokol v3.

Port byte-exact dari PHP core (``sk8dvlpr/securepayload``). Contoh::

    from securepayload import Options, SecurePayloadClient, SecurePayloadServer

Ekspor publik: client/server SDK, error, tipe opsi/hasil, dan primitif
kanonik (untuk conformance & tooling lanjutan).
"""

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
)
from .client import SecurePayloadClient
from .errors import (
    BAD_REQUEST,
    SERVER_ERROR,
    UNAUTHORIZED,
    UNPROCESSABLE,
    SecurePayloadError,
)
from .server import SecurePayloadServer
from .types import Mode, Options, SignAlg, VerifyResult

__version__ = "0.1.0"

__all__ = [
    "AEAD_ALG",
    "BAD_REQUEST",
    "ED25519_ALG",
    "HMAC_ALG",
    "KDF_PURPOSE_AEAD_REQ",
    "KDF_PURPOSE_AEAD_RESP",
    "KDF_PURPOSE_SIGN_REQ",
    "KDF_PURPOSE_SIGN_RESP",
    "SERVER_ERROR",
    "UNAUTHORIZED",
    "UNPROCESSABLE",
    "Mode",
    "Options",
    "SecurePayloadClient",
    "SecurePayloadError",
    "SecurePayloadServer",
    "SignAlg",
    "VerifyResult",
    "aead_nonce_from",
    "body_digest_b64",
    "build_request_aead_aad",
    "build_response_aead_aad",
    "canonical_query",
    "collect_bound_headers",
    "derive_subkey",
    "hmac_message",
    "normalize_path",
    "resp_aead_nonce_from",
    "resp_message",
]
