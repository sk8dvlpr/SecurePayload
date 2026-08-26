"""Eksepsi SDK Python SecurePayload.

Mirror kode status HTTP dari ``SecurePayloadException`` PHP:
BAD_REQUEST / SERVER_ERROR / UNAUTHORIZED / UNPROCESSABLE.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Kode status HTTP yang dipakai protokol (mirror SecurePayloadException PHP).
BAD_REQUEST = 400
UNAUTHORIZED = 401
UNPROCESSABLE = 422
SERVER_ERROR = 500


class SecurePayloadError(Exception):
    """Error protokol SecurePayload dengan kode status HTTP dan konteks debug.

    Konteks TIDAK PERNAH berisi secret/plaintext/ciphertext — hanya data
    non-rahasia untuk debugging (clientId, keyId, alasan, nilai header).
    """

    def __init__(self, status: int, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.context: Dict[str, Any] = context or {}
