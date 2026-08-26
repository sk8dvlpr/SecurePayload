"""Negative conformance v3 — semua docs/fixtures/v3/negative/*.json wajib GAGAL verify.

Tiap vektor adalah request yang sudah dimanipulasi (signature, nonce,
timestamp, downgrade signAlg) dan HARUS ditolak server dengan ok=false.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import FIXTURES_ROOT, load_json
from securepayload import Options, SecurePayloadServer

NEGATIVE_FILES = sorted(p.name for p in (FIXTURES_ROOT / "v3" / "negative").glob("*.json"))


@pytest.mark.parametrize("fname", NEGATIVE_FILES)
def test_negative_vector(fname: str, v3_root: Path, standard_keys: dict) -> None:
    vector = load_json(v3_root / "negative" / fname)
    cfg = vector["config"]
    fixed = vector["fixed"]
    req = vector["request"]

    server = SecurePayloadServer(
        Options(
            mode=cfg["mode"],
            # Anti-downgrade: signAlg server bisa berbeda dari yang dipakai client
            # (vektor signalg-downgrade) — header harus cocok config SERVER.
            sign_alg=(vector.get("server_config") or {}).get("signAlg", cfg["signAlg"]),
            version=vector["protocol_version"],
            derive_keys=bool(cfg.get("deriveKeys")),
            bind_headers=list(cfg.get("bindHeaders") or []),
            clock=lambda: fixed["timestamp"],
            replay_store=lambda cache_key, ttl: True,
            key_loader=lambda cid, kid: {
                "hmac_secret": standard_keys["hmacSecret"],
                "aead_key_b64": standard_keys["aeadKeyB64"],
                "ed25519_public_key_b64": standard_keys["ed25519ClientPublicB64"],
                "ed25519_secret_key_server_b64": standard_keys["ed25519ServerSecretB64"],
            },
        )
    )

    result = server.verify(
        vector["expected"]["headers"], vector["expected"]["body"], req["method"], req["path"], req["query"]
    )

    assert result.ok is False, f"{fname}: request tamper seharusnya ditolak"
    assert result.status in (400, 401), f"{fname}: status {result.status} di luar ekspektasi"
