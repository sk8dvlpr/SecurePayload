"""Interop smoke: Python SDK ↔ PHP core (proses nyata, byte-exact).

Dua arah:
1. PHP build → Python server verify.
2. Python client build → PHP server verify.

Test di-skip bila PHP CLI / vendor/ tidak tersedia (mis. di lingkungan
tanpa toolchain PHP); CI menjalankannya penuh (job python-sdk).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from securepayload import Options, SecurePayloadClient, SecurePayloadServer

INTEROP_DIR = Path(__file__).resolve().parent / "interop"
FIXED_TS = 1700000000
URL = "https://example.test/v1/pay?a=1&b=2"


def _php_available() -> bool:
    return shutil.which("php") is not None and (REPO_ROOT / "vendor" / "autoload.php").is_file()


pytestmark = pytest.mark.skipif(not _php_available(), reason="PHP CLI + vendor/ diperlukan untuk interop")


def _run_php(script: Path, stdin: str | None = None) -> str:
    proc = subprocess.run(
        ["php", str(script)],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    assert proc.returncode == 0, f"PHP gagal: {proc.stderr}"
    return proc.stdout.strip()


def _py_server(standard_keys: dict) -> SecurePayloadServer:
    return SecurePayloadServer(
        Options(
            mode="both",
            sign_alg="hmac",
            version="3",
            clock=lambda: FIXED_TS,
            replay_store=lambda cache_key, ttl: True,
            key_loader=lambda cid, kid: {
                "hmac_secret": standard_keys["hmacSecret"],
                "aead_key_b64": standard_keys["aeadKeyB64"],
                "ed25519_public_key_b64": standard_keys["ed25519ClientPublicB64"],
            },
        )
    )


def test_php_build_python_verify(standard_keys: dict) -> None:
    out = json.loads(_run_php(INTEROP_DIR / "php_build.php"))
    result = _py_server(standard_keys).verify(out["headers"], out["body"], "POST", "/v1/pay", {"a": "1", "b": "2"})
    assert result.ok, f"{result.status}: {result.error}"
    assert result.mode == "BOTH"
    assert result.json == {"amount": 100}


def test_python_build_php_verify(standard_keys: dict) -> None:
    client = SecurePayloadClient(
        Options(
            mode="both",
            sign_alg="hmac",
            version="3",
            client_id=standard_keys["clientId"],
            key_id=standard_keys["keyId"],
            hmac_secret_raw=standard_keys["hmacSecret"],
            aead_key_b64=standard_keys["aeadKeyB64"],
            clock=lambda: FIXED_TS,
            nonce_generator=lambda: "AQEBAQEBAQEBAQEBAQEBAQ==",
        )
    )
    headers, body = client.build_headers_and_body(URL, "POST", {"amount": 100})

    payload = json.dumps({"headers": headers, "body": body})
    out = json.loads(_run_php(INTEROP_DIR / "php_verify.php", stdin=payload))

    assert out["ok"] is True, f"PHP menolak request Python SDK: {out}"
    assert out["mode"] in ("BOTH", "BOTH-AEAD")
