"""Wire conformance v3 — semua docs/fixtures/v3/wire/*.json.

Untuk tiap vektor: rebuild headers+body dari request+config+fixed+kunci,
bandingkan byte-exact dengan ``expected``, lalu verifikasi sisi server dan
(untuk fixture roundtrip) build + verifikasi response.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

import pytest

from conftest import FIXTURES_ROOT, load_json
from securepayload import Options, SecurePayloadClient, SecurePayloadServer

WIRE_FILES = sorted(p.name for p in (FIXTURES_ROOT / "v3" / "wire").glob("*.json"))


def _make_url(req: dict) -> str:
    """Setara pola node-sdk: https://example.test{path}?{query}."""
    return f"https://example.test{req['path']}?{urlencode(req['query'])}"


def _extra_headers(req: dict) -> dict:
    extra = req.get("extra_headers")
    if not extra:
        return {}
    return {} if isinstance(extra, list) else dict(extra)


def _client_options(vector: dict, keys: dict) -> Options:
    cfg = vector["config"]
    fixed = vector["fixed"]
    return Options(
        mode=cfg["mode"],
        sign_alg=cfg["signAlg"],
        version=vector["protocol_version"],
        client_id=keys["clientId"],
        key_id=keys["keyId"],
        hmac_secret_raw=keys["hmacSecret"],
        aead_key_b64=keys["aeadKeyB64"],
        ed25519_secret_key_b64=keys["ed25519ClientSecretB64"],
        ed25519_public_key_server_b64=keys["ed25519ServerPublicB64"],
        derive_keys=bool(cfg.get("deriveKeys")),
        bind_headers=list(cfg.get("bindHeaders") or []),
        clock=lambda: fixed["timestamp"],
        nonce_generator=lambda: fixed["nonce_b64"],
        resp_nonce_generator=lambda: fixed["resp_nonce_b64"],
        key_loader=lambda cid, kid: {
            "hmac_secret": keys["hmacSecret"],
            "aead_key_b64": keys["aeadKeyB64"],
            "ed25519_public_key_b64": keys["ed25519ClientPublicB64"],
            "ed25519_secret_key_server_b64": keys["ed25519ServerSecretB64"],
            "ed25519_public_key_server_b64": keys["ed25519ServerPublicB64"],
        },
    )


def _server_options(vector: dict, keys: dict) -> Options:
    cfg = vector["config"]
    fixed = vector["fixed"]
    return Options(
        mode=cfg["mode"],
        sign_alg=(vector.get("server_config") or {}).get("signAlg", cfg["signAlg"]),
        version=vector["protocol_version"],
        derive_keys=bool(cfg.get("deriveKeys")),
        bind_headers=list(cfg.get("bindHeaders") or []),
        clock=lambda: fixed["timestamp"],
        replay_store=lambda cache_key, ttl: True,
        key_loader=lambda cid, kid: {
            "hmac_secret": keys["hmacSecret"],
            "aead_key_b64": keys["aeadKeyB64"],
            "ed25519_public_key_b64": keys["ed25519ClientPublicB64"],
            "ed25519_secret_key_server_b64": keys["ed25519ServerSecretB64"],
        },
    )


def test_wire_files_discovered(v3_root: Path) -> None:
    files = sorted(p.name for p in v3_root.glob("wire/*.json"))
    assert len(files) >= 9


@pytest.mark.parametrize("fname", WIRE_FILES)
def test_wire_vector(fname: str, v3_root: Path, standard_keys: dict) -> None:
    vector = load_json(v3_root / "wire" / fname)
    fixed = vector["fixed"]
    req = vector["request"]
    expected = vector["expected"]

    # 1. Client build → harus byte-exact dengan expected.
    client = SecurePayloadClient(_client_options(vector, standard_keys))
    headers, body = client.build_headers_and_body(
        _make_url(req), req["method"], req["payload"], _extra_headers(req)
    )
    assert headers == expected["headers"], f"{fname}: header mismatch"
    assert body == expected["body"], f"{fname}: body mismatch"

    # 2. Server verify terhadap wire hasil build.
    server = SecurePayloadServer(_server_options(vector, standard_keys))
    verified = server.verify(
        expected["headers"], expected["body"], req["method"], req["path"], req["query"]
    )
    assert verified.ok, f"{fname}: verify gagal — {verified.status} {verified.error}"

    # 3. Roundtrip response (bila fixture menyediakannya).
    if not expected.get("response"):
        return

    resp_expected = expected["response"]
    response_server = SecurePayloadServer(
        Options(
            mode=vector["config"]["mode"],
            sign_alg=vector["config"]["signAlg"],
            version=vector["protocol_version"],
            derive_keys=bool(vector["config"].get("deriveKeys")),
            hmac_secret_raw=standard_keys["hmacSecret"],
            aead_key_b64=standard_keys["aeadKeyB64"],
            ed25519_secret_key_server_b64=standard_keys["ed25519ServerSecretB64"],
            clock=lambda: fixed["resp_timestamp"],
            resp_nonce_generator=lambda: fixed["resp_nonce_b64"],
            key_loader=lambda cid, kid: {
                "hmac_secret": standard_keys["hmacSecret"],
                "aead_key_b64": standard_keys["aeadKeyB64"],
                "ed25519_secret_key_server_b64": standard_keys["ed25519ServerSecretB64"],
            },
        )
    )
    resp_headers, resp_body = response_server.build_response(expected["headers"], resp_expected["payload"])
    assert resp_headers == resp_expected["headers"], f"{fname}: response header mismatch"
    assert resp_body == resp_expected["body"], f"{fname}: response body mismatch"

    # 4. Client memverifikasi response tersebut.
    response_client = SecurePayloadClient(_client_options(vector, standard_keys))
    client_verify = response_client.verify_response(resp_headers, resp_body, fixed["nonce_b64"])
    assert client_verify.ok, f"{fname}: verify_response gagal — {client_verify.error}"
    assert client_verify.json == resp_expected["payload"]
