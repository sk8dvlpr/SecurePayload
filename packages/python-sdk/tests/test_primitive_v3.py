"""Conformance primitif protokol v3 — semua docs/fixtures/v3/primitive/*.json.

Target byte-exactness: output fungsi kanonik Python harus identik bit-per-bit
dengan implementasi PHP src/Protocol/*. Bandingkan via hex/b64 string.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securepayload._canonical import (
    aead_nonce_from,
    body_digest_b64,
    build_request_aead_aad,
    canonical_query,
    derive_subkey,
    hmac_message,
    normalize_path,
    resp_aead_nonce_from,
    resp_message,
)

pytestmark = pytest.mark.conformance_v3


def load(v3_root: Path, rel: str):
    with open(v3_root / rel, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_normalize_path(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/normalize-path.json")
    for case in vector["cases"]:
        assert normalize_path(case["input"]) == case["expected"], case["input"]


def test_canonical_query(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/canonical-query.json")
    for case in vector["cases"]:
        assert canonical_query(case["input"]) == case["expected"], case["input"]


def test_body_digest(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/body-digest.json")
    assert body_digest_b64(vector["input"]["json"]) == vector["expected"]["digest_b64"]


def test_hmac_message(v3_root: Path) -> None:
    req = load(v3_root, "primitive/hmac-message.json")
    i = req["input"]
    msg = hmac_message(
        i["version"], i["clientId"], i["keyId"], i["timestamp"],
        i["nonce_b64"], i["method"], i["path"],
        canonical_query(i["query"]), i["body_digest_b64"],
    )
    assert msg == req["expected"]["message"]


def test_resp_message(v3_root: Path) -> None:
    res = load(v3_root, "primitive/resp-message.json")
    i = res["input"]
    msg = resp_message(i["version"], i["req_nonce_b64"], i["resp_timestamp"], i["resp_nonce_b64"], i["body_digest_b64"])
    assert msg == res["expected"]["message"]


def test_aead_nonce_request(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/aead-nonce-request.json")
    i = vector["input"]
    nonce = aead_nonce_from(i["nonce_b64"], i["method"], i["path"], i["query_string"])
    assert nonce.hex() == vector["expected"]["nonce_hex"]


def test_resp_aead_nonce(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/resp-aead-nonce.json")
    nonce = resp_aead_nonce_from(vector["input"]["resp_nonce_b64"], vector["input"]["req_nonce_b64"])
    assert nonce.hex() == vector["expected"]["nonce_hex"]


def test_aead_aad_request(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/aead-aad-request.json")
    i = vector["input"]
    aad = build_request_aead_aad(i["version"], i["timestamp"], {"x-request-id": "trace-abc-123"})
    assert aad == vector["expected"]["aad"]


def test_hkdf_derive(v3_root: Path) -> None:
    vector = load(v3_root, "primitive/hkdf-derive.json")
    for case in vector["cases"]:
        master = bytes.fromhex(case["master_hex"]) if "master_hex" in case else case["master"].encode("utf-8")
        # Fixture berisi label lengkap 'sp-sign-req|v3'; derive_subkey menerima
        # purpose dasar + version numerik (tanpa prefiks 'v').
        base_purpose, _, ver_label = case["purpose"].partition("|")
        out = derive_subkey(master, base_purpose, ver_label[1:], True)
        assert out.hex() == case["expected_hex"], case["purpose"]
