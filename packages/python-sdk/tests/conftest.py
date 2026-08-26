"""Konfigurasi pytest SDK Python SecurePayload.

FIXTURES_ROOT menunjuk ke <repo>/docs/fixtures — naik 3 level dari
packages/python-sdk/tests/conftest.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_ROOT = REPO_ROOT / "docs" / "fixtures"


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def fixtures_root() -> Path:
    assert (FIXTURES_ROOT / "v3").is_dir(), (
        f"Fixture root tidak ditemukan di {FIXTURES_ROOT} — "
        "jalankan pytest dari checkout repo SecurePayload"
    )
    return FIXTURES_ROOT


@pytest.fixture(scope="session")
def v3_root(fixtures_root: Path) -> Path:
    return fixtures_root / "v3"


@pytest.fixture(scope="session")
def standard_keys(v3_root: Path) -> dict:
    """Kunci conformance bersama (docs/fixtures/v3/keys/standard.json)."""
    return load_json(v3_root / "keys" / "standard.json")
