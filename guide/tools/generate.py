#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate SecurePayload bilingual static User Guide into guide/dist/."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from html import escape
from typing import Any, Callable, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
# Repo root when this file is `_tmp_generate_guide.py` or `guide/tools/generate.py`
ROOT = _HERE.parent.parent if (_HERE.name == "tools" and _HERE.parent.name == "guide") else _HERE
GUIDE = ROOT / "guide"
DIST = GUIDE / "dist"
ASSETS_SRC = GUIDE / "assets"
VERSION = "3.2.0"
PROTOCOL = "4"
SITE_BASE = "https://sk8dvlpr.github.io/securepayload/"
GITHUB = "https://github.com/sk8dvlpr/SecurePayload"
ISSUES = f"{GITHUB}/issues/new"

# ---------------------------------------------------------------------------
# Page registry (identical structure ID + EN)
# ---------------------------------------------------------------------------

Page = Dict[str, Any]

PAGES: List[Page] = [
    # Top
    {"slug": "index", "file": "index.html", "group": "home", "cat": "home"},
    {"slug": "basics", "file": "basics.html", "group": "learn", "cat": "basics"},
    {"slug": "choose-setup", "file": "choose-setup.html", "group": "learn", "cat": "setup"},
    {"slug": "installation", "file": "installation.html", "group": "start", "cat": "install"},
    {"slug": "quickstart", "file": "quickstart.html", "group": "start", "cat": "quickstart"},
    {"slug": "keys", "file": "keys.html", "group": "start", "cat": "keys"},
    {"slug": "features", "file": "features/index.html", "group": "features", "cat": "features"},
    # Features
    {"slug": "anti-replay", "file": "features/anti-replay.html", "group": "features", "cat": "features"},
    {"slug": "response", "file": "features/response.html", "group": "features", "cat": "features"},
    {"slug": "file-small", "file": "features/file-small.html", "group": "features", "cat": "features"},
    {"slug": "file-stream", "file": "features/file-stream.html", "group": "features", "cat": "features"},
    {"slug": "file-multipart", "file": "features/file-multipart.html", "group": "features", "cat": "features"},
    {"slug": "webhook", "file": "features/webhook.html", "group": "features", "cat": "features"},
    {"slug": "ed25519", "file": "features/ed25519.html", "group": "features", "cat": "features"},
    {"slug": "hybrid-pq", "file": "features/hybrid-pq.html", "group": "features", "cat": "features"},
    {"slug": "derive-keys", "file": "features/derive-keys.html", "group": "features", "cat": "features"},
    {"slug": "bind-headers", "file": "features/bind-headers.html", "group": "features", "cat": "features"},
    {"slug": "observability", "file": "features/observability.html", "group": "features", "cat": "features"},
    {"slug": "rfc9421", "file": "features/rfc9421.html", "group": "features", "cat": "features"},
    {"slug": "sdk-node-go", "file": "features/sdk-node-go.html", "group": "features", "cat": "features"},
    {"slug": "cli", "file": "features/cli.html", "group": "features", "cat": "features"},
    {"slug": "mtls", "file": "features/mtls.html", "group": "features", "cat": "features"},
    {"slug": "kms", "file": "features/kms.html", "group": "features", "cat": "features"},
    {"slug": "file-storage-delivery", "file": "features/file-storage-delivery.html", "group": "features", "cat": "features"},
    {"slug": "idempotency-compress", "file": "features/idempotency-compress.html", "group": "features", "cat": "features"},
    # Warnings / troubleshooting after features in nav feel, but keep order for prev/next
    {"slug": "warnings", "file": "warnings.html", "group": "ops", "cat": "warnings"},
    {"slug": "troubleshooting", "file": "troubleshooting.html", "group": "ops", "cat": "troubleshooting"},
    # Frameworks
    {"slug": "native", "file": "frameworks/native.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "ci4", "file": "frameworks/ci4.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "laravel", "file": "frameworks/laravel.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "lumen", "file": "frameworks/lumen.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "slim", "file": "frameworks/slim.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "symfony", "file": "frameworks/symfony.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "node", "file": "frameworks/node.html", "group": "frameworks", "cat": "frameworks"},
    {"slug": "go", "file": "frameworks/go.html", "group": "frameworks", "cat": "frameworks"},
    # Reference
    {"slug": "options", "file": "reference/options.html", "group": "reference", "cat": "reference"},
    {"slug": "headers", "file": "reference/headers.html", "group": "reference", "cat": "reference"},
    {"slug": "events", "file": "reference/events.html", "group": "reference", "cat": "reference"},
    {"slug": "exceptions", "file": "reference/exceptions.html", "group": "reference", "cat": "reference"},
    {"slug": "methods", "file": "reference/methods.html", "group": "reference", "cat": "reference"},
    {"slug": "env", "file": "reference/env.html", "group": "reference", "cat": "reference"},
    # Other
    {"slug": "glossary", "file": "glossary.html", "group": "meta", "cat": "glossary"},
    {"slug": "versions", "file": "versions.html", "group": "meta", "cat": "versions"},
    {"slug": "security", "file": "security.html", "group": "meta", "cat": "security"},
    {"slug": "contributing", "file": "contributing.html", "group": "meta", "cat": "contributing"},
]

TITLES: Dict[str, Dict[str, str]] = {
    "index": {"id": "Beranda", "en": "Home"},
    "basics": {"id": "Konsep Dasar", "en": "The Basics"},
    "choose-setup": {"id": "Pilih Mode", "en": "Choose Your Setup"},
    "installation": {"id": "Instalasi", "en": "Installation"},
    "quickstart": {"id": "Mulai Cepat", "en": "Quick Start"},
    "keys": {"id": "Mengelola Kunci", "en": "Managing Keys"},
    "features": {"id": "Fitur & Manfaat", "en": "Features & Benefits"},
    "anti-replay": {"id": "Anti-replay", "en": "Anti-replay"},
    "response": {"id": "Response Dua Arah", "en": "Two-way Response"},
    "file-small": {"id": "File Kecil", "en": "Small Files"},
    "file-stream": {"id": "File Streaming", "en": "File Streaming"},
    "file-multipart": {"id": "File Multipart", "en": "Multipart Files"},
    "webhook": {"id": "Webhook", "en": "Webhooks"},
    "ed25519": {"id": "Ed25519", "en": "Ed25519"},
    "hybrid-pq": {"id": "Hybrid Pasca-kuantum", "en": "Hybrid Post-quantum"},
    "derive-keys": {"id": "deriveKeys", "en": "deriveKeys"},
    "bind-headers": {"id": "bindHeaders", "en": "bindHeaders"},
    "observability": {"id": "Observability", "en": "Observability"},
    "rfc9421": {"id": "RFC 9421", "en": "RFC 9421"},
    "sdk-node-go": {"id": "SDK Node & Go", "en": "Node & Go SDKs"},
    "cli": {"id": "CLI", "en": "CLI"},
    "mtls": {"id": "mTLS", "en": "mTLS"},
    "kms": {"id": "KMS", "en": "KMS"},
    "file-storage-delivery": {"id": "Penyimpanan File", "en": "File Storage & Delivery"},
    "idempotency-compress": {"id": "Idempotency & Compress", "en": "Idempotency & Compress"},
    "warnings": {"id": "Peringatan", "en": "Warnings"},
    "troubleshooting": {"id": "Pemecahan Masalah", "en": "Troubleshooting"},
    "native": {"id": "Native PHP", "en": "Native PHP"},
    "ci4": {"id": "CodeIgniter 4", "en": "CodeIgniter 4"},
    "laravel": {"id": "Laravel", "en": "Laravel"},
    "lumen": {"id": "Lumen", "en": "Lumen"},
    "slim": {"id": "Slim", "en": "Slim"},
    "symfony": {"id": "Symfony", "en": "Symfony"},
    "node": {"id": "Node.js", "en": "Node.js"},
    "go": {"id": "Go", "en": "Go"},
    "options": {"id": "Opsi Konstruktor", "en": "Constructor Options"},
    "headers": {"id": "Header Keamanan", "en": "Security Headers"},
    "events": {"id": "Event Keamanan", "en": "Security Events"},
    "exceptions": {"id": "Exception", "en": "Exceptions"},
    "methods": {"id": "Method Publik", "en": "Public Methods"},
    "env": {"id": "Variabel Env", "en": "Environment Variables"},
    "glossary": {"id": "Kamus Istilah", "en": "Glossary"},
    "versions": {"id": "Versi & Upgrade", "en": "Versions & Upgrading"},
    "security": {"id": "Keamanan & Pelaporan", "en": "Security & Reporting"},
    "contributing": {"id": "Kontribusi & Lisensi", "en": "Contributing & License"},
}

DESCS: Dict[str, Dict[str, str]] = {
    "index": {
        "id": "Kirim data antar-server dengan aman — tidak bisa diubah, tidak bisa dibaca orang lain, tidak bisa diputar ulang.",
        "en": "Send data between servers safely — it cannot be changed, read by others, or replayed.",
    },
    "basics": {
        "id": "Pahami tiga risiko (pemalsuan, penyadapan, replay) dan analogi amplop bersegel, terkunci, serta tiket sekali pakai.",
        "en": "Learn three risks (tampering, eavesdropping, replay) and the sealed envelope, locked envelope, and one-time ticket analogies.",
    },
    "choose-setup": {
        "id": "Wizard interaktif untuk memilih mode hmac/aead/both dan algoritma tanda tangan.",
        "en": "Interactive wizard to pick hmac/aead/both mode and signing algorithm.",
    },
    "installation": {
        "id": "Persyaratan PHP 8.0+, ext-sodium untuk AEAD, dan cara memasang lewat Composer.",
        "en": "PHP 8.0+ requirements, ext-sodium for AEAD, and Composer install steps.",
    },
    "quickstart": {
        "id": "Lima langkah agar request both-mode berhasil dalam sekitar 10 menit.",
        "en": "Five steps to a working both-mode request in about 10 minutes.",
    },
    "keys": {
        "id": "Membuat, menyimpan, dan merotasi kunci HMAC, AEAD, dan Ed25519 dengan aman.",
        "en": "Create, store, and rotate HMAC, AEAD, and Ed25519 keys safely.",
    },
    "features": {
        "id": "Daftar fitur SecurePayload dan manfaatnya untuk API server-to-server.",
        "en": "SecurePayload feature list and benefits for server-to-server APIs.",
    },
    "warnings": {
        "id": "Do/Don't produksi, requireReplayStore, dan checklist sebelum go-live.",
        "en": "Production Do/Don't, requireReplayStore, and a go-live checklist.",
    },
    "troubleshooting": {
        "id": "Gejala verifikasi gagal, kode HTTP, dan FAQ umum.",
        "en": "Failed verification symptoms, HTTP codes, and common FAQ.",
    },
    "glossary": {
        "id": "Kamus istilah: nonce, replay store, KMS, canonical request, dan lainnya.",
        "en": "Glossary: nonce, replay store, KMS, canonical request, and more.",
    },
    "versions": {
        "id": "Library v3.2.0, protocol default 4, dan catatan upgrade.",
        "en": "Library v3.2.0, protocol default 4, and upgrade notes.",
    },
    "security": {
        "id": "Cara melaporkan masalah keamanan. Belum ada audit pihak ketiga.",
        "en": "How to report security issues. No third-party audit yet.",
    },
    "contributing": {
        "id": "Kontribusi, lisensi MIT, dan tautan ke repositori.",
        "en": "Contributing, MIT license, and repository links.",
    },
}

# Default description for remaining pages
for p in PAGES:
    if p["slug"] not in DESCS:
        t = TITLES[p["slug"]]
        DESCS[p["slug"]] = {
            "id": f"Panduan {t['id']} pada SecurePayload v{VERSION}.",
            "en": f"Guide to {t['en']} in SecurePayload v{VERSION}.",
        }

NAV_GROUPS = [
    ("home", {"id": "Beranda", "en": "Home"}, ["index"]),
    ("learn", {"id": "Konsep", "en": "Concepts"}, ["basics", "choose-setup"]),
    ("start", {"id": "Mulai", "en": "Start"}, ["installation", "quickstart", "keys"]),
    ("features", {"id": "Fitur", "en": "Features"}, [
        "features", "anti-replay", "response", "file-small", "file-stream", "file-multipart",
        "webhook", "ed25519", "hybrid-pq", "derive-keys", "bind-headers", "observability",
        "rfc9421", "sdk-node-go", "cli", "mtls", "kms", "file-storage-delivery", "idempotency-compress",
    ]),
    ("ops", {"id": "Operasi", "en": "Ops"}, ["warnings", "troubleshooting"]),
    ("frameworks", {"id": "Framework", "en": "Frameworks"}, [
        "native", "ci4", "laravel", "lumen", "slim", "symfony", "node", "go",
    ]),
    ("reference", {"id": "Referensi", "en": "Reference"}, [
        "options", "headers", "events", "exceptions", "methods", "env",
    ]),
    ("meta", {"id": "Lainnya", "en": "More"}, ["glossary", "versions", "security", "contributing"]),
]

GLOSSARY = {
    "signature": {
        "id": "Segel pada amplop; jika isi berubah, segelnya rusak.",
        "en": "A seal on an envelope; if the contents change, the seal breaks.",
    },
    "encryption": {
        "id": "Mengunci isi agar hanya penerima yang bisa membuka.",
        "en": "Locking the contents so only the receiver can open them.",
    },
    "nonce": {
        "id": "Kode unik sekali pakai pada tiap pesan.",
        "en": "A one-time code attached to every message.",
    },
    "timestamp": {
        "id": "Cap waktu pengiriman; pesan lama ditolak.",
        "en": "The send time; old messages are rejected.",
    },
    "replay": {
        "id": "Orang menyalin pesan sah lalu mengirimnya lagi.",
        "en": "Someone copies a valid message and sends it again.",
    },
    "replay-store": {
        "id": "Buku catatan tiket (nonce) yang sudah dipakai.",
        "en": "A logbook of tickets (nonces) already used.",
    },
    "clock-skew": {
        "id": "Toleransi jika jam dua server tidak persis sama.",
        "en": "Allowed difference between two servers' clocks.",
    },
    "key-id": {
        "id": "Rahasia yang dipakai; nomor versi kuncinya.",
        "en": "The secret in use; and its version number.",
    },
    "kms": {
        "id": "Brankas untuk menyimpan & membungkus kunci.",
        "en": "A vault that stores and wraps keys.",
    },
    "key-wrapping": {
        "id": "Menyimpan kunci di dalam kotak terkunci lain.",
        "en": "Keeping a key inside another locked box.",
    },
    "ed25519": {
        "id": "Pengirim punya kunci pribadi; penerima hanya kunci publik.",
        "en": "Sender holds a private key; receiver only holds a public key.",
    },
    "post-quantum": {
        "id": "Persiapan menghadapi komputer kuantum di masa depan.",
        "en": "Preparation for future quantum computers.",
    },
    "middleware": {
        "id": "Lapisan yang memeriksa request sebelum sampai ke aplikasi.",
        "en": "A layer that checks a request before it reaches your app.",
    },
    "webhook": {
        "id": "Pesan otomatis dari sistem lain ke server Anda.",
        "en": "An automatic message another system sends to your server.",
    },
    "load-balancer": {
        "id": "Pembagi lalu lintas ke beberapa server.",
        "en": "A traffic splitter across several servers.",
    },
    "protocol-version": {
        "id": "“Bahasa” wire yang harus sama di kedua sisi (default 4).",
        "en": "The wire “language” both sides must share (default 4).",
    },
    "canonical-request": {
        "id": "Bentuk baku method/path/query agar tanda tangan cocok.",
        "en": "A normalized method/path/query so signatures match.",
    },
}

# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------


def depth_of(file: str) -> int:
    return file.count("/")


def asset_base(file: str) -> str:
    return "../" * (depth_of(file) + 1) + "assets/"


def href_between(from_file: str, to_file: str) -> str:
    """Relative href from one page file to another within the same lang dir."""
    from_parts = from_file.split("/")
    to_parts = to_file.split("/")
    # both under lang/
    up = len(from_parts) - 1
    return ("../" * up) + "/".join(to_parts) if up else to_file


def page_by_slug(slug: str) -> Page:
    for p in PAGES:
        if p["slug"] == slug:
            return p
    raise KeyError(slug)


def callout(kind: str, title: str, body: str) -> str:
    icons = {"info": "i", "tip": "✓", "warn": "!", "danger": "‼"}
    return (
        f'<aside class="callout {kind}" role="note">'
        f'<span class="icon" aria-hidden="true">{icons.get(kind, "i")}</span>'
        f'<div><div class="label">{escape(title)}</div><p>{body}</p></div></aside>'
    )


def code_block(lang: str, code: str, copy_label: str = "Copy") -> str:
    return (
        f'<div class="code"><span class="lang">{escape(lang)}</span>'
        f'<button type="button" data-copy aria-label="{escape(copy_label)}">{escape(copy_label)}</button>'
        f"<pre><code>{escape(code)}</code></pre></div>"
    )


def term(key: str, text: str) -> str:
    return f'<button type="button" class="term" data-term="{escape(key)}">{escape(text)}</button>'


def h2(anchor: str, text: str) -> str:
    return f'<h2 id="{escape(anchor)}">{escape(text)}</h2>'


def strip_tags(html: str) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ---------------------------------------------------------------------------
# Content builders
# ---------------------------------------------------------------------------


def body_index(lang: str) -> str:
    if lang == "id":
        return f"""
<p class="eyebrow">SecurePayload v{VERSION}</p>
<h1>Kirim data antar-server dengan aman</h1>
<p>Tidak bisa diubah, tidak bisa dibaca orang lain, tidak bisa diputar ulang.</p>
<p class="btn-row">
  <a class="btn btn-primary" href="quickstart.html">Mulai dalam 10 menit</a>
  <a class="btn btn-secondary" href="basics.html">Pahami dulu konsepnya</a>
</p>
{h2("manfaat", "Tiga perlindungan")}
<div class="path-grid">
  <a class="path-card" href="basics.html"><span class="num">1</span><h3>Pemalsuan</h3><p>Segel digital rusak jika isi diubah.</p></a>
  <a class="path-card" href="basics.html"><span class="num">2</span><h3>Penyadapan</h3><p>Isi dikunci (AEAD) di mode aead/both.</p></a>
  <a class="path-card" href="features/anti-replay.html"><span class="num">3</span><h3>Replay</h3><p>Tiket sekali pakai + buku daftar.</p></a>
</div>
{h2("jalur", "Pilih jalur belajar")}
<div class="path-grid">
  <a class="path-card" href="basics.html"><span class="num">A</span><h3>Saya ingin paham dulu</h3><p>Konsep tanpa kode.</p><span class="go">Mulai →</span></a>
  <a class="path-card" href="installation.html"><span class="num">B</span><h3>Saya developer</h3><p>Instalasi → Mulai cepat.</p><span class="go">Mulai →</span></a>
  <a class="path-card" href="warnings.html"><span class="num">C</span><h3>Saya ops/keamanan</h3><p>Peringatan & checklist.</p><span class="go">Mulai →</span></a>
</div>
{h2("siapa", "Siapa yang cocok?")}
<p>API server-to-server, webhook masuk, atau klien yang harus membuktikan identitas dengan kunci bersama atau Ed25519.</p>
{callout("warn", "Kapan tidak", "Bukan pengganti login pengguna akhir atau OAuth penuh. Mode <code>hmac</code> tidak mengenkripsi.")}
{h2("status", "Status")}
<ul>
  <li>Library <strong>v{VERSION}</strong> · protokol default <strong>{PROTOCOL}</strong></li>
  <li>PHP CI-tested <strong>8.0–8.5</strong> · lisensi <strong>MIT</strong></li>
  <li>Belum ada audit keamanan pihak ketiga</li>
  <li><a href="{GITHUB}">GitHub</a> · Packagist <code>sk8dvlpr/securepayload</code></li>
</ul>
"""
    return f"""
<p class="eyebrow">SecurePayload v{VERSION}</p>
<h1>Send data between servers safely</h1>
<p>It cannot be changed, read by others, or replayed.</p>
<p class="btn-row">
  <a class="btn btn-primary" href="quickstart.html">Start in 10 minutes</a>
  <a class="btn btn-secondary" href="basics.html">Learn the concepts first</a>
</p>
{h2("benefits", "Three protections")}
<div class="path-grid">
  <a class="path-card" href="basics.html"><span class="num">1</span><h3>Tampering</h3><p>The digital seal breaks if contents change.</p></a>
  <a class="path-card" href="basics.html"><span class="num">2</span><h3>Eavesdropping</h3><p>Contents are locked (AEAD) in aead/both.</p></a>
  <a class="path-card" href="features/anti-replay.html"><span class="num">3</span><h3>Replay</h3><p>One-time tickets plus a logbook.</p></a>
</div>
{h2("paths", "Choose a learning path")}
<div class="path-grid">
  <a class="path-card" href="basics.html"><span class="num">A</span><h3>I want concepts first</h3><p>No code yet.</p><span class="go">Start →</span></a>
  <a class="path-card" href="installation.html"><span class="num">B</span><h3>I am a developer</h3><p>Install → Quick start.</p><span class="go">Start →</span></a>
  <a class="path-card" href="warnings.html"><span class="num">C</span><h3>I run ops/security</h3><p>Warnings & checklist.</p><span class="go">Start →</span></a>
</div>
{h2("who", "Who is this for?")}
<p>Server-to-server APIs, inbound webhooks, or clients that must prove identity with a shared secret or Ed25519.</p>
{callout("warn", "When not", "Not a replacement for end-user login or full OAuth. Mode <code>hmac</code> does not encrypt.")}
{h2("status", "Status")}
<ul>
  <li>Library <strong>v{VERSION}</strong> · default protocol <strong>{PROTOCOL}</strong></li>
  <li>PHP CI-tested <strong>8.0–8.5</strong> · <strong>MIT</strong> license</li>
  <li>No third-party security audit yet</li>
  <li><a href="{GITHUB}">GitHub</a> · Packagist <code>sk8dvlpr/securepayload</code></li>
</ul>
"""


def body_basics(lang: str) -> str:
    if lang == "id":
        return f"""
<p>Anda akan belajar tiga risiko dan cara SecurePayload menjaganya dengan analogi sederhana.</p>
{h2("masalah", "Masalah yang dipecahkan")}
<ol>
  <li><strong>Pemalsuan</strong> — orang mengubah body di tengah jalan.</li>
  <li><strong>Penyadapan</strong> — orang membaca isi rahasia.</li>
  <li><strong>Replay</strong> — orang mengirim ulang pesan sah.</li>
</ol>
{h2("analogi", "Analogi tetap")}
<ul>
  <li>{term("signature", "Amplop bersegel")} = tanda tangan digital (HMAC / Ed25519).</li>
  <li>{term("encryption", "Amplop terkunci")} = enkripsi AEAD (XChaCha20-Poly1305).</li>
  <li>{term("nonce", "Tiket bernomor sekali pakai")} + {term("timestamp", "tanggal")} = nonce + timestamp.</li>
  <li>{term("replay-store", "Buku daftar tiket")} = replay store.</li>
  <li>{term("kms", "Brankas kunci")} = KMS.</li>
</ul>
{h2("mode", "Tiga mode")}
<div class="table-wrap"><table>
<thead><tr><th>Mode</th><th>Arti ramah</th><th>Kode</th></tr></thead>
<tbody>
<tr><td>Tanda tangan saja</td><td>Segel, isi masih bisa dibaca</td><td><code>hmac</code></td></tr>
<tr><td>Kunci saja</td><td>Isi terkunci, tanpa segel HMAC terpisah</td><td><code>aead</code></td></tr>
<tr><td>Keduanya</td><td>Terkunci + tersegel (disarankan)</td><td><code>both</code></td></tr>
</tbody></table></div>
{h2("alur", "Alur singkat")}
<p>Klien membangun header keamanan + body → server memverifikasi dari method/path/query <strong>miliknya sendiri</strong> → menolak jika segel rusak, kunci gagal, atau tiket sudah dipakai.</p>
{callout("danger", "Penting", "Jangan percaya header <code>X-Canonical-Request</code> untuk verifikasi. Itu hanya petunjuk debug.")}
<p><a href="choose-setup.html">Selanjutnya: Pilih Mode →</a></p>
"""
    return f"""
<p>You will learn three risks and how SecurePayload addresses them with simple analogies.</p>
{h2("problem", "Problem it solves")}
<ol>
  <li><strong>Tampering</strong> — someone changes the body in transit.</li>
  <li><strong>Eavesdropping</strong> — someone reads secret contents.</li>
  <li><strong>Replay</strong> — someone resends a valid message.</li>
</ol>
{h2("analogies", "Fixed analogies")}
<ul>
  <li>{term("signature", "Sealed envelope")} = digital signature (HMAC / Ed25519).</li>
  <li>{term("encryption", "Locked envelope")} = AEAD encryption (XChaCha20-Poly1305).</li>
  <li>{term("nonce", "One-time numbered ticket")} + {term("timestamp", "date")} = nonce + timestamp.</li>
  <li>{term("replay-store", "Ticket logbook")} = replay store.</li>
  <li>{term("kms", "Key vault")} = KMS.</li>
</ul>
{h2("modes", "Three modes")}
<div class="table-wrap"><table>
<thead><tr><th>Mode</th><th>Plain meaning</th><th>Code</th></tr></thead>
<tbody>
<tr><td>Sign only</td><td>Seal; body may still be readable</td><td><code>hmac</code></td></tr>
<tr><td>Encrypt only</td><td>Locked contents; no separate HMAC seal</td><td><code>aead</code></td></tr>
<tr><td>Both</td><td>Locked + sealed (recommended)</td><td><code>both</code></td></tr>
</tbody></table></div>
{h2("flow", "Short flow")}
<p>Client builds security headers + body → server verifies using its <strong>own</strong> method/path/query → rejects if the seal breaks, decrypt fails, or the ticket was already used.</p>
{callout("danger", "Important", "Never trust the <code>X-Canonical-Request</code> header for verification. It is a debug hint only.")}
<p><a href="choose-setup.html">Next: Choose Your Setup →</a></p>
"""


def body_choose_setup(lang: str) -> str:
    if lang == "id":
        q = [
            ("secret", "Apakah isi data rahasia?", "Ya, harus dikunci", "Tidak, cukup segel"),
            ("shared", "Apakah penerima boleh menyimpan kunci yang sama?", "Ya, shared secret OK", "Tidak, lebih suka kunci publik"),
            ("nonrep", "Perlu bukti pengirim (non-repudiation)?", "Ya, Ed25519", "Tidak perlu"),
            ("lb", "Ada banyak server di belakang load balancer?", "Ya", "Tidak / satu host"),
        ]
        copy_title = "Pilih Mode yang Tepat"
        lead = "Jawab empat pertanyaan. Hasilnya merekomendasikan mode dan algoritma tanda tangan."
        result_h = "Rekomendasi"
        mode_l, sign_l = "Mode", "Tanda tangan (signAlg)"
        replay_note = "Karena ada load balancer, setel <code>replayStore</code> terpusat dan pertimbangkan <code>requireReplayStore</code>."
        reset = "Ulangi"
        table_h = "Perbandingan singkat"
    else:
        q = [
            ("secret", "Is the payload secret?", "Yes, lock it", "No, seal is enough"),
            ("shared", "May the receiver keep the same secret?", "Yes, shared secret OK", "No, prefer public keys"),
            ("nonrep", "Need sender proof (non-repudiation)?", "Yes, Ed25519", "Not needed"),
            ("lb", "Many servers behind a load balancer?", "Yes", "No / single host"),
        ]
        copy_title = "Choose the Right Setup"
        lead = "Answer four questions. The result recommends mode and signing algorithm."
        result_h = "Recommendation"
        mode_l, sign_l = "Mode", "Signing (signAlg)"
        replay_note = "Because of a load balancer, configure a shared <code>replayStore</code> and consider <code>requireReplayStore</code>."
        reset = "Start over"
        table_h = "Quick comparison"

    steps = ""
    for key, question, yes, no in q:
        steps += f"""
<div data-wizard-step="{key}">
  <h3>{escape(question)}</h3>
  <p class="btn-row">
    <button type="button" class="btn btn-primary" data-wizard-answer="yes">{escape(yes)}</button>
    <button type="button" class="btn btn-secondary" data-wizard-answer="no">{escape(no)}</button>
  </p>
</div>"""

    return f"""
<p>{escape(lead)}</p>
<div class="wizard" data-wizard data-wizard-rules="builtin">
{steps}
  <div data-wizard-result hidden>
    <h3>{escape(result_h)}</h3>
    <p>{escape(mode_l)}: <strong data-rec-mode></strong></p>
    <p>{escape(sign_l)}: <strong data-rec-sign></strong></p>
    <p class="replay-hint">{replay_note}</p>
    <p class="btn-row">
      <a class="btn btn-primary" href="installation.html">{"Instalasi" if lang == "id" else "Installation"} →</a>
      <button type="button" class="btn btn-secondary" data-wizard-reset>{escape(reset)}</button>
    </p>
  </div>
</div>
{h2("compare", table_h)}
<div class="table-wrap"><table>
<thead><tr><th>Mode</th><th>{"Manfaat" if lang=="id" else "Benefit"}</th><th>{"Perlu" if lang=="id" else "Needs"}</th></tr></thead>
<tbody>
<tr><td><code>hmac</code></td><td>{"Segel saja" if lang=="id" else "Seal only"}</td><td>HMAC ≥32 chars</td></tr>
<tr><td><code>aead</code></td><td>{"Kunci saja" if lang=="id" else "Encrypt only"}</td><td>AEAD 32-byte + sodium</td></tr>
<tr><td><code>both</code></td><td>{"Segel + kunci" if lang=="id" else "Seal + encrypt"}</td><td>Keduanya</td></tr>
</tbody></table></div>
{callout("info", "signAlg", "hmac | ed25519 | hybrid-mldsa44-ed25519 — ditentukan konfigurasi server (anti-downgrade).")}
<details class="acc"><summary>{"Lanjutan" if lang=="id" else "Advanced"}</summary>
<div class="acc-body">
<p><code>ed25519</code>, hybrid PQ, <code>deriveKeys</code>, <code>bindHeaders</code> — lihat halaman Fitur.</p>
</div></details>
"""


def body_installation(lang: str) -> str:
    check = "php -v\nphp -m | findstr sodium" if lang == "id" else "php -v\nphp -m | grep sodium"
    if lang == "id":
        return f"""
<p>Anda akan memasang library dan mengecek ekstensi yang dibutuhkan.</p>
{h2("butuh", "Kebutuhan")}
<ul>
  <li>PHP <strong>≥ 8.0</strong> (CI menguji 8.0–8.5)</li>
  <li><code>ext-json</code>, <code>ext-hash</code></li>
  <li><code>ext-sodium</code> wajib untuk mode <code>aead</code>/<code>both</code> dan Ed25519</li>
  <li>Opsional: <code>ext-curl</code>, PSR-18, PSR-16, SDK KMS cloud</li>
</ul>
{h2("cek", "Cek di mesin Anda")}
{code_block("bash", check, "Salin")}
{h2("pasang", "Pasang lewat Composer")}
{code_block("bash", "composer require sk8dvlpr/securepayload", "Salin")}
<p>Jika berhasil, paket muncul di <code>vendor/sk8dvlpr/securepayload</code>.</p>
{callout("tip", "Tips", "Hybrid ML-DSA membutuhkan <code>pqSigner</code> dari aplikasi Anda — tidak dibundle.")}
<p><a href="quickstart.html">Selanjutnya: Mulai Cepat →</a></p>
"""
    return f"""
<p>You will install the library and check required extensions.</p>
{h2("needs", "Requirements")}
<ul>
  <li>PHP <strong>≥ 8.0</strong> (CI tests 8.0–8.5)</li>
  <li><code>ext-json</code>, <code>ext-hash</code></li>
  <li><code>ext-sodium</code> required for <code>aead</code>/<code>both</code> and Ed25519</li>
  <li>Optional: <code>ext-curl</code>, PSR-18, PSR-16, cloud KMS SDKs</li>
</ul>
{h2("check", "Check on your machine")}
{code_block("bash", check, "Copy")}
{h2("install", "Install with Composer")}
{code_block("bash", "composer require sk8dvlpr/securepayload", "Copy")}
<p>On success, the package appears under <code>vendor/sk8dvlpr/securepayload</code>.</p>
{callout("tip", "Tip", "Hybrid ML-DSA needs a <code>pqSigner</code> from your app — it is not bundled.")}
<p><a href="quickstart.html">Next: Quick Start →</a></p>
"""


def body_quickstart(lang: str) -> str:
    php_client = """<?php
use SecurePayload\\SecurePayload;

// TEST keys only — never use in production
$hmac = str_repeat('a', 32);
$aead = base64_encode(random_bytes(32));

$sp = new SecurePayload([
  'mode' => 'both',
  'clientId' => 'demo',
  'keyId' => 'v1',
  'hmacSecretRaw' => $hmac,
  'aeadKeyB64' => $aead,
]);

[$headers, $body] = $sp->buildHeadersAndBody(
  'https://example.test/api/orders', 'POST',
  ['orderId' => 1]
);
"""
    php_server = """<?php
$sp = new SecurePayload([
  'mode' => 'both',
  'keyLoader' => function ($cid, $kid) use ($hmac, $aead) {
    return ['hmacSecret' => $hmac, 'aeadKeyB64' => $aead];
  },
  // multi-server: inject replayStore + requireReplayStore
]);

$result = $sp->verify($headers, $body, 'POST', '/api/orders', '');
// $result['ok'] === true on success
"""
    if lang == "id":
        return f"""
<p>Target: request <code>both</code> berhasil dalam ≤ 10 menit. Kunci di bawah hanya untuk uji.</p>
<ol class="stepper">
  <li data-n="1"><strong>Buat kunci uji</strong><span>HMAC ≥ 32 karakter; AEAD tepat 32 byte (base64).</span></li>
  <li data-n="2"><strong>Sisi pengirim</strong><span>buildHeadersAndBody.</span></li>
  <li data-n="3"><strong>Sisi penerima</strong><span>verify dengan method/path/query server.</span></li>
  <li data-n="4"><strong>Kirim request</strong><span>Header X-* + body.</span></li>
  <li data-n="5"><strong>Uji rusak</strong><span>Ubah body → harus ditolak.</span></li>
</ol>
{h2("klien", "Contoh klien")}
{code_block("php", php_client, "Salin")}
{h2("server", "Contoh server")}
{code_block("php", php_server, "Salin")}
{callout("danger", "Jangan", "Jangan ambil method/path/query dari <code>X-Canonical-Request</code>.")}
{callout("warn", "Multi-server", "Cache file bawaan tidak dibagi. Pakai <code>replayStore</code> + <code>requireReplayStore</code>.")}
<p><a href="keys.html">Selanjutnya: Mengelola Kunci →</a></p>
"""
    return f"""
<p>Goal: a working <code>both</code> request in ≤ 10 minutes. Keys below are for tests only.</p>
<ol class="stepper">
  <li data-n="1"><strong>Create test keys</strong><span>HMAC ≥ 32 chars; AEAD exactly 32 bytes (base64).</span></li>
  <li data-n="2"><strong>Sender side</strong><span>buildHeadersAndBody.</span></li>
  <li data-n="3"><strong>Receiver side</strong><span>verify with the server's method/path/query.</span></li>
  <li data-n="4"><strong>Send the request</strong><span>X-* headers + body.</span></li>
  <li data-n="5"><strong>Tamper test</strong><span>Change the body → must fail.</span></li>
</ol>
{h2("client", "Client example")}
{code_block("php", php_client, "Copy")}
{h2("server", "Server example")}
{code_block("php", php_server, "Copy")}
{callout("danger", "Don't", "Do not take method/path/query from <code>X-Canonical-Request</code>.")}
{callout("warn", "Multi-server", "The default file cache is not shared. Use <code>replayStore</code> + <code>requireReplayStore</code>.")}
<p><a href="keys.html">Next: Managing Keys →</a></p>
"""


def body_keys(lang: str) -> str:
    if lang == "id":
        return f"""
{h2("buat", "Cara membuat kunci")}
<ul>
  <li>HMAC secret: minimal <strong>32 karakter</strong>.</li>
  <li>AEAD key: tepat <strong>32 byte</strong>, disimpan sebagai base64.</li>
  <li>Ed25519: pasangan kunci; request memakai pasangan <strong>klien</strong>; response memakai pasangan <strong>server</strong>.</li>
</ul>
{code_block("bash", "composer exec securepayload keys:generate", "Salin")}
{h2("simpan", "Tempat menyimpan")}
<p>Env (<code>EnvKeyProvider</code>), database (<code>DbKeyProvider</code>), atau {term("kms", "brankas KMS")}.</p>
{callout("danger", "Jangan", "Jangan commit kunci ke git, jangan kirim lewat chat, jangan log secret.")}
{h2("rotasi", "Rotasi")}
<p><code>KeyManager::rotateKey()</code> / CLI <code>keys:rotate</code> mendukung masa tenggang (<code>useKeyLifecycle</code>).</p>
{callout("warn", "LocalKms", "Hanya untuk pengembangan. Produksi: Vault/AWS/GCP/Azure.")}
<p><a href="features/index.html">Selanjutnya: Fitur →</a></p>
"""
    return f"""
{h2("create", "How to create keys")}
<ul>
  <li>HMAC secret: at least <strong>32 characters</strong>.</li>
  <li>AEAD key: exactly <strong>32 bytes</strong>, stored as base64.</li>
  <li>Ed25519: key pairs; requests use the <strong>client</strong> pair; responses use the <strong>server</strong> pair.</li>
</ul>
{code_block("bash", "composer exec securepayload keys:generate", "Copy")}
{h2("store", "Where to store")}
<p>Env (<code>EnvKeyProvider</code>), database (<code>DbKeyProvider</code>), or a {term("kms", "KMS vault")}.</p>
{callout("danger", "Don't", "Do not commit keys to git, send them in chat, or log secrets.")}
{h2("rotate", "Rotation")}
<p><code>KeyManager::rotateKey()</code> / CLI <code>keys:rotate</code> support a grace period (<code>useKeyLifecycle</code>).</p>
{callout("warn", "LocalKms", "Dev only. Production: Vault/AWS/GCP/Azure.")}
<p><a href="features/index.html">Next: Features →</a></p>
"""


def body_warnings(lang: str) -> str:
    if lang == "id":
        dos = [
            ("⛔", "Samakan versi protokol di klien & server (default 4)."),
            ("⛔", "Server wajib memakai method/path/query dari request sendiri."),
            ("⛔", "Multi-server: <code>replayStore</code> terpusat + <code>requireReplayStore</code>."),
            ("⛔", "HTTPS di produksi."),
            ("⚠️", "HMAC ≥ 32 chars; AEAD 32 byte."),
            ("⚠️", "<code>deriveKeys</code> dan <code>bindHeaders</code> harus sama di kedua sisi."),
            ("💡", "Response mengikuti <code>signAlg</code> — bukan selalu HMAC."),
        ]
        donts = [
            ("⛔", "Jangan percaya <code>X-Canonical-Request</code> untuk verifikasi."),
            ("⛔", "Jangan simpan private Ed25519 request di server."),
            ("⛔", "Jangan log secret / plaintext."),
            ("⚠️", "Jangan andalkan cache file bawaan di belakang load balancer."),
            ("⚠️", "Jangan pakai <code>LocalKms</code> di produksi."),
            ("💡", "Jangan anggap library sudah diaudit pihak ketiga — belum."),
        ]
        checklist = [
            ("proto", "Protocol version sama di kedua sisi"),
            ("https", "HTTPS wajib"),
            ("replay", "replayStore terpusat jika multi-server"),
            ("require", "requireReplayStore diaktifkan di multi-server"),
            ("keys", "Kunci dari env/KMS, bukan hardcode"),
            ("signalg", "signAlg ditetapkan di server"),
            ("audit", "Tim paham belum ada audit pihak ketiga"),
        ]
        return f"""
{h2("do", "Wajib / Do")}
<ul>{''.join(f'<li><span aria-hidden="true">{i}</span> {t}</li>' for i,t in dos)}</ul>
{h2("dont", "Jangan / Don't")}
<ul>{''.join(f'<li><span aria-hidden="true">{i}</span> {t}</li>' for i,t in donts)}</ul>
{h2("checklist", "Daftar periksa produksi")}
<p>Centang disimpan di browser (localStorage) bila tersedia.</p>
<ul data-checklist="production">
{''.join(f'<li><label><input type="checkbox" name="{k}"> {t}</label></li>' for k,t in checklist)}
</ul>
<p><button type="button" class="btn btn-secondary" data-checklist-reset>Reset checklist</button></p>
{callout("info", "Default", "replayTtl=120, clockSkew=60. Jendela memori nonce = replayTtl + clockSkew.")}
<p><a href="troubleshooting.html">Selanjutnya: Troubleshooting →</a></p>
"""
    dos = [
        ("⛔", "Keep protocol version identical on client & server (default 4)."),
        ("⛔", "Server must use its own method/path/query."),
        ("⛔", "Multi-server: shared <code>replayStore</code> + <code>requireReplayStore</code>."),
        ("⛔", "HTTPS in production."),
        ("⚠️", "HMAC ≥ 32 chars; AEAD 32 bytes."),
        ("⚠️", "<code>deriveKeys</code> and <code>bindHeaders</code> must match both sides."),
        ("💡", "Response follows <code>signAlg</code> — not always HMAC."),
    ]
    donts = [
        ("⛔", "Do not trust <code>X-Canonical-Request</code> for verification."),
        ("⛔", "Do not store the request Ed25519 private key on the server."),
        ("⛔", "Do not log secrets / plaintext."),
        ("⚠️", "Do not rely on the default file cache behind a load balancer."),
        ("⚠️", "Do not use <code>LocalKms</code> in production."),
        ("💡", "Do not assume a third-party audit exists — none yet."),
    ]
    checklist = [
        ("proto", "Protocol version matches both sides"),
        ("https", "HTTPS required"),
        ("replay", "Shared replayStore if multi-server"),
        ("require", "requireReplayStore enabled for multi-server"),
        ("keys", "Keys from env/KMS, not hard-coded"),
        ("signalg", "signAlg set by the server"),
        ("audit", "Team knows there is no third-party audit yet"),
    ]
    return f"""
{h2("do", "Do")}
<ul>{''.join(f'<li><span aria-hidden="true">{i}</span> {t}</li>' for i,t in dos)}</ul>
{h2("dont", "Don't")}
<ul>{''.join(f'<li><span aria-hidden="true">{i}</span> {t}</li>' for i,t in donts)}</ul>
{h2("checklist", "Production checklist")}
<p>Checks persist in the browser (localStorage) when available.</p>
<ul data-checklist="production">
{''.join(f'<li><label><input type="checkbox" name="{k}"> {t}</label></li>' for k,t in checklist)}
</ul>
<p><button type="button" class="btn btn-secondary" data-checklist-reset>Reset checklist</button></p>
{callout("info", "Defaults", "replayTtl=120, clockSkew=60. Nonce memory window = replayTtl + clockSkew.")}
<p><a href="troubleshooting.html">Next: Troubleshooting →</a></p>
"""


def body_troubleshooting(lang: str) -> str:
    rows_id = [
        ("401 / tanda tangan invalid", "Segel tidak cocok", "Secret beda / body berubah / path beda", "Samakan kunci; cek method/path/query"),
        ("401 / replay detected", "Tiket sudah dipakai", "Request diulang; store file multi-host", "Nonce baru; replayStore terpusat"),
        ("401 / timestamp", "Di luar jendela waktu", "Jam server beda", "NTP; naikkan clockSkew hati-hati"),
        ("422 / decrypt failed", "Amplop terkunci gagal dibuka", "AEAD key / AAD / bindHeaders beda", "Samakan kunci & bindHeaders"),
        ("500 / sodium", "Ekstensi hilang", "Mode aead/both tanpa sodium", "Aktifkan ext-sodium"),
    ]
    rows_en = [
        ("401 / invalid signature", "Seal mismatch", "Different secret / changed body / path", "Match keys; check method/path/query"),
        ("401 / replay detected", "Ticket already used", "Retried request; file store multi-host", "Fresh nonce; shared replayStore"),
        ("401 / timestamp", "Outside time window", "Clock drift", "NTP; raise clockSkew carefully"),
        ("422 / decrypt failed", "Locked envelope won't open", "AEAD key / AAD / bindHeaders mismatch", "Match keys & bindHeaders"),
        ("500 / sodium", "Missing extension", "aead/both without sodium", "Enable ext-sodium"),
    ]
    rows = rows_id if lang == "id" else rows_en
    table = '<div class="table-wrap"><table><thead><tr><th>Symptom</th><th>Meaning</th><th>Likely cause</th><th>Fix</th></tr></thead><tbody>'
    for a, b, c, d in rows:
        table += f"<tr><td>{a}</td><td>{b}</td><td>{c}</td><td>{d}</td></tr>"
    table += "</tbody></table></div>"
    if lang == "id":
        return f"""
{h2("tabel", "Gejala → perbaikan")}
{table}
{h2("faq", "FAQ")}
<details class="acc"><summary>Kenapa ditolak padahal kunci sudah benar?</summary><div class="acc-body"><p>Path dinormalisasi beda, query order, atau body digeser proxy. Samakan canonical di kedua sisi.</p></div></details>
<details class="acc"><summary>Aman di belakang load balancer?</summary><div class="acc-body"><p>Ya, jika replayStore terbagi (Redis/Memcached) dan requireReplayStore aktif.</p></div></details>
<details class="acc"><summary>Bisa tanpa enkripsi?</summary><div class="acc-body"><p>Ya — mode <code>hmac</code>. Isi tetap terbaca.</p></div></details>
<details class="acc"><summary>Response selalu HMAC?</summary><div class="acc-body"><p>Tidak. Response mengikuti <code>signAlg</code> (HMAC, Ed25519 server, atau hybrid).</p></div></details>
<details class="acc"><summary>Default replayTtl / clockSkew?</summary><div class="acc-body"><p>120 dan 60 detik.</p></div></details>
<details class="acc"><summary>X-Canonical-Request untuk verify?</summary><div class="acc-body"><p>Tidak. Hanya debug.</p></div></details>
<details class="acc"><summary>Upgrade v3 → v4?</summary><div class="acc-body"><p>Samakan <code>version</code> di kedua sisi; lihat CHANGELOG untuk wire multipart.</p></div></details>
<details class="acc"><summary>Debug aman?</summary><div class="acc-body"><p>CLI <code>debug:verify</code> dan <code>test:roundtrip</code> — jangan cetak secret.</p></div></details>
<details class="acc"><summary>Hybrid tanpa pqSigner?</summary><div class="acc-body"><p>Gagal. Sediakan implementasi dari aplikasi.</p></div></details>
<details class="acc"><summary>File kecil vs stream?</summary><div class="acc-body"><p>In-memory ≈ ≤10MB; streaming untuk file besar.</p></div></details>
<details class="acc"><summary>PSR-16 selalu atomik?</summary><div class="acc-body"><p>Tidak. Prefer cache dengan <code>add()</code> atomik.</p></div></details>
<details class="acc"><summary>Sudah diaudit?</summary><div class="acc-body"><p>Belum ada audit pihak ketiga.</p></div></details>
"""
    return f"""
{h2("table", "Symptom → fix")}
{table}
{h2("faq", "FAQ")}
<details class="acc"><summary>Rejected even with correct keys?</summary><div class="acc-body"><p>Normalized path differs, query order, or a proxy mutated the body. Align canonicalization.</p></div></details>
<details class="acc"><summary>Safe behind a load balancer?</summary><div class="acc-body"><p>Yes, with a shared replayStore (Redis/Memcached) and requireReplayStore.</p></div></details>
<details class="acc"><summary>Without encryption?</summary><div class="acc-body"><p>Yes — mode <code>hmac</code>. The body stays readable.</p></div></details>
<details class="acc"><summary>Is response always HMAC?</summary><div class="acc-body"><p>No. Response follows <code>signAlg</code> (HMAC, server Ed25519, or hybrid).</p></div></details>
<details class="acc"><summary>Default replayTtl / clockSkew?</summary><div class="acc-body"><p>120 and 60 seconds.</p></div></details>
<details class="acc"><summary>Use X-Canonical-Request to verify?</summary><div class="acc-body"><p>No. Debug only.</p></div></details>
<details class="acc"><summary>Upgrade v3 → v4?</summary><div class="acc-body"><p>Match <code>version</code> on both sides; see CHANGELOG for multipart wire.</p></div></details>
<details class="acc"><summary>Safe debugging?</summary><div class="acc-body"><p>CLI <code>debug:verify</code> and <code>test:roundtrip</code> — never print secrets.</p></div></details>
<details class="acc"><summary>Hybrid without pqSigner?</summary><div class="acc-body"><p>It fails closed. Provide an app implementation.</p></div></details>
<details class="acc"><summary>Small file vs stream?</summary><div class="acc-body"><p>In-memory ≈ ≤10MB; streaming for large files.</p></div></details>
<details class="acc"><summary>Is PSR-16 always atomic?</summary><div class="acc-body"><p>No. Prefer caches with atomic <code>add()</code>.</p></div></details>
<details class="acc"><summary>Audited?</summary><div class="acc-body"><p>No third-party audit yet.</p></div></details>
"""


FEATURE_SPECS: List[Tuple[str, Dict[str, str], Dict[str, str], str]] = [
    ("anti-replay", {
        "id": "Melindungi dari pesan sah yang dikirim ulang.",
        "en": "Stops valid messages from being sent again.",
    }, {
        "id": "Nonce + timestamp + replay store (buku tiket).",
        "en": "Nonce + timestamp + replay store (ticket logbook).",
    }, "checkReplay / replayStore / requireReplayStore"),
    ("response", {
        "id": "Server membalas dengan segel yang terikat ke nonce request.",
        "en": "Server replies with a seal bound to the request nonce.",
    }, {
        "id": "buildResponse / verifyResponse — mengikuti signAlg.",
        "en": "buildResponse / verifyResponse — follows signAlg.",
    }, "buildResponse, verifyResponse"),
    ("file-small", {
        "id": "Kirim lampiran kecil di JSON (_attachment).",
        "en": "Send small attachments in JSON (_attachment).",
    }, {
        "id": "Cocok ≤ ~10MB. Validasi ekstensi/MIME tersedia.",
        "en": "Suitable ≤ ~10MB. Extension/MIME validation available.",
    }, "buildFilePayload / verifyFilePayload"),
    ("file-stream", {
        "id": "Streaming secretstream per-chunk untuk file besar.",
        "en": "Per-chunk secretstream for large files.",
    }, {
        "id": "RAM ≈ satu chunk. Gagal → plaintext parsial dihapus.",
        "en": "RAM ≈ one chunk. Failure deletes partial plaintext.",
    }, "buildFileStream / verifyFileStream"),
    ("file-multipart", {
        "id": "Manifest aman + ciphertext dalam satu request multipart (wire v4).",
        "en": "Secure manifest + ciphertext in one multipart request (wire v4).",
    }, {
        "id": "Header X-SP-Multipart menandai aliran.",
        "en": "X-SP-Multipart marks the flow.",
    }, "buildFileStreamMultipartRequest"),
    ("webhook", {
        "id": "Verifikasi webhook masuk dengan aturan yang sama.",
        "en": "Verify inbound webhooks with the same rules.",
    }, {
        "id": "WebhookVerifier di src/Webhook.",
        "en": "WebhookVerifier in src/Webhook.",
    }, "WebhookVerifier"),
    ("ed25519", {
        "id": "Tanda tangan asimetris: klien private, server public.",
        "en": "Asymmetric signing: client private, server public.",
    }, {
        "id": "Response Ed25519 memakai keypair server terpisah.",
        "en": "Response Ed25519 uses a separate server keypair.",
    }, "signAlg=ed25519"),
    ("hybrid-pq", {
        "id": "Hybrid ML-DSA44 + Ed25519 untuk persiapan pasca-kuantum.",
        "en": "Hybrid ML-DSA44 + Ed25519 for post-quantum readiness.",
    }, {
        "id": "Butuh pqSigner dari aplikasi — tidak dibundle.",
        "en": "Needs an app-supplied pqSigner — not bundled.",
    }, "signAlg=hybrid-mldsa44-ed25519"),
    ("derive-keys", {
        "id": "HKDF menurunkan subkey per fungsi dari master key.",
        "en": "HKDF derives per-purpose subkeys from a master key.",
    }, {
        "id": "Opt-in deriveKeys=>true; harus sama di kedua sisi.",
        "en": "Opt-in deriveKeys=>true; must match both sides.",
    }, "deriveKeys, deriveKey()"),
    ("bind-headers", {
        "id": "Ikat header kritis ke AAD agar tidak bisa diganti diam-diam.",
        "en": "Bind critical headers into AAD so they cannot be swapped quietly.",
    }, {
        "id": "X-Timestamp selalu terikat AAD di protocol v3+.",
        "en": "X-Timestamp is always in AAD on protocol v3+.",
    }, "bindHeaders"),
    ("observability", {
        "id": "Callback onSecurityEvent + Prometheus/OTel exporter.",
        "en": "onSecurityEvent callback + Prometheus/OTel exporters.",
    }, {
        "id": "Konteks event tidak berisi secret/plaintext.",
        "en": "Event context never includes secrets/plaintext.",
    }, "EVENT_*, PrometheusSecurityExporter"),
    ("rfc9421", {
        "id": "Jembatan interop ke HTTP Message Signatures.",
        "en": "Interop bridge to HTTP Message Signatures.",
    }, {
        "id": "Rfc9421Bridge di src/Interop.",
        "en": "Rfc9421Bridge in src/Interop.",
    }, "Interop\\\\Rfc9421Bridge"),
    ("sdk-node-go", {
        "id": "SDK Node.js & Go mengikuti wire protocol (default 4).",
        "en": "Node.js & Go SDKs follow the wire protocol (default 4).",
    }, {
        "id": "Samakan version di semua runtime.",
        "en": "Keep version aligned across runtimes.",
    }, "packages/node-sdk, packages/go-sdk"),
    ("cli", {
        "id": "CLI untuk generate/rotate keys dan debug.",
        "en": "CLI for key generate/rotate and debug.",
    }, {
        "id": "keys:generate, keys:rotate, debug:verify, test:roundtrip, doctor.",
        "en": "keys:generate, keys:rotate, debug:verify, test:roundtrip, doctor.",
    }, "securepayload-cli"),
    ("mtls", {
        "id": "mTLS melengkapi SecurePayload di lapisan transport.",
        "en": "mTLS complements SecurePayload at the transport layer.",
    }, {
        "id": "SecurePayload tetap menjaga payload & replay.",
        "en": "SecurePayload still protects payload & replay.",
    }, "docs / examples mTLS"),
    ("kms", {
        "id": "Brankas kunci: Local, Vault, AWS, GCP, Azure.",
        "en": "Key vaults: Local, Vault, AWS, GCP, Azure.",
    }, {
        "id": "Vault Transit: derived=true. LocalKms hanya dev.",
        "en": "Vault Transit: derived=true. LocalKms is dev-only.",
    }, "VaultKms, AwsKms, GcpKms, AzureKeyVaultKms"),
    ("file-storage-delivery", {
        "id": "Pola simpan & kirim file setelah verifikasi aman.",
        "en": "Patterns to store & deliver files after safe verification.",
    }, {
        "id": "Sanitasi nama file; jangan pakai nama mentah sebagai path.",
        "en": "Sanitize filenames; never use raw names as paths.",
    }, "File/* + events file_*"),
    ("idempotency-compress", {
        "id": "Idempotency-Key, compress, dan payloadSchema opsional.",
        "en": "Optional Idempotency-Key, compress, and payloadSchema.",
    }, {
        "id": "compress default false; schema gagal → event payload_schema_invalid.",
        "en": "compress defaults false; schema failure → payload_schema_invalid.",
    }, "compress, payloadSchema, X-Idempotency-Key"),
]


def feature_body(slug: str, lang: str) -> str:
    for s, what, when, api in FEATURE_SPECS:
        if s == slug:
            w = what[lang]
            k = when[lang]
            break
    else:
        w = DESCS[slug][lang]
        k = ""
        api = slug
    title = TITLES[slug][lang]
    if lang == "id":
        return f"""
<p><strong>Apa ini?</strong> {escape(w)}</p>
{h2("kapan", "Kapan dipakai")}
<p>{escape(k)}</p>
{h2("cara", "Cara kerja (analogi)")}
<p>Amplop bersegel / terkunci + tiket sekali pakai menjaga request terkait fitur ini.</p>
{h2("api", "API terkait")}
<p><code>{escape(api)}</code></p>
{callout("warn", "Peringatan", f'Lihat juga <a href="../warnings.html">Peringatan</a>. Defaults: replayTtl=120, clockSkew=60.')}
<details class="acc"><summary>Detail teknis</summary><div class="acc-body"><p>Protocol default {PROTOCOL}. Library v{VERSION}. signAlg ditentukan server.</p></div></details>
<p><a href="index.html">← Hub fitur</a></p>
"""
    return f"""
<p><strong>What is this?</strong> {escape(w)}</p>
{h2("when", "When to use")}
<p>{escape(k)}</p>
{h2("how", "How it works (analogy)")}
<p>Sealed / locked envelopes plus one-time tickets protect this feature's requests.</p>
{h2("api", "Related API")}
<p><code>{escape(api)}</code></p>
{callout("warn", "Warning", f'Also see <a href="../warnings.html">Warnings</a>. Defaults: replayTtl=120, clockSkew=60.')}
<details class="acc"><summary>Technical details</summary><div class="acc-body"><p>Default protocol {PROTOCOL}. Library v{VERSION}. signAlg is server-controlled.</p></div></details>
<p><a href="index.html">← Features hub</a></p>
"""


def body_features_hub(lang: str) -> str:
    links = []
    for s, what, _when, _api in FEATURE_SPECS:
        links.append(
            f'<li><a href="{s}.html"><strong>{escape(TITLES[s][lang])}</strong></a> — {escape(what[lang])}</li>'
        )
    if lang == "id":
        return f"<p>Pilih fitur. Setiap halaman memakai template manfaat → kapan → cara → API.</p><ul>{''.join(links)}</ul>"
    return f"<p>Pick a feature. Each page uses benefits → when → how → API.</p><ul>{''.join(links)}</ul>"


FRAMEWORK_NOTES = {
    "native": {"id": "Contoh Native PHP tanpa framework.", "en": "Native PHP examples without a framework."},
    "ci4": {"id": "Integrasi CodeIgniter 4 (packages/ci4).", "en": "CodeIgniter 4 integration (packages/ci4)."},
    "laravel": {"id": "Middleware Laravel; baca raw body sebelum parse.", "en": "Laravel middleware; read raw body before parsing."},
    "lumen": {"id": "Pola mirip Laravel untuk Lumen.", "en": "Laravel-like patterns for Lumen."},
    "slim": {"id": "Middleware Slim PSR-15.", "en": "Slim PSR-15 middleware."},
    "symfony": {"id": "Bundle/event Symfony.", "en": "Symfony bundle/events."},
    "node": {"id": "Express/Fastify via packages/node-sdk.", "en": "Express/Fastify via packages/node-sdk."},
    "go": {"id": "Gin/Echo/Fiber middleware di packages/go-sdk.", "en": "Gin/Echo/Fiber middleware in packages/go-sdk."},
}


def body_framework(slug: str, lang: str) -> str:
    note = FRAMEWORK_NOTES[slug][lang]
    if lang == "id":
        return f"""
<p>{escape(note)}</p>
{callout("warn", "Raw body", "Baca body mentah sebelum framework mem-parse JSON bila tanda tangan mencakup body.")}
{code_block("php" if slug not in ("node", "go") else ("js" if slug == "node" else "go"),
            "// TEST only — see examples/ and packages/\\n// Pass server method/path/query into verify()", "Salin")}
<p><a href="../warnings.html">Peringatan produksi →</a></p>
"""
    return f"""
<p>{escape(note)}</p>
{callout("warn", "Raw body", "Read the raw body before the framework parses JSON if the signature covers the body.")}
{code_block("php" if slug not in ("node", "go") else ("js" if slug == "node" else "go"),
            "// TEST only — see examples/ and packages/\\n// Pass server method/path/query into verify()", "Copy")}
<p><a href="../warnings.html">Production warnings →</a></p>
"""


def body_reference(slug: str, lang: str) -> str:
    tables = {
        "options": [
            ("mode", "hmac|aead|both", "Security mode"),
            ("signAlg", "hmac|ed25519|hybrid-mldsa44-ed25519", "Server-controlled"),
            ("version", f"default {PROTOCOL}", "Wire protocol"),
            ("replayTtl", "120", "Seconds"),
            ("clockSkew", "60", "Seconds"),
            ("requireReplayStore", "false", "Fail if no store"),
            ("deriveKeys", "false", "HKDF subkeys"),
            ("bindHeaders", "[]", "AAD-bound headers"),
            ("compress", "false", "Optional"),
        ],
        "headers": [
            ("X-Client-Id", "Client identity", "Required"),
            ("X-Key-Id", "Key version", "Required"),
            ("X-Timestamp", "Send time", "Freshness"),
            ("X-Nonce", "One-time ticket", "Replay"),
            ("X-Signature*", "Seal", "Integrity"),
            ("X-Canonical-Request", "Debug hint", "Do not trust"),
            ("X-AEAD-*", "Locked envelope", "aead/both"),
            ("X-Resp-*", "Response seal", "Two-way"),
        ],
        "events": [
            ("timestamp_invalid", "Time window", ""),
            ("replay_detected", "Ticket reused", ""),
            ("decrypt_failed", "AEAD fail", ""),
            ("signature_invalid", "Seal fail", ""),
            ("key_not_found", "Loader miss", ""),
            ("nonce_mismatch", "AEAD nonce", ""),
            ("payload_schema_invalid", "Schema", ""),
        ],
        "exceptions": [
            ("400", "BAD_REQUEST", "Incomplete headers / bad input"),
            ("401", "UNAUTHORIZED", "Signature / replay / timestamp"),
            ("422", "UNPROCESSABLE", "Decrypt / digest"),
            ("500", "SERVER_ERROR", "Config / sodium / requireReplayStore"),
        ],
        "methods": [
            ("buildHeadersAndBody", "Client", "Build request"),
            ("verify / verifyOrThrow", "Server", "Verify request"),
            ("buildResponse", "Server", "Secure response"),
            ("verifyResponse", "Client", "Check response"),
            ("buildFilePayload / Stream", "Client", "Files"),
            ("verifyFilePayload / Stream", "Server", "Files"),
        ],
        "env": [
            ("SECUREPAYLOAD_{CID}_{KID}_HMAC_SECRET", "HMAC", "EnvKeyProvider"),
            ("..._AEAD_KEY_B64", "AEAD", "32-byte b64"),
            ("..._ED25519_PUBLIC_B64", "Client pub", "Request verify"),
            ("..._ED25519_SERVER_*", "Server pair", "Response"),
            ("SECURE_KEKS / SECURE_KEK_*", "LocalKms", "Dev wrapping"),
        ],
    }
    rows = tables[slug]
    thead = "<tr>" + "".join(f"<th>{escape(h)}</th>" for h in (("Name", "Value", "Notes") if slug != "exceptions" else ("HTTP", "Code", "Meaning"))) + "</tr>"
    body = "".join(f"<tr><td><code>{escape(a)}</code></td><td>{escape(b)}</td><td>{escape(c)}</td></tr>" for a, b, c in rows)
    lead = "Referensi ringkas dari kode aktual." if lang == "id" else "Short reference from actual code."
    return f"<p>{lead}</p>{h2('table', TITLES[slug][lang])}<div class=\"table-wrap\"><table><thead>{thead}</thead><tbody>{body}</tbody></table></div>"


def body_glossary(lang: str) -> str:
    items = []
    for key, defs in GLOSSARY.items():
        items.append(f"<dt id=\"{escape(key)}\"><button type=\"button\" class=\"term\" data-term=\"{escape(key)}\">{escape(key)}</button></dt><dd>{escape(defs[lang])}</dd>")
    return f"<p>{'Kamus istilah tetap untuk tooltip.' if lang=='id' else 'Fixed glossary for tooltips.'}</p><dl>{''.join(items)}</dl>"


def body_versions(lang: str) -> str:
    if lang == "id":
        return f"""
<ul>
  <li>Library <strong>v{VERSION}</strong></li>
  <li>Protocol default <strong>{PROTOCOL}</strong> (<code>SecurePayload::DEFAULT_VERSION</code>)</li>
  <li>PHP CI 8.0–8.5</li>
</ul>
{callout("info", "Upgrade", "Samakan version di klien & server. Wire v4 menambah multipart file stream.")}
<p>Lihat CHANGELOG di repositori untuk breaking changes.</p>
"""
    return f"""
<ul>
  <li>Library <strong>v{VERSION}</strong></li>
  <li>Default protocol <strong>{PROTOCOL}</strong> (<code>SecurePayload::DEFAULT_VERSION</code>)</li>
  <li>PHP CI 8.0–8.5</li>
</ul>
{callout("info", "Upgrade", "Keep version aligned on client & server. Wire v4 adds multipart file streaming.")}
<p>See the repository CHANGELOG for breaking changes.</p>
"""


def body_security(lang: str) -> str:
    if lang == "id":
        return f"""
{callout("warn", "Audit", "Belum ada audit keamanan pihak ketiga.")}
<p>Laporkan kerentanan secara bertanggung jawab lewat kebijakan keamanan repositori.</p>
<p><a href="{GITHUB}/blob/main/SECURITY.md">SECURITY.md</a></p>
<ul>
  <li>Jangan publikasikan exploit detail sebelum perbaikan.</li>
  <li>Sertakan versi library dan langkah reproduksi aman.</li>
</ul>
"""
    return f"""
{callout("warn", "Audit", "There is no third-party security audit yet.")}
<p>Report vulnerabilities responsibly via the repository security policy.</p>
<p><a href="{GITHUB}/blob/main/SECURITY.md">SECURITY.md</a></p>
<ul>
  <li>Do not publish exploit details before a fix.</li>
  <li>Include library version and safe reproduction steps.</li>
</ul>
"""


def body_contributing(lang: str) -> str:
    if lang == "id":
        return f"""
<p>Kontribusi diterima lewat pull request di GitHub.</p>
<ul>
  <li>Lisensi: <strong>MIT</strong></li>
  <li>Repo: <a href="{GITHUB}">{GITHUB}</a></li>
  <li>Tes: <code>composer test</code> · Stan: <code>composer stan</code></li>
</ul>
"""
    return f"""
<p>Contributions are welcome via GitHub pull requests.</p>
<ul>
  <li>License: <strong>MIT</strong></li>
  <li>Repo: <a href="{GITHUB}">{GITHUB}</a></li>
  <li>Tests: <code>composer test</code> · Stan: <code>composer stan</code></li>
</ul>
"""


BODY_BUILDERS: Dict[str, Callable[[str], str]] = {
    "index": body_index,
    "basics": body_basics,
    "choose-setup": body_choose_setup,
    "installation": body_installation,
    "quickstart": body_quickstart,
    "keys": body_keys,
    "features": body_features_hub,
    "warnings": body_warnings,
    "troubleshooting": body_troubleshooting,
    "glossary": body_glossary,
    "versions": body_versions,
    "security": body_security,
    "contributing": body_contributing,
}


def build_body(slug: str, lang: str) -> str:
    if slug in BODY_BUILDERS:
        return BODY_BUILDERS[slug](lang)
    if slug in {s for s, *_ in FEATURE_SPECS}:
        return feature_body(slug, lang)
    if slug in FRAMEWORK_NOTES:
        return body_framework(slug, lang)
    if slug in ("options", "headers", "events", "exceptions", "methods", "env"):
        return body_reference(slug, lang)
    return f"<p>{escape(DESCS[slug][lang])}</p>"


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------


def ui(lang: str) -> Dict[str, str]:
    if lang == "id":
        return {
            "skip": "Lewati ke konten",
            "menu": "Menu",
            "search": "Cari",
            "theme_light": "Terang",
            "theme_dark": "Gelap",
            "theme_auto": "Otomatis",
            "on_this": "Di halaman ini",
            "prev": "Sebelumnya",
            "next": "Berikutnya",
            "helpful": "Apakah halaman ini membantu?",
            "feedback": "Laporkan masalah",
            "toc_empty": "Tidak ada bagian",
        }
    return {
        "skip": "Skip to content",
        "menu": "Menu",
        "search": "Search",
        "theme_light": "Light",
        "theme_dark": "Dark",
        "theme_auto": "Auto",
        "on_this": "On this page",
        "prev": "Previous",
        "next": "Next",
        "helpful": "Was this page helpful?",
        "feedback": "Report an issue",
        "toc_empty": "No sections",
    }


def extract_toc(html: str) -> List[Tuple[str, str]]:
    return [(m.group(1), re.sub(r"<[^>]+>", "", m.group(2))) for m in re.finditer(r'<h2 id="([^"]+)">([^<]+)</h2>', html)]


def render_nav(lang: str, current: str, from_file: str) -> str:
    parts = ['<nav class="site-sidebar" aria-label="Docs">']
    for _gid, labels, slugs in NAV_GROUPS:
        parts.append(f'<div class="nav-group"><div class="nav-group-title">{escape(labels[lang])}</div><ul>')
        for slug in slugs:
            p = page_by_slug(slug)
            href = href_between(from_file, p["file"])
            active = ' aria-current="page"' if slug == current else ""
            parts.append(
                f'<li><a href="{href}"{active}>{escape(TITLES[slug][lang])}</a></li>'
            )
        parts.append("</ul></div>")
    parts.append("</nav>")
    return "\n".join(parts)


def render_page(lang: str, page: Page, idx: int) -> str:
    slug = page["slug"]
    file = page["file"]
    ab = asset_base(file)
    u = ui(lang)
    title = TITLES[slug][lang]
    desc = DESCS[slug][lang]
    body = build_body(slug, lang)
    toc = extract_toc(body)
    other = "en" if lang == "id" else "id"
    # canonical / hreflang use placeholder absolute base
    canon = f"{SITE_BASE}{lang}/{file}"
    alt = f"{SITE_BASE}{other}/{file}"
    # lang switch relative
    lang_href = href_between(file, file)  # same path other lang handled via ../
    # From id/foo -> en/foo: go up depth+1 then into other lang
    up = "../" * (depth_of(file) + 1)
    switch_id = f"{up}id/{file}"
    switch_en = f"{up}en/{file}"

    prev_html = next_html = ""
    if idx > 0:
        prev = PAGES[idx - 1]
        prev_html = f'<a href="{href_between(file, prev["file"])}">{u["prev"]}: {escape(TITLES[prev["slug"]][lang])}</a>'
    if idx < len(PAGES) - 1:
        nxt = PAGES[idx + 1]
        next_html = f'<a href="{href_between(file, nxt["file"])}">{u["next"]}: {escape(TITLES[nxt["slug"]][lang])}</a>'

    toc_html = "".join(f'<a href="#{escape(a)}">{escape(t)}</a>' for a, t in toc) or f"<span>{u['toc_empty']}</span>"
    issue_title = escape(f"Guide feedback: {lang}/{slug}")
    issue_url = f"{ISSUES}?title={issue_title}"

    return f"""<!DOCTYPE html>
<html lang="{lang}" data-theme="auto">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{escape(title)} · SecurePayload</title>
  <meta name="description" content="{escape(desc)}" />
  <meta name="sp-asset-base" content="{ab}" />
  <link rel="canonical" href="{canon}" />
  <link rel="alternate" hreflang="{lang}" href="{canon}" />
  <link rel="alternate" hreflang="{other}" href="{alt}" />
  <link rel="alternate" hreflang="x-default" href="{SITE_BASE}en/{file}" />
  <meta property="og:title" content="{escape(title)} · SecurePayload" />
  <meta property="og:description" content="{escape(desc)}" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="{canon}" />
  <link rel="icon" href="{ab}logo/v4-a-shield-code-icon.svg" type="image/svg+xml" />
  <link rel="apple-touch-icon" href="{ab}logo/v4-a-shield-code-icon-512.png" />
  <link rel="stylesheet" href="{ab}css/site.css" />
  <script src="{ab}js/site.js" defer></script>
</head>
<body>
  <a class="skip-link" href="#main">{escape(u["skip"])}</a>
  <header class="site-topbar">
    <div class="site-topbar__start">
      <button type="button" class="icon-btn" data-sidebar-toggle aria-expanded="false" aria-controls="sidebar">{escape(u["menu"])}</button>
      <a class="brand-block" href="{href_between(file, 'index.html')}" aria-label="SecurePayload">
        <img class="brand-wordmark logo-light" src="{ab}logo/v4-a-shield-code-logo.svg" alt="SecurePayload" width="180" height="40" />
        <img class="brand-wordmark logo-dark" src="{ab}logo/v4-a-shield-code-logo-dark.svg" alt="SecurePayload" width="180" height="40" />
      </a>
    </div>
    <div class="site-topbar__end">
      <button type="button" class="icon-btn" data-search-open aria-haspopup="dialog">{escape(u["search"])}</button>
      <div class="segment" role="group" aria-label="Language">
        <a class="segment-item" data-lang-switch="id" href="{switch_id}" {"aria-current='true'" if lang=="id" else ""}>ID</a>
        <a class="segment-item" data-lang-switch="en" href="{switch_en}" {"aria-current='true'" if lang=="en" else ""}>EN</a>
      </div>
      <div class="segment" role="group" aria-label="Theme">
        <button type="button" data-theme-set="light">{escape(u["theme_light"])}</button>
        <button type="button" data-theme-set="dark">{escape(u["theme_dark"])}</button>
        <button type="button" data-theme-set="auto">{escape(u["theme_auto"])}</button>
      </div>
      <span class="badge">v{VERSION}</span>
      <a class="top-link" href="{GITHUB}" rel="noopener">GitHub</a>
    </div>
  </header>
  <div class="sidebar-backdrop" data-sidebar-backdrop hidden></div>
  <div class="docs-shell">
    <aside id="sidebar" class="site-sidebar-wrap">
      {render_nav(lang, slug, file)}
    </aside>
    <main id="main" class="site-main">
      <article class="prose">
        {body}
      </article>
      <nav class="page-nav" aria-label="Pagination">
        {prev_html}
        {next_html}
      </nav>
      <p class="footer-note">{escape(u["helpful"])}
 <a href="{issue_url}">{escape(u["feedback"])}</a></p>
    </main>
    <aside class="site-toc" aria-label="{escape(u["on_this"])}">
      <div class="site-toc__title">{escape(u["on_this"])}</div>
      <nav>{toc_html}</nav>
    </aside>
  </div>
  <div class="search-modal" data-search-modal hidden>
    <div class="search-dialog" role="dialog" aria-modal="true" aria-label="{escape(u["search"])}">
      <div class="search-input-wrap">
        <input type="search" data-search-input placeholder="{escape(u["search"])}…" autocomplete="off" />
        <button type="button" data-search-close>Esc</button>
      </div>
      <p data-search-loading hidden>…</p>
      <p data-search-empty hidden>{'Tidak ada hasil' if lang=='id' else 'No results'}</p>
      <ul class="search-results" data-search-results></ul>
    </div>
  </div>
</body>
</html>
"""


def root_index() -> str:
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SecurePayload User Guide</title>
  <meta name="description" content="SecurePayload bilingual user guide (ID / EN)." />
  <meta name="sp-asset-base" content="assets/" />
  <link rel="icon" href="assets/logo/v4-a-shield-code-icon.svg" type="image/svg+xml" />
  <link rel="stylesheet" href="assets/css/site.css" />
  <script>
  (function () {{
    try {{
      var saved = localStorage.getItem('sp-guide-lang');
      var nav = (navigator.language || 'en').toLowerCase();
      var lang = saved || (nav.indexOf('id') === 0 ? 'id' : 'en');
      if (lang !== 'id' && lang !== 'en') lang = 'en';
      location.replace('./' + lang + '/index.html');
    }} catch (e) {{
      /* show manual links below */
    }}
  }})();
  </script>
</head>
<body>
  <main class="shell prose" style="padding:48px 24px;max-width:40rem;margin:0 auto">
    <h1>SecurePayload User Guide</h1>
    <p>Choose a language / Pilih bahasa:</p>
    <p class="btn-row">
      <a class="btn btn-primary" href="id/index.html">Indonesia (ID)</a>
      <a class="btn btn-secondary" href="en/index.html">English (EN)</a>
    </p>
  </main>
</body>
</html>
"""


def page_404() -> str:
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>404 · SecurePayload Guide</title>
  <meta name="sp-asset-base" content="assets/" />
  <link rel="icon" href="assets/logo/v4-a-shield-code-icon.svg" type="image/svg+xml" />
  <link rel="stylesheet" href="assets/css/site.css" />
</head>
<body>
  <main class="shell prose" style="padding:48px 24px;max-width:40rem;margin:0 auto">
    <h1>Page not found</h1>
    <p>Halaman tidak ditemukan. Try one of these:</p>
    <ul>
      <li><a href="en/index.html" data-root="en/index.html">Home (EN)</a> · <a href="id/index.html" data-root="id/index.html">Beranda (ID)</a></li>
      <li><a href="en/quickstart.html" data-root="en/quickstart.html">Quick Start</a> · <a href="id/quickstart.html" data-root="id/quickstart.html">Mulai Cepat</a></li>
      <li><a href="en/warnings.html" data-root="en/warnings.html">Warnings</a> · <a href="id/warnings.html" data-root="id/warnings.html">Peringatan</a></li>
      <li><a href="en/features/index.html" data-root="en/features/index.html">Features</a></li>
      <li><a href="en/troubleshooting.html" data-root="en/troubleshooting.html">Troubleshooting</a></li>
    </ul>
  </main>
  <script>
  (function () {
    function root() {
      var p = location.pathname;
      var m = p.match(/^(.*)\/(?:id|en)(?:\/|$)/);
      if (m) return (m[1] || '') + '/';
      return p.replace(/\/[^/]*$/, '/') || './';
    }
    document.addEventListener('DOMContentLoaded', function () {
      var r = root();
      document.querySelectorAll('a[data-root]').forEach(function (a) {
        a.href = r + a.getAttribute('data-root');
      });
    });
  })();
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def copy_assets() -> None:
    dest = DIST / "assets"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ASSETS_SRC, dest)


def write_search_index(entries: List[Dict[str, str]]) -> None:
    (DIST / "assets" / "search-index.json").write_text(
        json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_glossary() -> None:
    (DIST / "assets" / "glossary.json").write_text(
        json.dumps(GLOSSARY, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_sitemap() -> None:
    urls = [f"{SITE_BASE}", f"{SITE_BASE}id/", f"{SITE_BASE}en/"]
    for lang in ("id", "en"):
        for p in PAGES:
            urls.append(f"{SITE_BASE}{lang}/{p['file']}")
    body = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in urls:
        body.append(f"  <url><loc>{escape(u)}</loc></url>")
    body.append("</urlset>")
    (DIST / "sitemap.xml").write_text("\n".join(body) + "\n", encoding="utf-8")


def write_robots() -> None:
    (DIST / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {SITE_BASE}sitemap.xml\n",
        encoding="utf-8",
    )


def self_copy_to_tools() -> None:
    src = Path(__file__).resolve()
    dest = GUIDE / "tools" / "generate.py"
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = src.read_text(encoding="utf-8")
    dest.write_text(text, encoding="utf-8", newline="\n")


def build() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    copy_assets()
    (DIST / ".nojekyll").write_text("", encoding="utf-8")
    (DIST / "serve.json").write_text(
        '{\n  "cleanUrls": false\n}\n',
        encoding="utf-8",
        newline="\n",
    )
    
    (DIST / "index.html").write_text(root_index(), encoding="utf-8", newline="\n")
    (DIST / "404.html").write_text(page_404(), encoding="utf-8", newline="\n")
    write_robots()
    write_sitemap()
    write_glossary()

    search: List[Dict[str, str]] = []
    counts = {"id": 0, "en": 0}

    for lang in ("id", "en"):
        for idx, page in enumerate(PAGES):
            html = render_page(lang, page, idx)
            out = DIST / lang / page["file"]
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(html, encoding="utf-8", newline="\n")
            counts[lang] += 1
            text = strip_tags(build_body(page["slug"], lang))[:1200]
            url = f"{lang}/{page['file']}"
            search.append({
                "lang": lang,
                "title": TITLES[page["slug"]][lang],
                "url": url,
                "text": text,
                "category": page["cat"],
            })

    write_search_index(search)
    self_copy_to_tools()
    print(f"Built guide/dist: {counts['id']} id + {counts['en']} en pages")
    print(f"Search entries: {len(search)}")
    print(f"Copied generator -> guide/tools/generate.py")


if __name__ == "__main__":
    build()
