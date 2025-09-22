# Panduan Rilis ke Packagist (dan Update Versi)

Dokumen ini menjelaskan langkah **publish pertama kali** ke Packagist dan **update** versi berikutnya.

---

## 0) Prasyarat
- Kode berada di Git repository publik (GitHub/GitLab/Bitbucket).
- `composer.json` valid dan memiliki minimal field:
  - `name`: `vendor/name` (contoh: `sk8dvlpr/securepayload`)
  - `description`, `type: "library"`, `license`, `autoload` PSR-4, dll.
- Branch default: `main` atau `master`.
- (Opsional) GitHub Actions CI sudah berjalan: lint, phpstan, phpunit.

> **Catatan:** Disarankan **tidak** menaruh field `version` di `composer.json` untuk library. **Packagist menggunakan tag git** sebagai sumber versi.

---

## 1) Rilis Pertama Kali (Submit Package)
1. Push repo ke GitHub: `https://github.com/<user>/<repo>`
2. Buka **https://packagist.org/packages/submit**
3. Masukkan URL repository Git: `https://github.com/<user>/<repo>.git`
4. Klik **Check** → **Submit**
5. (Opsional) Hubungkan **GitHub Service Hook** (Auto-Update):
   - Di Packagist profile → **Services** → **GitHub** → sambungkan akun GitHub Anda
   - Pada halaman paket, aktifkan **Auto-Update** (GitHub/GitLab integration).
   - Atau gunakan **GitHub Webhook** bawaan Packagist (di Settings → Webhooks).

> Dengan Auto-Update terhubung, setiap **push tag** baru akan otomatis memicu update di Packagist.

---

## 2) Membuat Tag Versi (SemVer)
Gunakan **Semantic Versioning**: `MAJOR.MINOR.PATCH` (contoh: `1.2.3`).

```bash
# Pastikan status bersih
git status

# Update CHANGELOG.md (opsional tapi disarankan)

# Buat tag rilis baru
git tag -a v1.0.0 -m "Release v1.0.0"

# Dorong tag ke remote
git push origin v1.0.0
```

> **Packagist** akan membaca `v1.0.0` dan membuat rilis **1.0.0**.
> Hindari field `version` di `composer.json` untuk library—**biarkan tag menjadi sumber kebenaran**.

---

## 3) Update / Rilis Versi Baru
1. Commit perubahan
2. Naikkan versi sesuai SemVer (Patch/Minor/Major)
3. Buat dan push tag baru:
   ```bash
   git tag -a v1.0.1 -m "Fix: PHPStan warnings"
   git push origin v1.0.1
   ```
4. **Dengan Auto-Update aktif**, Packagist akan memproses otomatis.
   Jika belum terhubung, buka halaman paket di Packagist → klik **Update** (manual).

---

## 4) Tips Praktis
- **Branch alias** (opsional) untuk pengembangan:
  ```json
  {
    "extra": {
      "branch-alias": {
        "dev-main": "1.x-dev"
      }
    }
  }
  ```
- **Konsistensi Tag**: gunakan prefix `v` (mis. `v1.2.0`) agar rapi.
- **CI Wajib Lulus** sebelum tag dibuat: pastikan Actions green.
- **Stabilitas**: rilis `0.x` dianggap **unstable**. Mulai `1.0.0` untuk Stable API.
- **Security**: buat **GHSA / Security Policy** dan aktifkan Dependabot untuk dev deps.

---

## 5) Troubleshooting
- **Packagist tidak memperbarui versi**
  - Pastikan tag **sudah dipush**.
  - Cek apakah **Auto-Update** sudah terhubung (Packagist ↔ GitHub).
  - Klik **Update** manual di halaman paket.
- **Nama vendor sudah dipakai**
  - Ganti `name` di `composer.json` (mis. `yourname/securepayload`) atau minta transfer kepemilikan.
- **CI gagal saat rilis**
  - Hapus tag: `git tag -d v1.0.1 && git push origin :refs/tags/v1.0.1`
  - Perbaiki CI, buat tag ulang.

---

## 6) Contoh composer.json (ringkas)
```json
{
  "name": "sk8dvlpr/securepayload",
  "description": "Unified client+server security helper for HMAC and AEAD (XChaCha20-Poly1305) with nonce/replay protection.",
  "type": "library",
  "license": "MIT",
  "require": {
    "php": ">=8.0",
    "ext-json": "*",
    "ext-hash": "*"
  },
  "autoload": {"psr-4": {"SecurePayload\\": "src/"}}
}
```

---

## 7) Workflow Rilis (Checklist)
- [ ] Update kode & docs
- [ ] CI hijau (lint/phpstan/phpunit)
- [ ] Update CHANGELOG.md
- [ ] `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] `git push origin vX.Y.Z`
- [ ] Verifikasi di Packagist
