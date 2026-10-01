# SecurePayload User Guide

Situs panduan bilingual (ID / EN) untuk `sk8dvlpr/securepayload` — statis, siap GitHub Pages.

## Build

Dari **akar repo**:

```bash
python guide/tools/generate.py
# atau: cd guide && npm run build
```

Output: `guide/dist/` (HTML, assets, search index, glossary, sitemap, `.nojekyll`).

## Preview lokal

```bash
cd guide
npx serve dist
# atau: python -m http.server 4177 --directory dist
```

Buka URL yang dicetak. Akar `index.html` mengalihkan menurut bahasa browser; atau buka `/id/` · `/en/`.

## GitHub Pages

1. Deploy **isi** `guide/dist/` sebagai root Pages (bukan seluruh folder `guide/`).
2. Pastikan `.nojekyll` ikut ter-deploy.
3. Semua URL relatif — cocok untuk `https://<user>.github.io/<repo>/`.
4. Di GitHub: **Settings → Pages → Build and deployment** = GitHub Actions.
5. Salin draf `guide/.github-workflow-draft/deploy.yml` ke `.github/workflows/deploy-guide.yml` bila siap mengaktifkan (pin action ke SHA dulu).

## Tes

```bash
node guide/tests/run.mjs
php guide/tests/snippets/roundtrip.php
```

Laporan: `guide/tests/reports/`.

## Menambah halaman

1. Daftarkan slug di `guide/tools/generate.py` (`PAGES` / judul / body).
2. Samakan di navigasi ID dan EN.
3. Rebuild + jalankan parity test.