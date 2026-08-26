# Dashboard Admin Read-only

Dashboard **read-only** untuk event keamanan SecurePayload: satu exporter JSONL
untuk persistensi ringan + viewer HTML server-side murni. Library sendiri tetap
tidak menyimpan apa pun — persistensi hanya terjadi bila aplikasi memasang
exporter pada opsi `onSecurityEvent`.

Komponen:

| Komponen | File |
|----------|------|
| Exporter JSONL | `src/Observability/JsonlSecurityExporter.php` |
| Viewer read-only | `examples/dashboard/index.php` |

---

## 1. Wiring: exporter → `onSecurityEvent`

```php
use SecurePayload\Observability\JsonlSecurityEventExporter;
use SecurePayload\SecurePayload;

$exporter = new JsonlSecurityEventExporter('/var/log/securepayload/events.jsonl', [
    // 'maxSizeBytes' => 10 * 1024 * 1024, // rotasi saat >= 10 MiB (0 = off)
    // 'maxFiles'     => 3,                // simpan events.jsonl.1 .. .3
]);

$server = new SecurePayload([
    // ... konfigurasi verifikasi Anda ...
    'onSecurityEvent' => $exporter->onSecurityEvent(),
]);
```

Semantik mengikuti `Internal\EventEmitter`: kegagalan I/O (disk penuh, izin,
rotasi gagal) **tidak pernah melempar exception ke alur utama** — event itu
diam-diam tidak tertulis dan pesannya dapat diperiksa:

```php
if (($err = $exporter->getLastError()) !== null) {
    // laporkan lewat channel monitoring aplikasi Anda; jangan dari jalur request.
}
```

### Opsi konstruktor

| Opsi | Default | Arti |
|------|---------|------|
| `$path` | *(wajib)* | Path file log; direktori induk harus sudah ada |
| `maxSizeBytes` | `0` | Rotasi by-size; `0` = dinonaktifkan |
| `maxFiles` | `3` | Jumlah arsip `<path>.1 … <path>.N` (min 1) |
| `clock` | `time()` | Injectable timestamp unix (untuk pengujian) |

Rotasi sederhana by-size: ketika file utama mencapai `maxSizeBytes`, ia menjadi
`<path>.1`, arsip lama bergeser (`.<n-1>` → `.<n>`), dan arsip tertua dihapus.
Bila rotasi gagal, event berikutnya juga tidak ditulis (mencegah pertumbuhan
tanpa batas) sampai penyebabnya hilang.

## 2. Format JSONL

Satu event = satu baris fisik (newline dalam nilai diganti spasi):

```json
{"ts":1770000000,"event":"signature_invalid","ctx":{"clientId":"c1","keyId":"k1"}}
```

* `ts` — unix timestamp dari `clock`.
* `event` — nama event (`SecurePayload::EVENT_*`; daftar sama seperti
  `PrometheusSecurityExporter::knownEvents()`).
* `ctx` — context event yang **WAJIB non-secret** (konvensi `onSecurityEvent`;
  exporter hanya serialisasi, tidak pernah menambah field). Nilai array
  di-flatten satu level (`key=value` untuk assoc, JSON ringkas untuk level
  lebih dalam); scalar di-stringify aman.

Append atomik per baris (`fopen 'ab'` + `flock LOCK_EX`) sehingga aman untuk
beberapa proses yang menulis ke file yang sama pada mesin yang sama.

> Catatan skala: ini MVP single-file. Untuk volume tinggi / multi-host, kirim
> event ke pipeline log (OTel/queue) alih-alih file lokal.

## 3. Menjalankan viewer

```bash
SP_EVENT_LOG=/var/log/securepayload/events.jsonl \
  php -S localhost:8080 examples/dashboard/index.php
```

Yang ditampilkan:

1. **Jumlah per tipe event** — agregat atas jendela log yang dimuat.
2. **Jumlah per `client_id`** — dibaca dari `ctx.clientId` / `ctx.client_id`.
   `client_id` berasal dari request eksternal (data tak tepercaya) sehingga
   selalu di-render ter-escape.
3. **N event terakhir** (default 100; `?limit=` di-clamp 10–500).
4. **Panel umur KEK** — hanya *nama* dari env `SECURE_KEKS` (konvensi yang sama
   dengan `LocalKms::fromEnv()`) plus timestamp opsional `<kek-id>_CREATED_AT`:

   ```dotenv
   SECURE_KEKS=kek-2026-01,kek-2026-08
   kek-2026-01_CREATED_AT=2026-01-15T00:00:00Z
   ```

   Viewer **tidak pernah membaca/menampilkan nilai material kunci**
   (`SECURE_KEK_<id>_B64` dsb.).

Log besar tetap aman dimuat: hanya tail 8 MiB terakhir yang diparse.

## 4. Keamanan — WAJIB DIBACA

> ### ⚠️ Dashboard menampilkan metrik keamanan internal (pola serangan,
> ### client aktif). JANGAN ekspos ke publik — WAJIB di belakang auth
> ### produksi: VPN / reverse-proxy auth / SSO internal.

* **Read-only total** — tidak ada endpoint tulis; metode selain GET/HEAD
  ditolak (405).
* **Path log hanya dari env** — `SP_EVENT_LOG`. Sengaja tidak bisa diatur via
  query/URL agar halaman tidak menjadi file-read gadget arbitrer.
* **XSS-safe** — seluruh output melewati `htmlspecialchars(ENT_QUOTES)`;
  konteks event bisa berisi data dari penyerang.
* **Placeholder auth** tersedia sebagai komentar di `examples/dashboard/index.php`
  (HTTP Basic Auth + `hash_equals`). Lebih baik lagi terapkan auth di reverse
  proxy/web server, bukan di kode aplikasi.

## 5. Batasan MVP

* Ringkasan dihitung atas jendela log yang dimuat (tail 8 MiB), bukan seluruh
  riwayat.
* Tanpa filter/pencarian/timeline; tanpa JS — cocok untuk review berkala, bukan SIEM.
* Satu file log per host; tidak ada shipping antar-host.
