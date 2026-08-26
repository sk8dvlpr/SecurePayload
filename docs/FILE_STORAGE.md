# Penyimpanan File Terenkripsi (Envelope Encryption)

Simpan file secara aman dengan enkripsi *envelope*: setiap file punya **DEK acak sendiri** (32 byte) yang mengenkripsi isi via XChaCha20-Poly1305 *secretstream*, lalu DEK tersebut di-*wrap* oleh KEK milik **KMS**. Modul ini **standalone** — bisa dipakai tanpa instance `SecurePayload` maupun protokol request/response HTTP.

## Arsitektur

```
plaintext ──▶ [DEK acak 32 byte] ──▶ secretstream frames ──▶ blob ciphertext ──▶ Adapter (Local/S3/GCS)
                    │                                                        ▲
                    ▼                                                        │ murni ciphertext,
             kms->wrap(KEK, AAD)                                             │ tanpa metadata
                    │                                                        │
                    └──▶ wrapped DEK + AAD context + digest ──▶ FileManifest ──┘  (dipersist di DB aplikasi)
```

- **Blob di adapter** bersifat *self-contained*: ciphertext frame secretstream tanpa metadata apa pun. Integritasnya diverifikasi terhadap `cipher_digest` milik manifest sebelum dekripsi.
- **Manifest** adalah satu-satunya tempat metadata hidup (wrapped DEK, AAD context, digest, ukuran, timestamp). Objek `FileManifest` immutable — serialisasi dengan `toArray()` dan muat ulang dengan `FileManifest::fromArray()`.
- Format storage internal bernilai `SecureFileStorage::STORAGE_FORMAT_VERSION = '1'` — independen dari wire protocol v3/v4. Algoritma stream tercatat di `alg` (`XCHACHA20POLY1305-SECRETSTREAM`).

## Quick Start (Standalone)

```bash
# .env — KEK terdaftar (base64 dari tepat 32 byte):
#   SECURE_KEKS=PRIMARY,SECONDARY
#   SECURE_KEK_PRIMARY_B64=...
#   SECURE_KEK_SECONDARY_B64=...
```

```php
use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;

$kms     = LocalKms::fromEnv();
$adapter = new LocalStorageAdapter('/var/lib/app/secure-blobs');

$storage = new SecureFileStorage($kms, $adapter, [
    'chunkSize' => 256 * 1024,   // opsional: 1KiB–8MiB (default 64KiB)
    'onSecurityEvent' => function (string $event, array $ctx): void {
        error_log("[security] $event " . json_encode($ctx)); // konteks WAJIB non-secret
    },
]);

// 1. Simpan: plaintext → blob ciphertext; kembalikan manifest.
$manifest = $storage->store('/tmp/laporan.pdf', [
    'client_id' => 'report-service',              // provenance (masuk konteks event)
    'kek_id'    => 'PRIMARY',                     // KEK yang membungkus DEK
    'purpose'   => 'laporan-bulanan',             // opsional, provenance
    'metadata'  => ['nama_asli' => 'laporan.pdf'],// opsional, map string=>string
]);

// 2. Persist manifest di DB aplikasi Anda (INI KUNCI pembuka filenya).
db_insert('secure_files', $manifest->toArray());

// 3. Muat ulang manifest lalu baca isinya.
$m = FileManifest::fromArray(db_fetch('secure_files', $manifest->fileId()));

var_dump($storage->exists($m));                   // cek blob masih ada

$storage->retrieveStream($m, function (string $chunk): void {
    echo $chunk;                                  // plaintext per chunk ±64KB
});

$result = $storage->retrieve($m, '/tmp/restored.pdf');
// $result = ['path' => '/tmp/restored.pdf', 'size' => 12345]
// Penulisan atomik: file sementara + rename; gagal di tengah jalan tidak menyisakan file parsial.

// 4. Hapus (crypto-shredding — lihat Invariant Keamanan).
$storage->delete($m);
db_delete('secure_files', $m->fileId());          // WAJIB: hapus manifest/wrapped DEK juga
```

Contoh skrip runnable: [`examples/file-storage/store_retrieve.php`](../examples/file-storage/store_retrieve.php).

## Adapter Cloud (S3 / GCS)

SDK cloud bersifat **duck-typed** dan menjadi dependency opsional (`composer suggest`) — library inti tidak menarik SDK berat:

```php
use SecurePayload\Storage\Adapter\S3StorageAdapter;
use SecurePayload\Storage\Adapter\GcsStorageAdapter;

// Amazon S3 — klien wajib punya putObject/getObject/headObject/deleteObject.
$client  = new \Aws\S3\S3Client(['region' => 'ap-southeast-1', 'version' => 'latest']); // composer require aws/aws-sdk-php
$adapter = new S3StorageAdapter($client, ['bucket' => 'secure-files']);

// Google Cloud Storage — objek bucket wajib punya upload()/object();
// objek hasilnya cukup punya downloadAsString()/exists()/delete().
$bucket  = (new \Google\Cloud\Storage\StorageClient())->bucket('secure-files'); // google/cloud-storage
$adapter = new GcsStorageAdapter($bucket);

$storage = new SecureFileStorage(LocalKms::fromEnv(), $adapter); // KMS boleh Vault/AWS/GCP/Azure apa saja
```

## Referensi API

| Class / Method | Peran |
|----------------|-------|
| `SecureFileStorage::__construct(Kms, StorageAdapterInterface, opts)` | Wiring KMS + adapter; `opts`: `chunkSize`, `onSecurityEvent`, `clock` |
| `SecureFileStorage::store($srcPath, $meta)` | Enkripsi + simpan blob; kembalikan `FileManifest` |
| `SecureFileStorage::retrieve($m, $destPath)` | Verifikasi digest → dekripsi → tulis atomik ke file; `['path','size']` |
| `SecureFileStorage::retrieveStream($m, $sink, opts)` | Verifikasi + dekripsi → hook watermark opsional → kirim plaintext ke callback per chunk ±64KB; `opts`: `beforeStream`, `requester` |
| `SecureFileStorage::delete($m)` | Hapus blob ciphertext dari adapter (emit `file_deleted`) |
| `SecureFileStorage::exists($m)` | Cek keberadaan blob milik manifest |
| `FileManifest::fromArray($data)` | Bangun manifest tervalidasi dari array/row DB (fail-closed) |
| `FileManifest::toArray()` | Serialisasi ke array polos — aman dipersist/JSON-kan |
| `FileManifest::fileId() / kekId() / size() / ...` | Accessor field immutable |
| `LocalStorageAdapter($rootDir, opts)` | Adapter filesystem lokal; tulis atomik tmp+rename; `dirMode` default `0770` |
| `S3StorageAdapter($s3Client, opts)` | Adapter S3 duck-typed; `opts['bucket']` wajib |
| `GcsStorageAdapter($bucketClient)` | Adapter GCS duck-typed pada objek bucket |
| `StorageAdapterInterface` | Kontrak `put/get/delete/exists` untuk adapter kustom |

### Event Audit

Pasang lewat `onSecurityEvent` di konstruktor (handler `(string $event, array $context)`, konteks selalu non-secret):

| Event (`SecurePayload::EVENT_*`) | Konteks | Kapan |
|----------------------------------|---------|-------|
| `EVENT_FILE_STORED` (`file_stored`) | `file_id`, `size`, `client_id`, `purpose` | File berhasil dienkripsi & disimpan |
| `EVENT_FILE_WATERMARKED` (`file_watermarked`) | `file_id` | Hook watermark `beforeStream` berhasil diterapkan di `retrieveStream()` |
| `EVENT_FILE_WATERMARK_FAILED` (`file_watermark_failed`) | `file_id` | Hook watermark melempar exception — streaming dibatalkan (fail-closed) |
| `EVENT_FILE_DELETED` (`file_deleted`) | `file_id` | Blob ciphertext dihapus dari adapter |

## Watermark Forensik

`retrieveStream()` menerima opsi `beforeStream`: hook yang menyisipkan **watermark identitas pemegang** ke dokumen sebelum satu byte pun dikirim — memberi jejak jika dokumen bocor dari sisi yang berwenang (plan §5.4). Library tetap **PDF-agnostic**: transformasi dokumen adalah urusan pemanggil (mis. stamp teks/gambar via `mpdf/mpdf` untuk PDF, lihat `composer suggest`).

```php
$storage->retrieveStream(
    $m,
    function (string $chunk): void {
        echo $chunk;                       // plaintext TERWATERMARK per chunk ±64KB
    },
    [
        // Konteks peminta non-secret, diteruskan utuh ke hook:
        'requester' => ['user_id' => 'u-42', 'unit' => 'finance'],

        // Kontrak: callable(string $plain, FileManifest $m, array $ctx): string
        // Menerima plaintext PENUH → mengembalikan plaintext BARU terwatermark.
        'beforeStream' => function (string $plain, FileManifest $m, array $ctx): string {
            // Contoh generik (teks); untuk PDF nyata gunakan mpdf di sini.
            return "LISENSI user={$ctx['requester']['user_id']} file={$ctx['file_id']}\n" . $plain;
        },
    ]
);
```

**Urutan eksekusi:** unwrapDek → decryptVerifiedBlob (digest + AEAD) → **hook** → str_split 64KB → sink. Hook dipanggil tepat **satu kali sebelum chunk pertama**, sehingga kegagalan hook menjamin **NOL byte body terkirim**.

**Kontrak & error handling (fail-closed):**

- Return bukan string atau `beforeStream` non-callable → `BAD_REQUEST`.
- Exception dari hook dipropagasi sebagai `SERVER_ERROR` (exception asli ter-chain sebagai `previous`) setelah event `file_watermark_failed` di-emit — streaming dibatalkan.
- Plaintext kosong tetap memanggil hook (kontrak seragam); loop chunk saja yang dilewati.

**Caveat HTTP:** ukuran akhir body baru diketahui *setelah* hook jalan, jadi `Content-Length` tidak dapat diset sebelum panggilan — gunakan transfer chunked saat watermark aktif.

**Catatan memori:** hasil watermark boleh lebih besar dari `manifest.size`; aman karena pemeriksaan ukuran terjadi di gerbang dekripsi *sebelum* hook berjalan dan hasil hook tidak diverifikasi ulang terhadap manifest.

**Mengapa `retrieve()` tidak di-hook (v1):** `retrieve()` menulis ke path file internal milik aplikasi (restore/arsip), bukan jalur distribusi ke pemegang dokumen — jejak forensik hanya relevan pada jalur keluar `retrieveStream()`.

Contoh wiring end-to-end di endpoint unduhan: [`examples/secure-delivery/download_endpoint.php`](../examples/secure-delivery/download_endpoint.php).

## Invariant Keamanan

- **AAD binding wrap-DEK.** DEK dibungkus KMS dengan AAD `ksort({file_id, kek_id, purpose})`. Memindahkan wrapped DEK dari manifest A ke manifest B (atau menukar blob antar file) membuat `unwrap` gagal — substitusi antar file mustahil tanpa terdeteksi.
- **Digest dicek `hash_equals` SEBELUM dekripsi.** Blob dari adapter diverifikasi `sha256=`-nya terhadap `cipher_digest` manifest lebih dahulu; blob rusak/dimanipulasi ditolak (`UNPROCESSABLE`) sebelum kode kripto dieksekusi.
- **TAG_FINAL anti-truncation & append.** Setiap frame secretstream mengikat AAD biner `{v, file_id}`; memotong ekor blob atau menempelkan data tambahan menggagalkan autentikasi AEAD. Ukuran plaintext akhir juga wajib persis sama dengan `size` manifest.
- **Nama blob tak bisa ditebak.** `file_id` = 16 byte acak (32 karakter hex lowercase), dan semua adapter menolak key di luar pola `^[a-f0-9]{32}$` — tidak ada path traversal, tidak ada key arbitrer.
- **Crypto-shredding.** `delete()` hanya menghapus ciphertext. Penghapusan menyeluruh = hapus **manifest/wrapped DEK** di DB aplikasi + (opsional) musnahkan KEK di KMS. Blob yatim tanpa wrapped DEK (dan KEK-nya) tidak bisa dibuka siapa pun, termasuk operator penyimpanan.
- **Trade-off memori `retrieveStream()`.** Codec bekerja pada blob utuh di memori sehingga pemakaian puncak ≤ ukuran file (plaintext + ciphertext); buffer sink tetap 64KB per panggilan. Untuk file sangat besar, pertimbangkan batas `memory_limit` — inkrementalisasi pull-per-frame dapat diimplementasikan bila dibutuhkan di masa depan.
- **Fail-closed tanpa output parsial.** Kegagalan KMS/digest/AEAD tidak pernah menghasilkan file setengah jadi; penulisan tujuan dan blob lokal memakai pola tmp+rename dengan cleanup di `finally`.
- **Watermark fail-closed.** Hook `beforeStream` berjalan sebelum chunk pertama: gagal (exception/return non-string) = streaming dibatalkan dengan NOL byte body terkirim — dokumen tidak pernah keluar tanpa watermark. Konteks event hanya memuat `file_id` (non-secret); identitas pemegang hidup di sisi aplikasi, bukan di event audit.

## Batasan

- Key adapter wajib cocok regex `^[a-f0-9]{32}$` (32 karakter hex **lowercase**) — bentuk `file_id` yang dihasilkan `store()`.
- `chunkSize` valid di rentang **1KiB–8MiB**; nilai di luar rentang ditolak `BAD_REQUEST`.
- Wajib `ext-sodium` (AEAD/secretstream).
- `store()` menuntut `meta['client_id']` dan `meta['kek_id']` bertipe string non-kosong; `metadata` wajib map `string=>string`.
