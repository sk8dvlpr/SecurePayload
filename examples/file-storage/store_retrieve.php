<?php
declare(strict_types=1);

/**
 * Contoh CLI: simpan & ambil file terenkripsi (envelope encryption) — Storage.
 *
 * Alur:
 *   1. Wiring: LocalKms (KEK dari env) + LocalStorageAdapter (blob di direktori lokal).
 *   2. store(): plaintext → blob ciphertext (DEK per file, di-wrap KEK).
 *   3. Persist FileManifest ke file JSON — di produksi, ini tabel DB aplikasi Anda.
 *   4. retrieveStream()/retrieve(): verifikasi digest → unwrap DEK → dekripsi.
 *   5. delete() + hapus manifest = crypto-shredding (blob yatim tak terbuka siapa pun).
 *
 * Jalankan:
 *   php examples/file-storage/store_retrieve.php
 */

use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;

require __DIR__ . '/../../vendor/autoload.php';

// --- 0. KEK dev fallback deterministik (PRODUKSI: set env SECURE_KEKS + SECURE_KEK_<id>_B64 sungguhan) ---
if (getenv('SECURE_KEKS') === false) {
    putenv('SECURE_KEKS=DEMOKEK');
    putenv('SECURE_KEK_DEMOKEK_B64=' . base64_encode(hash('sha256', 'securepayload-demo-kek', true)));
}

$kms     = LocalKms::fromEnv();
$bloss   = sys_get_temp_dir() . '/securepayload-example-blobs';
$adapter = new LocalStorageAdapter($bloss);

$storage = new SecureFileStorage($kms, $adapter, [
    // 'chunkSize' => 256 * 1024,   // opsional: 1KiB–8MiB (default 64KiB)
    'onSecurityEvent' => function (string $event, array $ctx): void {
        echo "[event] {$event} " . json_encode($ctx) . PHP_EOL; // konteks WAJIB non-secret
    },
]);

// --- 1. Siapkan file sumber contoh ---
$src = tempnam(sys_get_temp_dir(), 'sp-plain-');
file_put_contents($src, "Laporan rahasia SecurePayload\nBaris kedua.\n");

// --- 2. Simpan terenkripsi ---
$manifest = $storage->store($src, [
    'client_id' => 'internal-job',              // provenance (masuk konteks event)
    'kek_id'    => 'DEMOKEK',                   // KEK yang membungkus DEK
    'purpose'   => 'contoh-doc',
    'metadata'  => ['nama_asli' => 'laporan.txt'],
]);

echo "file_id       : {$manifest->fileId()}\n";
echo "cipher_digest : {$manifest->cipherDigest()}\n";

// --- 3. Persist manifest (di produksi: INSERT ke tabel DB aplikasi Anda) ---
$manifestFile = sys_get_temp_dir() . '/sp-manifest-' . $manifest->fileId() . '.json';
file_put_contents($manifestFile, json_encode($manifest->toArray()));

// --- 4a. Muat ulang manifest lalu stream isinya ---
$m = FileManifest::fromArray(json_decode((string) file_get_contents($manifestFile), true));

var_dump($storage->exists($m));                 // cek blob masih ada
echo "--- isi (retrieveStream) ---\n";
$storage->retrieveStream($m, static function (string $chunk): void {
    echo $chunk;                                // plaintext per chunk ±64KB
});

// --- 4b. Atau dekripsi penuh ke file tujuan (atomik: tmp + rename) ---
$res = $storage->retrieve($m, $src . '.restored');
echo "--- restored {$res['size']} byte ke {$res['path']} ---\n";

// --- 5. Crypto-shredding: hapus blob + HAPUS JUGA manifest/wrapped-DEK ---
$storage->delete($m);
unlink($manifestFile);                          // tanpa wrapped-DEK, blob yatim tak terbuka siapa pun
unlink($res['path']);
unlink($src);

echo "Selesai. Blob ciphertext sengaja dibiarkan yatim di: {$bloss}\n";
