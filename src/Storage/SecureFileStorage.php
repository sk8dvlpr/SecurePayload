<?php
declare(strict_types=1);

namespace SecurePayload\Storage;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\EventEmitter;
use SecurePayload\KMS\Kms;
use SecurePayload\Storage\Internal\EnvelopeCodec;
use SecurePayload\SecurePayload;

/**
 * Storage file terenkripsi end-to-end — bagian modul Storage inti.
 *
 * Arsitektur: DEK acak per file (32 byte) mengenkripsi isi via
 * secretstream XChaCha20-Poly1305 (blob self-contained); DEK dibungkus
 * KMS dengan AAD binding file_id+kek_id+purpose dan disimpan DI DALAM
 * FileManifest, bukan di samping blob. Blob di adapter murni
 * ciphertext tanpa metadata — integritasnya diverifikasi cipher_digest
 * sebelum dekripsi.
 *
 * Fail-closed: kegagalan KMS/digest/AEAD tidak pernah menghasilkan output
 * parsial; penulisan plaintext memakai tmp+rename agar file tujuan tidak
 * pernah tertinggal setengah jadi.
 */
final class SecureFileStorage
{
    /** Versi format storage internal — independen dari wire protocol v3/v4. */
    public const STORAGE_FORMAT_VERSION = '1';

    private const DEFAULT_CHUNK_SIZE = 65536;
    private const MIN_CHUNK = 1024;
    /** Batas atas sama dengan FileStreamService (8MiB). */
    private const MAX_CHUNK = 8 * 1024 * 1024;
    /** Ukuran potongan saat retrieveStream mengirim plaintext ke sink. */
    private const SINK_CHUNK = 65536;

    private Kms $kms;
    private StorageAdapterInterface $adapter;
    private int $chunkSize;
    private EventEmitter $events;
    /** @var callable callable():int */
    private $clock;

    /**
     * @param array{chunkSize?:int,onSecurityEvent?:callable,clock?:callable} $opts
     *        chunkSize       : ukuran chunk plaintext per frame (default 65536; rentang 1KiB–8MiB).
     *        onSecurityEvent : handler event keamanan (string $event, array $context) — WAJIB non-secret.
     *        clock           : sumber waktu callable():int untuk created_at (injectable untuk test).
     *
     * @throws SecurePayloadException BAD_REQUEST bila opts tidak valid.
     */
    public function __construct(Kms $kms, StorageAdapterInterface $adapter, array $opts = [])
    {
        if (isset($opts['chunkSize'])) {
            if (!is_int($opts['chunkSize']) || $opts['chunkSize'] < self::MIN_CHUNK || $opts['chunkSize'] > self::MAX_CHUNK) {
                throw new SecurePayloadException('chunkSize di luar rentang wajar (1KiB–8MiB)', SecurePayloadException::BAD_REQUEST);
            }
            $this->chunkSize = $opts['chunkSize'];
        } else {
            $this->chunkSize = self::DEFAULT_CHUNK_SIZE;
        }
        if (isset($opts['onSecurityEvent']) && !is_callable($opts['onSecurityEvent'])) {
            throw new SecurePayloadException('onSecurityEvent wajib berupa callable', SecurePayloadException::BAD_REQUEST);
        }
        if (isset($opts['clock']) && !is_callable($opts['clock'])) {
            throw new SecurePayloadException('clock wajib berupa callable', SecurePayloadException::BAD_REQUEST);
        }
        $this->kms = $kms;
        $this->adapter = $adapter;
        $this->events = new EventEmitter($opts['onSecurityEvent'] ?? null);
        $this->clock = $opts['clock'] ?? static fn (): int => time();
    }

    /**
     * Enkripsi file sumber dan simpan blob ciphertext ke adapter.
     *
     * @param array{client_id:string,kek_id:string,purpose?:string,metadata?:array<string,string>} $meta
     *        client_id/kek_id wajib non-kosong; client_id & purpose hanya provenance
     *        (diteruskan ke konteks event), binding kriptografis memakai AAD.
     *
     * @throws SecurePayloadException BAD_REQUEST bila input tidak valid,
     *                                SERVER_ERROR bila KMS/adapter gagal.
     */
    public function store(string $srcPath, array $meta): FileManifest
    {
        EnvelopeCodec::ensureSodium();
        $clientId = $meta['client_id'] ?? null;
        if (!is_string($clientId) || $clientId === '') {
            throw new SecurePayloadException("meta['client_id'] wajib ada dan bertipe string non-kosong", SecurePayloadException::BAD_REQUEST);
        }
        $kekId = $meta['kek_id'] ?? null;
        if (!is_string($kekId) || $kekId === '') {
            throw new SecurePayloadException("meta['kek_id'] wajib ada dan bertipe string non-kosong", SecurePayloadException::BAD_REQUEST);
        }
        $purpose = null;
        if (array_key_exists('purpose', $meta)) {
            if (!is_string($meta['purpose']) || $meta['purpose'] === '') {
                throw new SecurePayloadException("meta['purpose'] bila diisi wajib string non-kosong", SecurePayloadException::BAD_REQUEST);
            }
            $purpose = $meta['purpose'];
        }
        $metadata = $meta['metadata'] ?? [];
        if (!is_array($metadata)) {
            throw new SecurePayloadException("meta['metadata'] wajib bertipe array<string,string>", SecurePayloadException::BAD_REQUEST);
        }
        foreach ($metadata as $mk => $mv) {
            if (!is_string($mk) || !is_string($mv)) {
                throw new SecurePayloadException("meta['metadata'] wajib berisi pasangan key/value string", SecurePayloadException::BAD_REQUEST);
            }
        }

        if (!is_file($srcPath) || !is_readable($srcPath)) {
            throw new SecurePayloadException("File sumber tidak ditemukan/terbaca: $srcPath", SecurePayloadException::BAD_REQUEST);
        }
        $in = fopen($srcPath, 'rb');
        if ($in === false) {
            throw new SecurePayloadException("Gagal membuka file sumber: $srcPath", SecurePayloadException::BAD_REQUEST);
        }

        try {
            // file_id 32 hex lowercase acak � tidak bisa ditebak/dienumerasi.
            $fileId = bin2hex(random_bytes(16));
            $dek = random_bytes(32);

            // AAD wrap DEK: ksort+json_encode dilakukan implementasi Kms.
            $aadWrap = [
                'file_id' => $fileId,
                'kek_id' => $kekId,
                'purpose' => 'securepayload-file-dek',
            ];
            $wrappedDekB64 = $this->kms->wrap($kekId, $dek, $aadWrap);

            // AAD frame biner mengikat setiap frame secretstream ke versi format + file_id.
            $aadFrame = json_encode([
                'v' => self::STORAGE_FORMAT_VERSION,
                'file_id' => $fileId,
            ]);

            $enc = EnvelopeCodec::encryptStream($in, $dek, $aadFrame, $this->chunkSize);
            $this->adapter->put($fileId, $enc['blob']);

            $manifest = FileManifest::fromArray([
                'v' => self::STORAGE_FORMAT_VERSION,
                'alg' => SecurePayload::STREAM_ALG,
                'file_id' => $fileId,
                'kek_id' => $kekId,
                'wrapped_dek_b64' => $wrappedDekB64,
                'aad_context' => $aadWrap,
                'size' => $enc['size'],
                'cipher_digest' => $enc['digest'],
                'chunk_size' => $this->chunkSize,
                'created_at' => ($this->clock)(),
                'metadata' => $metadata,
            ]);

            $this->events->emit(SecurePayload::EVENT_FILE_STORED, [
                'file_id' => $fileId,
                'size' => $enc['size'],
                'client_id' => $clientId,
                'purpose' => $purpose,
            ]);
            return $manifest;
        } finally {
            fclose($in);
        }
    }

    /**
     * Verifikasi integritas blob lalu dekripsi penuh ke $destPath.
     *
     * Penulisan memakai file sementara + rename di direktori yang sama:
     * bila proses gagal di tengah jalan, file parsial dihapus dan
     * $destPath yang sudah ada sebelumnya tidak tersentuh.
     *
     * @return array{path:string,size:int}
     *
     * @throws SecurePayloadException UNAUTHORIZED bila wrapped DEK/AEAD gagal dibuka,
     *                                UNPROCESSABLE bila digest/ukuran tidak cocok atau blob rusak.
     */
    public function retrieve(FileManifest $m, string $destPath): array
    {
        $dek = $this->unwrapDek($m);
        $plain = $this->decryptVerifiedBlob($m, $dek);

        $dir = dirname($destPath);
        if (!is_dir($dir)) {
            throw new SecurePayloadException("Direktori tujuan tidak ada: $dir", SecurePayloadException::BAD_REQUEST);
        }
        $tmp = $destPath . '.tmp-' . bin2hex(random_bytes(8));
        try {
            if (@file_put_contents($tmp, $plain, LOCK_EX) === false) {
                throw new SecurePayloadException("Gagal menulis file tujuan: $destPath", SecurePayloadException::SERVER_ERROR);
            }
            if (!@rename($tmp, $destPath)) {
                throw new SecurePayloadException("Gagal memindahkan file hasil dekripsi ke: $destPath", SecurePayloadException::SERVER_ERROR);
            }
        } finally {
            // Fail-closed cleanup: file sementara tidak boleh tertinggal.
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        }

        return ['path' => $destPath, 'size' => strlen($plain)];
    }

    /**
     * Dekripsi blob lalu kirim plaintext ke $sink per chunk ±64KB.
     *
     * URUTAN EKSEKUSI: unwrapDek → decryptVerifiedBlob (digest + AEAD) →
     * hook watermark `beforeStream` (bila dipasang) → str_split 64KB → sink.
     *
     * WATERMARK FORENSIK (plan §5.4, opsi `beforeStream`):
     * Hook menerima plaintext penuh, manifest, dan konteks peminta lalu
     * mengembalikan plaintext BARU yang sudah terwatermark:
     *     callable(string $plain, FileManifest $m, array $ctx): string
     * dengan `$ctx = ['file_id' => ..., 'requester' => ...]`. Library tetap
     * PDF-agnostic — transformasi dokumen (mis. stamp mpdf) adalah urusan
     * pemanggil. Hook dipanggil TEPAT SATU kali SEBELUM chunk pertama
     * dikirim, sehingga kegagalan hook menjamin NOL byte body terkirim
     * (fail-closed): exception dari hook dipropagasi setelah event
     * EVENT_FILE_WATERMARK_FAILED di-emit; return bukan string,
     * beforeStream non-callable, atau requester non-array → BAD_REQUEST.
     * Catatan memori: hasil watermark boleh lebih besar dari manifest.size
     * karena pemeriksaan ukuran terjadi di decryptVerifiedBlob SEBELUM hook
     * berjalan; hasil hook tidak diverifikasi ulang terhadap manifest.
     * Caveat HTTP: ukuran akhir body baru diketahui SETELAH hook jalan,
     * sehingga Content-Length tidak dapat diset sebelum panggilan — gunakan
     * transfer chunked saat memakai watermark.
     *
     * Plaintext kosong tetap memanggil hook (kontrak seragam); loop
     * str_split saja yang dilewati.
     *
     * retrieve() TIDAK di-hook pada v1: method itu menulis ke path file
     * internal milik aplikasi (restore/arsip), bukan jalur distribusi ke
     * pemegang dokumen — jejak forensik hanya relevan pada jalur keluar
     * retrieveStream().
     *
     * TRADE-OFF MEMORI (dokumentasi): codec bekerja pada blob utuh di memori,
     * sehingga pemakaian puncak ≤ ukuran file (plaintext + blob). Ini tetap
     * membatasi buffer sink ke 64KB per panggilan; inkrementalisasi penuh
     * pull-per-frame dapat diinkrementalkan pada iterasi berikutnya bila dibutuhkan.
     *
     * @param callable(string $chunk):void $sink
     * @param array{beforeStream?:callable|null,requester?:array<string,string>} $opts
     *        beforeStream : hook watermark (lihat kontrak di atas); null = tanpa watermark.
     *        requester    : konteks peminta non-secret, diteruskan utuh ke hook via $ctx['requester'].
     *
     * @throws SecurePayloadException BAD_REQUEST bila opts tidak valid;
     *                                SERVER_ERROR bila hook melempar exception
     *                                (previous exception tetap ter-chain);
     *                                selainnya sama seperti retrieve().
     */
    public function retrieveStream(FileManifest $m, callable $sink, array $opts = []): void
    {
        $hook = $opts['beforeStream'] ?? null;
        if ($hook !== null && !is_callable($hook)) {
            throw new SecurePayloadException("opts['beforeStream'] wajib berupa callable", SecurePayloadException::BAD_REQUEST);
        }
        $requester = $opts['requester'] ?? null;
        if ($requester !== null && !is_array($requester)) {
            throw new SecurePayloadException("opts['requester'] wajib bertipe array<string,string>", SecurePayloadException::BAD_REQUEST);
        }

        $dek = $this->unwrapDek($m);
        $plain = $this->decryptVerifiedBlob($m, $dek);

        if ($hook !== null) {
            try {
                /** @var mixed $watermarked */
                $watermarked = $hook($plain, $m, ['file_id' => $m->fileId(), 'requester' => $requester]);
            } catch (\Throwable $e) {
                $this->events->emit(SecurePayload::EVENT_FILE_WATERMARK_FAILED, ['file_id' => $m->fileId()]);
                throw new SecurePayloadException(
                    'Watermark forensik gagal: hook beforeStream melempar exception (' . $e->getMessage() . ')',
                    SecurePayloadException::SERVER_ERROR,
                    ['file_id' => $m->fileId()],
                    $e
                );
            }
            if (!is_string($watermarked)) {
                throw new SecurePayloadException("opts['beforeStream'] wajib mengembalikan string plaintext terwatermark", SecurePayloadException::BAD_REQUEST);
            }
            $this->events->emit(SecurePayload::EVENT_FILE_WATERMARKED, ['file_id' => $m->fileId()]);
            $plain = $watermarked;
        }

        if ($plain !== '') {
            foreach (str_split($plain, self::SINK_CHUNK) as $chunk) {
                $sink($chunk);
            }
        }
    }

    /**
     * Hapus blob ciphertext dari adapter.
     *
     * CRYPTO-SHREDDING: method ini hanya menghapus ciphertext. Untuk
     * penghapusan menyeluruh, pemanggil WAJIB menghapus baris manifest/
     * wrapped-DEK di DB aplikasinya sendiri — ciphertext yatim tanpa
     * wrapped-DEK (dan KEK yang sesuai) tidak bisa dibuka siapa pun.
     */
    public function delete(FileManifest $m): void
    {
        $this->adapter->delete($m->fileId());
        $this->events->emit(SecurePayload::EVENT_FILE_DELETED, ['file_id' => $m->fileId()]);
    }

    /** Cek keberadaan blob ciphertext milik manifest. */
    public function exists(FileManifest $m): bool
    {
        return $this->adapter->exists($m->fileId());
    }

    /**
     * Buka wrapped DEK dari manifest via KMS. Gagal → UNAUTHORIZED.
     *
     * Fail-closed lebih dulu: manifest dari versi format atau algoritma berbeda
     * ditolak SEBELUM menyentuh KMS/adapter (titik cek tunggal bagi retrieve()
     * dan retrieveStream()).
     *
     * @throws SecurePayloadException UNPROCESSABLE bila manifest versi/alg tidak cocok;
     *                                UNAUTHORIZED bila unwrap gagal.
     */
    private function unwrapDek(FileManifest $m): string
    {
        if ($m->v() !== self::STORAGE_FORMAT_VERSION) {
            throw new SecurePayloadException(
                'Manifest versi format "' . $m->v() . '" tidak didukung (diharapkan "' . self::STORAGE_FORMAT_VERSION . '")',
                SecurePayloadException::UNPROCESSABLE,
                ['file_id' => $m->fileId()]
            );
        }
        if ($m->alg() !== SecurePayload::STREAM_ALG) {
            throw new SecurePayloadException(
                'Manifest algoritma "' . $m->alg() . '" tidak cocok (diharapkan "' . SecurePayload::STREAM_ALG . '")',
                SecurePayloadException::UNPROCESSABLE,
                ['file_id' => $m->fileId()]
            );
        }
        try {
            return $this->kms->unwrap($m->kekId(), $m->wrappedDekB64(), $m->aadContext());
        } catch (\Throwable $e) {
            throw new SecurePayloadException(
                'Wrapped DEK tidak dapat dibuka (KEK tidak dikenal, AAD tidak cocok, atau blob wrapped rusak)',
                SecurePayloadException::UNAUTHORIZED,
                ['file_id' => $m->fileId(), 'kek_id' => $m->kekId()]
            );
        }
    }

    /**
     * Ambil blob dari adapter, verifikasi cipher_digest vs manifest
     * (hash_equals, SEBELUM dekripsi), lalu dekripsi dan cek ukuran.
     *
     * @return string Plaintext penuh.
     *
     * @throws SecurePayloadException UNPROCESSABLE bila digest/ukuran tidak cocok;
     *                                UNAUTHORIZED bila AEAD auth gagal.
     */
    private function decryptVerifiedBlob(FileManifest $m, string $dek): string
    {
        $blob = $this->adapter->get($m->fileId());
        $digest = 'sha256=' . base64_encode(hash('sha256', $blob, true));
        if (!hash_equals($m->cipherDigest(), $digest)) {
            throw new SecurePayloadException(
                'Integritas blob gagal: cipher_digest tidak cocok dengan manifest',
                SecurePayloadException::UNPROCESSABLE,
                ['file_id' => $m->fileId()]
            );
        }

        $aadFrame = json_encode([
            'v' => self::STORAGE_FORMAT_VERSION,
            'file_id' => $m->fileId(),
        ]);
        $plain = EnvelopeCodec::decryptStream($blob, $dek, $aadFrame);

        if (strlen($plain) !== $m->size()) {
            throw new SecurePayloadException(
                "Ukuran plaintext (" . strlen($plain) . ") tidak sesuai manifest ({$m->size()})",
                SecurePayloadException::UNPROCESSABLE,
                ['file_id' => $m->fileId()]
            );
        }
        return $plain;
    }
}
