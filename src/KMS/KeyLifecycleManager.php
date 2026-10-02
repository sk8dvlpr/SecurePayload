<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use InvalidArgumentException;
use PDO;
use RuntimeException;
use SecurePayload\Exceptions\KeyDestroyedException;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Protocol\Aead;
use SecurePayload\Protocol\Canonical;
use SecurePayload\Protocol\Hkdf;
use SecurePayload\SecurePayload;

/**
 * KeyLifecycleManager
 * -------------------
 * Operasi siklus hidup kunci (status/retire/revoke/schedule destroy) plus
 * dekripsi arsip payload dengan kunci TERCATAT di baris arsip (bukan kunci aktif).
 *
 * MENGAPA MEMBACA VIA SQL LANGSUNG (bypass DbKeyProvider):
 * DbKeyProvider::load() sengaja fail-closed — status revoked/destroyed/retiring-kedaluwarsa
 * dikembalikan sebagai array kosong, identik dengan "baris tidak ada". Untuk alur lifecycle
 * kita HARUS bisa membedakan "hancur" vs "memang tidak ada", jadi kelas ini membaca kolom
 * status secara langsung lewat query tersendiri. Keamanan tetap terjaga: identifier SQL
 * divalidasi whitelist regex sama seperti DbKeyProvider, dan semua nilai dibind via prepared
 * statement (tidak ada interpolasi nilai user ke SQL).
 *
 * ASUMSI MATERIAL KUNCI UNTUK decryptArchivedLog():
 * Kolom aead_key_b64 (atau hasil unwrap wrapped_b64 via KMS) adalah MASTER KEY AEAD —
 * material yang sama yang dimuat keyLoader server waktu verifikasi asli. Ini replikasi
 * persis RequestVerifier: raw key dari loader lalu deriveSubkey(KDF_PURPOSE_AEAD_REQ)
 * bila opsi deriveKeys aktif. Jika konfigurasi asli memakai deriveKeys/version/bindHeaders,
 * operator WAJIB mengisi opsi yang sama di konstruktor kelas ini agar parameter dekripsi
 * cocok; mismatch akan gagal-closed (dekripsi gagal), bukan menghasilkan plaintext salah.
 *
 * Konvensi kode error SecurePayloadException yang dipakai (dokumentasi konsistensi):
 * - BAD_REQUEST (400)  : baris kunci tidak ditemukan / data arsip tidak lengkap / mode hmac.
 *                        Kelas ini tooling offline (tanpa layer HTTP), 404 bukan bagian
 *                        kode exception library, jadi "permintaan tidak bisa diproses"
 *                        dipetakan konsisten ke BAD_REQUEST.
 * - UNAUTHORIZED (401) : kunci revoked / masa grace retiring habis / dekripsi gagal.
 * - UNPROCESSABLE(422) : transisi status tidak sah (mis. retire atas kunci destroyed).
 * - SERVER_ERROR (500) : material kunci rusak pada sisi server.
 * - KeyDestroyedException (410) : kunci destroyed — dilempar STANDALONE agar aplikasi
 *                                  dapat menangkapnya terpisah (lihat docblock kelas itu).
 */
final class KeyLifecycleManager
{
    private PDO $pdo;
    private string $table;
    private string $colClient;
    private string $colKey;
    private string $colHmac;
    private string $colAeadB64;
    private string $colWrapped;
    private string $colKekId;
    private string $colStatus;
    private string $colValidUntil;

    /**
     * Fitur destroy opsional (kolom destroy_after, lihat docs/migrations/002_key_destroy.sql).
     * Default false agar kompatibel dengan skema lama; scheduleDestroy()/destroyIfDue()
     * menolak bekerja ketika fitur ini tidak diaktifkan.
     */
    private bool $useDestroyAfter;
    private string $colDestroyAfter;

    /** Replikasi opsi deriveKeys SecurePayloadConfig untuk rekonstruksi subkey AEAD arsip. */
    private bool $deriveKeys;
    private string $version;

    /** @var list<string> Nama header kritikal yang diikat AAD saat verifikasi asli. */
    private array $bindHeaders;

    /** @var callable */
    private $clock;

    private ?Kms $kms;

    /**
     * @param PDO      $pdo  Koneksi database (harus sudah terkoneksi).
     * @param array    $opts Opsi penamaan tabel/kolom (mirror DbKeyProvider):
     *                       ['table'=>'...', 'colClient'=>'...', 'colKey'=>'...',
     *                        'colHmac'=>'...', 'colAeadB64'=>'...', 'colWrapped'=>'...',
     *                        'colKekId'=>'...',
     *                        'useKeyLifecycle'=>bool (diterima demi kompatibilitas opts
     *                            DbKeyProvider; catatan: filtering lifecycle SELALU aktif
     *                            di kelas ini karena memang inti fungsinya),
     *                        'colStatus'=>'...', 'colValidUntil'=>'...',
     *                        'useDestroyAfter'=>bool, 'colDestroyAfter'=>'...',
     *                        'deriveKeys'=>bool, 'version'=>string,
     *                        'bindHeaders'=>list<string>, 'clock'=>callable]
     *                       CATATAN: Nama tabel/kolom hanya boleh [A-Za-z0-9_].
     * @param Kms|null $kms  Instance KMS untuk membuka kunci arsip yang terbungkus (wrapped).
     */
    public function __construct(PDO $pdo, array $opts = [], ?Kms $kms = null)
    {
        $this->pdo = $pdo;
        $this->table = $opts['table'] ?? 'secure_keys';
        $this->colClient = $opts['colClient'] ?? 'client_id';
        $this->colKey = $opts['colKey'] ?? 'key_id';
        $this->colHmac = $opts['colHmac'] ?? 'hmac_secret';
        $this->colAeadB64 = $opts['colAeadB64'] ?? 'aead_key_b64';
        $this->colWrapped = $opts['colWrapped'] ?? 'wrapped_b64';
        $this->colKekId = $opts['colKekId'] ?? 'kek_id';
        $this->colStatus = $opts['colStatus'] ?? 'status';
        $this->colValidUntil = $opts['colValidUntil'] ?? 'valid_until';
        $this->useDestroyAfter = (bool) ($opts['useDestroyAfter'] ?? false);
        $this->colDestroyAfter = $opts['colDestroyAfter'] ?? 'destroy_after';
        $this->deriveKeys = !empty($opts['deriveKeys']);
        $this->version = (string) ($opts['version'] ?? SecurePayload::DEFAULT_VERSION);
        $bind = $opts['bindHeaders'] ?? [];
        $this->bindHeaders = [];
        if (is_array($bind)) {
            foreach ($bind as $h) {
                if (is_string($h) && $h !== '') {
                    $this->bindHeaders[] = $h;
                }
            }
        }
        $this->clock = $opts['clock'] ?? static fn (): int => time();
        $this->kms = $kms;
    }

    /**
     * Ambil status kunci saat ini (dinormalisasi; kosong/null dianggap active).
     *
     * @return string Salah satu nilai KeyStatus::*.
     * @throws SecurePayloadException BAD_REQUEST jika baris kunci tidak ditemukan.
     */
    public function statusOf(string $clientId, string $keyId): string
    {
        $row = $this->loadRow($clientId, $keyId, [$this->colStatus]);
        if ($row === null) {
            throw new SecurePayloadException(
                "Kunci tidak ditemukan untuk client '$clientId' / key '$keyId'.",
                SecurePayloadException::BAD_REQUEST,
                ['client_id' => $clientId, 'key_id' => $keyId]
            );
        }
        return $this->normalizeStatus($row[$this->colStatus] ?? null);
    }

    /**
     * Retire kunci: status menjadi 'retiring' dengan grace period sampai now + graceSeconds.
     *
     * Transisi dari REVOKED sengaja dilarang: retire menyetel valid_until masa depan,
     * sehingga revoked -> retiring berarti MENGHIDUPKAN KEMBALI akses lewat grace window.
     *
     * @throws InvalidArgumentException Jika graceSeconds <= 0.
     * @throws SecurePayloadException   Kunci tidak ditemukan (400) atau status asal tidak
     *                                  sah — destroyed/revoked (422).
     */
    public function retire(string $clientId, string $keyId, int $graceSeconds): void
    {
        if ($graceSeconds <= 0) {
            throw new InvalidArgumentException('graceSeconds harus lebih besar dari 0.');
        }
        $this->requireMutableRow($clientId, $keyId, [KeyStatus::DESTROYED, KeyStatus::REVOKED]);

        $validUntil = ($this->clock)() + $graceSeconds;
        $stmt = $this->pdo->prepare(sprintf(
            'UPDATE %s SET %s = :status, %s = :valid_until WHERE %s = :cid AND %s = :kid',
            $this->q($this->table),
            $this->q($this->colStatus),
            $this->q($this->colValidUntil),
            $this->q($this->colClient),
            $this->q($this->colKey)
        ));
        $stmt->execute([
            ':status' => KeyStatus::RETIRING,
            ':valid_until' => $validUntil,
            ':cid' => $clientId,
            ':kid' => $keyId,
        ]);
    }

    /**
     * Revoke kunci segera (tanpa grace period): status 'revoked', valid_until dikosongkan.
     *
     * @throws SecurePayloadException Kunci tidak ditemukan (400) atau sudah destroyed (422).
     */
    public function revoke(string $clientId, string $keyId): void
    {
        $this->requireMutableRow($clientId, $keyId);

        $stmt = $this->pdo->prepare(sprintf(
            'UPDATE %s SET %s = :status, %s = NULL WHERE %s = :cid AND %s = :kid',
            $this->q($this->table),
            $this->q($this->colStatus),
            $this->q($this->colValidUntil),
            $this->q($this->colClient),
            $this->q($this->colKey)
        ));
        $stmt->execute([
            ':status' => KeyStatus::REVOKED,
            ':cid' => $clientId,
            ':kid' => $keyId,
        ]);
    }

    /**
     * Jadwalkan penghancuran kunci pada unix timestamp tertentu (status TIDAK berubah;
     * eksekusi aktual dilakukan destroyIfDue()). Butuh kolom destroy_after
     * (docs/migrations/002_key_destroy.sql) dan opsi useDestroyAfter=true.
     *
     * Catatan crypto-shredding: metode ini HANYA menandai jadwal. Penghapusan/pemusnahan
     * fisik material secret adalah kebijakan DBA — kelas ini sengaja tidak menimpa kolom
     * secret agar perilaku deterministik dan dapat diaudit.
     *
     * @throws RuntimeException        Jika fitur destroy tidak diaktifkan (useDestroyAfter=false).
     * @throws SecurePayloadException  Kunci tidak ditemukan (400) atau sudah destroyed (422).
     */
    public function scheduleDestroy(string $clientId, string $keyId, int $destroyAfterTs): void
    {
        $this->requireDestroyFeature();
        $this->requireMutableRow($clientId, $keyId);

        $stmt = $this->pdo->prepare(sprintf(
            'UPDATE %s SET %s = :destroy_after WHERE %s = :cid AND %s = :kid',
            $this->q($this->table),
            $this->q($this->colDestroyAfter),
            $this->q($this->colClient),
            $this->q($this->colKey)
        ));
        $stmt->execute([
            ':destroy_after' => $destroyAfterTs,
            ':cid' => $clientId,
            ':kid' => $keyId,
        ]);
    }

    /**
     * Eksekusi destroy jika jadwalnya sudah jatuh tempo.
     *
     * Aturan:
     * - baris tidak ada / destroy_after NULL / belum due / sudah destroyed -> false (tanpa efek).
     * - destroy_after <= now -> UPDATE status='destroyed', return true.
     *
     * ATOMIK: dieksekusi sebagai SATU pernyataan UPDATE berkondisi (bukan read-then-update)
     * agar dua worker cron yang berjalan bersamaan tidak sama-sama membaca status lama lalu
     * saling menimpa — hanya satu yang mendapat rowCount > 0. Kondisi `(status IS NULL OR
     * status <> 'destroyed')` menangani skema lama yang statusnya NULL/kosong.
     * Nilai param dibind dengan nama placeholder BERBEDA untuk nilai identik agar aman
     * pada driver PDO native-prepare yang melarang placeholder bernama duplikat.
     *
     * Material secret sengaja TIDAK di-NULL-kan (crypto-shredding adalah kebijakan DBA);
     * pencegahan dekripsi murni lewat gate status di decryptArchivedLog().
     *
     * @param int|null $now Unix timestamp acuan; default dari clock yang di-inject.
     *
     * @return bool true jika destroy dieksekusi SEKARANG, false jika tidak.
     * @throws RuntimeException Jika fitur destroy tidak diaktifkan (useDestroyAfter=false).
     */
    public function destroyIfDue(string $clientId, string $keyId, ?int $now = null): bool
    {
        $this->requireDestroyFeature();

        $now = $now ?? ($this->clock)();

        // Identifier SQL divalidasi via q() (whitelist regex) sebelum masuk query.
        $stmt = $this->pdo->prepare(sprintf(
            'UPDATE %s SET %s = :new_status'
            . ' WHERE %s = :cid AND %s = :kid'
            . ' AND %s IS NOT NULL AND %s <= :now'
            . ' AND (%s IS NULL OR %s <> :not_destroyed)',
            $this->q($this->table),
            $this->q($this->colStatus),
            $this->q($this->colClient),
            $this->q($this->colKey),
            $this->q($this->colDestroyAfter),
            $this->q($this->colDestroyAfter),
            $this->q($this->colStatus),
            $this->q($this->colStatus)
        ));
        $stmt->execute([
            ':new_status' => KeyStatus::DESTROYED,
            ':cid' => $clientId,
            ':kid' => $keyId,
            ':now' => $now,
            ':not_destroyed' => KeyStatus::DESTROYED,
        ]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Decrypt payload arsip dengan kunci TERCATAT di baris arsip (bukan kunci aktif sekarang).
     *
     * Alur (fail-closed, replikasi persis parameter RequestVerifier):
     *  1. Baca baris kunci via SQL langsung (bypass filter provider — lihat docblock kelas).
     *  2. status destroyed  -> KeyDestroyedException (tangkap terpisah, petakan HTTP 410).
     *  3. status revoked    -> SecurePayloadException UNAUTHORIZED.
     *  4. status retiring dengan grace habis (now > valid_until, atau valid_until NULL
     *     — selaras isKeyLoadable() DbKeyProvider) -> UNAUTHORIZED.
     *  5. Material AEAD: aead_key_b64 dipakai apa adanya; jika kosong, unwrap wrapped_b64
     *     via KMS dengan AAD context identik DbKeyProvider. Tanpa keduanya (mode hmac) ->
     *     BAD_REQUEST "arsip mode hmac tidak memiliki ciphertext".
     *  6. Nonce direkonstruksi dari X-Nonce arsip + method/path/query ARSIP (server-derived;
     *     header X-Canonical-Request sengaja TIDAK dipercaya — security invariant).
     *  7. Kunci final = master dari baris DB lalu HKDF subkey bila opsi deriveKeys aktif
     *     (asumsi lengkap di docblock kelas).
     *  8. Ciphertext = field __aead_b64 pada JSON body arsip; AAD dibangun dari versi +
     *     timestamp header arsip + bindHeaders yang dikonfigurasi (replikasi verifier).
     *
     * @param array{client_id:mixed,key_id:mixed,ciphertext:mixed,
     *              headers:mixed,method:mixed,path:mixed,query:mixed} $log
     *              Rekaman arsip: headers = header request asli saat verifikasi;
     *              method/path/query = nilai yang dipakai server saat verify();
     *              ciphertext = rawBody HTTP saat itu.
     *
     * @return string Plaintext hasil dekripsi (JSON body asli).
     *
     * @throws KeyDestroyedException   Kunci berstatus destroyed.
     * @throws SecurePayloadException  Kunci tidak ada / revoked / grace habis / material
     *                                 tidak cukup / dekripsi gagal.
     * @throws RuntimeException        KMS belum di-inject padahal baris memakai wrapped key,
     *                                 atau unwrap KMS gagal.
     */
    public function decryptArchivedLog(array $log): string
    {
        $cid = isset($log['client_id']) && is_scalar($log['client_id']) ? (string) $log['client_id'] : '';
        $kid = isset($log['key_id']) && is_scalar($log['key_id']) ? (string) $log['key_id'] : '';
        if ($cid === '' || $kid === '') {
            throw new SecurePayloadException('Arsip tidak memuat client_id/key_id yang valid.', SecurePayloadException::BAD_REQUEST);
        }

        // 1. Baris kunci pembawa arsip — bukan kunci aktif.
        $row = $this->loadRow($cid, $kid, [
            $this->colHmac,
            $this->colAeadB64,
            $this->colWrapped,
            $this->colKekId,
            $this->colStatus,
            $this->colValidUntil,
        ]);
        if ($row === null) {
            throw new SecurePayloadException(
                "Baris kunci arsip tidak ditemukan untuk client '$cid' / key '$kid'.",
                SecurePayloadException::BAD_REQUEST,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }

        // 2-4. Gate status lifecycle.
        $status = $this->normalizeStatus($row[$this->colStatus] ?? null);
        if ($status === KeyStatus::DESTROYED) {
            throw new KeyDestroyedException(
                "Kunci arsip '$kid' telah dihancurkan (destroyed); payload tidak dapat didekripsi lagi.",
                410,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }
        if ($status === KeyStatus::REVOKED) {
            throw new SecurePayloadException(
                "Kunci arsip '$kid' telah dicabut (revoked); dekripsi ditolak.",
                SecurePayloadException::UNAUTHORIZED,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }
        if ($status === KeyStatus::RETIRING) {
            $validUntil = $this->intOrNull($row[$this->colValidUntil] ?? null);
            // Selaras isKeyLoadable() DbKeyProvider: retiring tanpa valid_until ATAU
            // now > valid_until dianggap kedaluwarsa.
            if ($validUntil === null || ($this->clock)() > $validUntil) {
                throw new SecurePayloadException(
                    "Masa grace kunci arsip '$kid' telah habis; dekripsi ditolak.",
                    SecurePayloadException::UNAUTHORIZED,
                    ['client_id' => $cid, 'key_id' => $kid, 'valid_until' => $validUntil]
                );
            }
        } elseif ($status !== KeyStatus::ACTIVE) {
            // Whitelist ketat selaras isKeyLoadable() DbKeyProvider: status TIDAK dikenal
            // (mis. typo atau status versi skema lain) ditolak fail-closed, bukan diloloskan.
            throw new SecurePayloadException(
                "Status kunci arsip '$kid' tidak dikenal ('{$status}'); dekripsi ditolak fail-closed.",
                SecurePayloadException::UNAUTHORIZED,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }

        // 5. Material kunci AEAD dari baris.
        $keyRaw = $this->resolveAeadKeyRaw($row, $cid, $kid);

        // Header arsip dinormalisasi UPPERCASE seperti pada RequestVerifier.
        $headers = $this->normalizeHeaders(is_array($log['headers'] ?? null) ? $log['headers'] : []);
        $nonceB64 = $headers[self::upper(SecurePayload::HX_NONCE)] ?? '';
        $ver = $headers[self::upper(SecurePayload::HX_SIG_VER)] ?? '';
        $tsStr = $headers[self::upper(SecurePayload::HX_TIMESTAMP)] ?? '';
        if ($nonceB64 === '' || $ver === '' || $tsStr === '') {
            throw new SecurePayloadException(
                'Header keamanan arsip tidak lengkap (X-Nonce, X-Signature-Version, X-Timestamp wajib ada).',
                SecurePayloadException::BAD_REQUEST
            );
        }

        // 6. Nonce direkonstruksi dari konteks request ARSIP (server-derived).
        $method = strtoupper((string) ($log['method'] ?? ''));
        $path = Canonical::normalizePath(((string) ($log['path'] ?? '')) ?: '/');
        $qStr = $this->canonicalQueryString($log['query'] ?? []);
        $nonceCalc = Aead::aeadNonceFrom($nonceB64, $method, $path, $qStr);

        // 8. Ciphertext dari rawBody arsip (struktur JSON __aead_b64 persis RequestVerifier).
        $rawBody = (string) ($log['ciphertext'] ?? '');
        if ($rawBody === '') {
            throw new SecurePayloadException('Ciphertext arsip kosong.', SecurePayloadException::BAD_REQUEST);
        }
        $json = json_decode($rawBody, true);
        $blobB64 = is_array($json) && isset($json['__aead_b64']) && is_string($json['__aead_b64'])
            ? $json['__aead_b64']
            : '';
        if ($blobB64 === '') {
            throw new SecurePayloadException('Payload AEAD (__aead_b64) tidak ditemukan pada arsip.', SecurePayloadException::BAD_REQUEST);
        }
        $ct = base64_decode($blobB64, true);
        if ($ct === false) {
            throw new SecurePayloadException('Format base64 body arsip rusak.', SecurePayloadException::BAD_REQUEST);
        }

        if (!extension_loaded('sodium')) {
            throw new SecurePayloadException('Ekstensi sodium diperlukan untuk dekripsi arsip AEAD.', SecurePayloadException::SERVER_ERROR);
        }

        // AAD: replikasi persis verifier — versi + timestamp dari HEADER arsip, plus
        // header terikat (bindHeaders) sesuai konfigurasi saat verifikasi asli.
        $boundHeaders = $this->collectBoundHeaders($headers);
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ct,
            Aead::buildRequestAeadAad($ver, $tsStr, $boundHeaders),
            $nonceCalc,
            $keyRaw
        );
        if ($plain === false) {
            throw new SecurePayloadException(
                'Dekripsi arsip gagal (kunci salah atau data rusak).',
                SecurePayloadException::UNAUTHORIZED,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }
        return $plain;
    }

    /**
     * Baca satu baris kunci via SQL langsung (identifier tervalidasi, nilai dibind).
     *
     * @param list<string> $cols Daftar nama kolom yang diambil.
     *
     * @return array<string,mixed>|null Null jika baris tidak ada.
     */
    private function loadRow(string $clientId, string $keyId, array $cols): ?array
    {
        $sel = [];
        foreach ($cols as $c) {
            $sel[] = $this->q($c);
        }
        $sql = sprintf(
            'SELECT %s FROM %s WHERE %s = :cid AND %s = :kid LIMIT 1',
            implode(', ', $sel),
            $this->q($this->table),
            $this->q($this->colClient),
            $this->q($this->colKey)
        );
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':cid' => $clientId, ':kid' => $keyId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /**
     * Pastikan baris kunci ada DAN status asalnya sah untuk transisi.
     *
     * Catatan arah transisi: hanya transisi yang MEMBATASI akses (revoke, schedule
     * destroy, eksekusi destroy) diizinkan dari status apa pun kecuali destroyed —
     * agar operator SELALU bisa mematikan kunci. Transisi yang MELEBARKAN akses
     * (retire) dilarang dari status yang lebih ketat.
     *
     * @param list<string> $blockedFrom Status asal yang dilarang (default: destroyed saja).
     *
     * @return array<string,mixed> Baris minimal berisi kolom status.
     */
    private function requireMutableRow(string $clientId, string $keyId, array $blockedFrom = [KeyStatus::DESTROYED]): array
    {
        $row = $this->loadRow($clientId, $keyId, [$this->colStatus]);
        if ($row === null) {
            throw new SecurePayloadException(
                "Kunci tidak ditemukan untuk client '$clientId' / key '$keyId'.",
                SecurePayloadException::BAD_REQUEST,
                ['client_id' => $clientId, 'key_id' => $keyId]
            );
        }
        $status = $this->normalizeStatus($row[$this->colStatus] ?? null);
        if (in_array($status, $blockedFrom, true)) {
            throw new SecurePayloadException(
                "Kunci '$keyId' berstatus '{$status}' dan tidak dapat ditransisi via operasi ini.",
                SecurePayloadException::UNPROCESSABLE,
                ['client_id' => $clientId, 'key_id' => $keyId, 'status' => $status]
            );
        }
        return $row;
    }

    private function requireDestroyFeature(): void
    {
        if (!$this->useDestroyAfter) {
            throw new RuntimeException(
                'Fitur destroy belum diaktifkan: set opsi useDestroyAfter=true pada '
                . 'KeyLifecycleManager dan tambahkan kolom destroy_after (lihat docs/migrations/002_key_destroy.sql).'
            );
        }
    }

    /**
     * Selesaikan material AEAD raw 32-byte dari baris arsip.
     *
     * Prioritas: aead_key_b64 plaintext -> unwrap wrapped_b64 via KMS (AAD context identik
     * DbKeyProvider). Mode hmac-only (tanpa keduanya) ditolak fail-closed.
     *
     * @param array<string,mixed> $row
     */
    private function resolveAeadKeyRaw(array $row, string $cid, string $kid): string
    {
        $aeadB64 = $row[$this->colAeadB64] ?? null;
        $aeadB64 = (is_string($aeadB64) && $aeadB64 !== '') ? $aeadB64 : null;

        if ($aeadB64 === null) {
            $wrappedB64 = $row[$this->colWrapped] ?? null;
            $kekId = $row[$this->colKekId] ?? null;
            if (is_string($wrappedB64) && $wrappedB64 !== '' && is_string($kekId) && $kekId !== '') {
                if (!$this->kms) {
                    throw new RuntimeException('Data kunci terenkripsi ditemukan pada arsip, tapi KMS provider belum dikonfigurasi di KeyLifecycleManager.');
                }
                try {
                    $raw = $this->kms->unwrap($kekId, $wrappedB64, [
                        'client_id' => $cid,
                        'key_id' => $kid,
                        'purpose' => 'securepayload-aead-key',
                    ]);
                } catch (\Exception $e) {
                    throw new RuntimeException('Gagal membuka kunci (unwrap) via KMS saat decrypt arsip: ' . $e->getMessage(), 0, $e);
                }
                if (strlen($raw) !== 32) {
                    throw new RuntimeException('Hasil unwrap KMS tidak valid (harus 32 byte raw).');
                }
                $aeadB64 = base64_encode($raw);
            }
        }

        if ($aeadB64 === null) {
            $hmacSecret = $row[$this->colHmac] ?? null;
            if (is_string($hmacSecret) && $hmacSecret !== '') {
                throw new SecurePayloadException(
                    'Arsip mode HMAC tidak memiliki material enkripsi (aead_key_b64/wrapped_b64 kosong); '
                    . 'body arsip tidak pernah terenkripsi sehingga tidak dapat didekripsi.',
                    SecurePayloadException::BAD_REQUEST,
                    ['client_id' => $cid, 'key_id' => $kid]
                );
            }
            throw new SecurePayloadException(
                'Baris kunci arsip tidak memiliki material kunci yang cukup (hmac_secret/aead_key_b64/wrapped_b64 kosong).',
                SecurePayloadException::BAD_REQUEST,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }

        $keyRaw = base64_decode($aeadB64, true);
        if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
            throw new SecurePayloadException(
                'Kunci AEAD pada baris arsip tidak valid (harus base64 dari 32 byte).',
                SecurePayloadException::SERVER_ERROR,
                ['client_id' => $cid, 'key_id' => $kid]
            );
        }

        // 7. Replikasi SecurePayloadConfig::deriveSubkey() — no-op bila deriveKeys nonaktif.
        if ($this->deriveKeys) {
            $keyRaw = Hkdf::deriveKey($keyRaw, SecurePayload::KDF_PURPOSE_AEAD_REQ . '|v' . $this->version);
        }
        return $keyRaw;
    }

    /**
     * Susun canonical query string persis seperti RequestVerifier:
     * array -> canonicalQuery; string -> parse_str lalu canonicalQuery.
     *
     * @param mixed $query
     */
    private function canonicalQueryString($query): string
    {
        if (is_array($query)) {
            /** @var array<string,mixed> $query */
            return Canonical::canonicalQuery($query);
        }
        parse_str((string) $query, $qArr);
        return Canonical::canonicalQuery($qArr);
    }

    /**
     * Normalisasi header arsip menjadi map UPPERCASE => nilai.
     *
     * @param array<mixed> $headers
     *
     * @return array<string,string>
     */
    private function normalizeHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k)) {
                continue;
            }
            $out[self::upper($k)] = (string) $v;
        }
        return $out;
    }

    /**
     * Replikasi SecurePayloadConfig::collectBoundHeaders() atas header arsip yang sudah
     * dinormalisasi UPPERCASE: lookup case-insensitive, nama lowercase, terurut ksort.
     *
     * @param array<string,string> $upperHeaders
     *
     * @return array<string,string>
     */
    private function collectBoundHeaders(array $upperHeaders): array
    {
        if ($this->bindHeaders === []) {
            return [];
        }
        $lowerMap = [];
        foreach ($upperHeaders as $k => $v) {
            $lowerMap[strtolower($k)] = $v;
        }
        $out = [];
        foreach ($this->bindHeaders as $name) {
            $lname = strtolower($name);
            $out[$lname] = $lowerMap[$lname] ?? '';
        }
        ksort($out);
        return $out;
    }

    /** Status kosong/null dinormalisasi ke ACTIVE (selaras DbKeyProvider). */
    private function normalizeStatus(mixed $status): string
    {
        return ($status === null || $status === '') ? KeyStatus::ACTIVE : (string) $status;
    }

    private function intOrNull(mixed $v): ?int
    {
        return ($v === null || $v === '') ? null : (int) $v;
    }

    private static function upper(string $s): string
    {
        return strtoupper($s);
    }

    /**
     * Validasi identifier SQL (nama tabel/kolom) — whitelist regex sama seperti
     * DbKeyProvider untuk mencegah SQL injection pada identifier.
     *
     * @throws \InvalidArgumentException Jika identifier tidak valid.
     */
    private function q(string $id): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $id)) {
            throw new \InvalidArgumentException(
                "Nama tabel/kolom tidak valid: '$id'. Hanya huruf, angka, dan underscore yang diizinkan."
            );
        }
        return $id; // Identifier sudah bersih, tidak perlu quoting
    }
}
