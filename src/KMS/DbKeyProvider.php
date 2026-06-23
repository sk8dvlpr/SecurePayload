<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use PDO;
use RuntimeException;

/**
 * DbKeyProvider
 * -------------
 * Penyedia kunci yang mengambil data dari database via PDO.
 * Mendukung kunci plaintext (HMAC) dan kunci terenkripsi (AEAD + KMS).
 *
 * Skema tabel default 'secure_keys':
 * - client_id (string)
 * - key_id (string)
 * - hmac_secret (string|null)
 * - aead_key_b64 (string|null)
 * - wrapped_b64 (string|null)
 * - kek_id (string|null)
 * - ed25519_public_b64 (string|null)  -- opsional, hanya dibaca jika opts['useEd25519']=true
 */
final class DbKeyProvider implements SecureKeyProvider
{
    private PDO $pdo;
    private string $table;
    private string $colClient;
    private string $colKey;
    private string $colHmac;
    private string $colAeadB64;
    private string $colWrapped;
    private string $colKekId;
    private string $colEd25519Pub;
    private bool $useEd25519;

    private ?Kms $kms;

    /**
     * @param PDO   $pdo  Koneksi database (harus sudah terkoneksi).
     * @param array $opts Opsional mapping nama tabel/kolom:
     *                    ['table'=>'...', 'colClient'=>'...', 'colKey'=>'...',
     *                     'colHmac'=>'...', 'colAeadB64'=>'...',
     *                     'colWrapped'=>'...', 'colKekId'=>'...',
     *                     'colEd25519Pub'=>'...', 'useEd25519'=>bool]
     *                    Set 'useEd25519'=>true untuk membaca kolom public key Ed25519.
     *                    CATATAN: Nama tabel dan kolom hanya boleh mengandung [A-Za-z0-9_].
     *                             Jangan gunakan SQL Reserved Words sebagai nama kolom.
     * @param Kms|null $kms Instance KMS untuk membuka kunci AEAD yang terbungkus (wrapped).
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
        $this->colEd25519Pub = $opts['colEd25519Pub'] ?? 'ed25519_public_b64';
        // Kolom Ed25519 bersifat opt-in agar kompatibel dengan skema lama yang
        // belum memiliki kolom ini. Aktifkan via opts['useEd25519'] = true.
        $this->useEd25519 = (bool) ($opts['useEd25519'] ?? false);
        $this->kms = $kms;
    }

    /**
     * @return array{hmacSecret:?string,aeadKeyB64:?string,ed25519PublicKeyB64:?string}
     * @throws RuntimeException Jika terjadi kesalahan query atau dekripsi KMS.
     */
    public function load(string $clientId, string $keyId): array
    {
        $cols = [
            $this->q($this->colHmac),
            $this->q($this->colAeadB64),
            $this->q($this->colWrapped),
            $this->q($this->colKekId),
        ];
        if ($this->useEd25519) {
            $cols[] = $this->q($this->colEd25519Pub);
        }

        $sql = sprintf(
            "SELECT %s FROM %s WHERE %s = :cid AND %s = :kid LIMIT 1",
            implode(', ', $cols),
            $this->q($this->table),
            $this->q($this->colClient),
            $this->q($this->colKey),
        );

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':cid' => $clientId, ':kid' => $keyId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            // Tidak ditemukan bukan error, return null values agar SecurePayload handle auth failure
            return ['hmacSecret' => null, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => null];
        }

        $hmacSecret = $row[$this->colHmac] ?? null;
        $aeadKeyB64 = $row[$this->colAeadB64] ?? null;
        $wrappedB64 = $row[$this->colWrapped] ?? null;
        $kekId = $row[$this->colKekId] ?? null;
        $ed25519Pub = $this->useEd25519 ? ($row[$this->colEd25519Pub] ?? null) : null;

        // Logika Unwrapping:
        // Jika AEAD Key belum ada (kosong) TAPI ada wrapped key + kek_id, coba buka via KMS.
        if (
            empty($aeadKeyB64) &&
            is_string($wrappedB64) && $wrappedB64 !== '' &&
            is_string($kekId) && $kekId !== ''
        ) {
            if (!$this->kms) {
                // Konfigurasi salah: Ada data encrypted tapi tidak ada KMS provider
                throw new RuntimeException('Data kunci terenkripsi ditemukan, tapi KMS provider belum dikonfigurasi di DbKeyProvider.');
            }

            try {
                // Context AAD harus sesuai saat pembungkusan (wrapping)
                $aeadKeyRaw = $this->kms->unwrap($kekId, $wrappedB64, [
                    'client_id' => $clientId,
                    'key_id' => $keyId,
                    'purpose' => 'securepayload-aead-key',
                ]);
            } catch (\Exception $e) {
                // Wrap error KMS agar lebih jelas
                throw new RuntimeException('Gagal membuka kunci (unwrap) via KMS: ' . $e->getMessage(), 0, $e);
            }

            if (strlen($aeadKeyRaw) !== 32) {
                throw new RuntimeException('Hasil unwrap KMS tidak valid (harus 32 byte raw).');
            }
            $aeadKeyB64 = base64_encode($aeadKeyRaw);
        }

        return [
            'hmacSecret' => ($hmacSecret !== null && $hmacSecret !== '') ? (string) $hmacSecret : null,
            'aeadKeyB64' => ($aeadKeyB64 !== null && $aeadKeyB64 !== '') ? (string) $aeadKeyB64 : null,
            'ed25519PublicKeyB64' => ($ed25519Pub !== null && $ed25519Pub !== '') ? (string) $ed25519Pub : null,
        ];
    }

    /**
     * Memvalidasi identifier SQL (nama tabel/kolom) agar aman digunakan dalam query.
     * Hanya mengizinkan karakter alfanumerik dan underscore (whitelist).
     * Melempar exception jika identifier mengandung karakter berbahaya.
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
