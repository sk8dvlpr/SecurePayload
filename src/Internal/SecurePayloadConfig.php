<?php

declare(strict_types=1);

namespace SecurePayload\Internal;

use SecurePayload\Crypto\PqSignerInterface;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Http\HttpTransportInterface;
use SecurePayload\Protocol\Digest;
use SecurePayload\Protocol\Hkdf;
use SecurePayload\SecurePayload;

/**
 * Konfigurasi internal SecurePayload: state konstruktor dan helper kriptografi bersama.
 */
final class SecurePayloadConfig
{
    /** @var 'hmac'|'aead'|'both' Mode keamanan yang digunakan */
    private string $mode;

    /** @var 'hmac'|'ed25519'|'hybrid-mldsa44-ed25519' Algoritma tanda tangan untuk mode hmac/both */
    private string $signAlg;

    /** @var string Versi protokol */
    private string $version;

    private ?string $clientId;
    private ?string $keyId;
    private ?string $hmacSecretRaw;
    private ?string $aeadKeyB64;

    /** @var string|null Secret key Ed25519 (base64, 64 byte) untuk signing request di sisi client */
    private ?string $ed25519SecretKeyB64;

    /** @var string|null Public key Ed25519 server (base64, 32 byte) untuk verifikasi response di sisi client */
    private ?string $ed25519PublicKeyServerB64;

    /** @var string|null Secret key Ed25519 server (base64, 64 byte) untuk signing response di sisi server */
    private ?string $ed25519SecretKeyServerB64;

    /** @var string|null Public key ML-DSA client (base64) untuk verifikasi request hybrid */
    private ?string $mldsaPublicKeyB64;

    /** @var string|null Secret key ML-DSA client (base64) — disimpan untuk dokumentasi; signing via pqSigner */
    private ?string $mldsaSecretKeyB64;

    /** @var string|null Public key ML-DSA server (base64) untuk verifikasi response hybrid */
    private ?string $mldsaPublicKeyServerB64;

    /** @var string|null Secret key ML-DSA server (base64) */
    private ?string $mldsaSecretKeyServerB64;

    /** @var PqSignerInterface|null Signer PQ yang di-inject (wajib jika signAlg hybrid) */
    private ?PqSignerInterface $pqSigner;

    /** @var callable(string,string): array{hmacSecret:?string,aeadKeyB64:?string,ed25519PublicKeyB64:?string,ed25519SecretKeyServerB64:?string,mldsaPublicKeyB64?:?string,mldsaPublicKeyServerB64?:?string}|null Fungsi untuk memuat kunci */
    private $keyLoader;

    /** @var callable(string,int): bool|null Fungsi kustom untuk penyimpanan replay cache */
    private $replayStore;

    /** @var int Time-to-live untuk replay protection (detik) */
    private int $replayTtl;

    /** @var int Toleransi perbedaan waktu jam server (detik) */
    private int $clockSkew;

    /**
     * @var list<string> Nama header kritikal yang nilainya diikat ke AAD AEAD
     */
    private array $bindHeaders;

    /** @var bool Jika true, kunci HMAC & AEAD diturunkan via HKDF */
    private bool $deriveKeys;

    /**
     * @var callable(string, array<string,mixed>): void|null Hook event keamanan.
     */
    private $onSecurityEvent;

    /** @var callable(): int */
    private $clock;

    /** @var callable(): string */
    private $nonceGenerator;

    /** @var callable(): string */
    private $respNonceGenerator;

    /** @var HttpTransportInterface|callable():HttpTransportInterface|null Transport HTTP untuk send()/sendFile() */
    private $httpTransport;

    /**
     * Konstruktor SecurePayloadConfig
     *
     * @param array{
     *   mode?: 'hmac'|'aead'|'both',
     *   signAlg?: 'hmac'|'ed25519'|'hybrid-mldsa44-ed25519',
     *   version?: string,
     *   clientId?: string,
     *   keyId?: string,
     *   hmacSecretRaw?: string|null,
     *   ed25519SecretKeyB64?: string|null,
     *   ed25519PublicKeyServerB64?: string|null,
     *   ed25519SecretKeyServerB64?: string|null,
     *   mldsaSecretKeyB64?: string|null,
     *   mldsaPublicKeyB64?: string|null,
     *   mldsaSecretKeyServerB64?: string|null,
     *   mldsaPublicKeyServerB64?: string|null,
     *   pqSigner?: PqSignerInterface|null,
     *   aeadKeyB64?: string|null,
     *   keyLoader?: callable|null,
     *   replayStore?: callable|null,
     *   replayTtl?: int,
     *   clockSkew?: int,
     *   bindHeaders?: list<string>,
     *   deriveKeys?: bool,
     *   onSecurityEvent?: callable|null,
     *   clock?: callable|null,
     *   nonceGenerator?: callable|null,
     *   respNonceGenerator?: callable|null,
     *   httpTransport?: HttpTransportInterface|callable():HttpTransportInterface|null
     * } $opts
     * @throws SecurePayloadException Jika konfigurasi tidak valid
     */
    public function __construct(array $opts = [])
    {
        $this->mode = $opts['mode'] ?? 'both';
        $this->version = $opts['version'] ?? SecurePayload::DEFAULT_VERSION;
        $this->clientId = $opts['clientId'] ?? null;
        $this->keyId = $opts['keyId'] ?? null;
        $this->hmacSecretRaw = $opts['hmacSecretRaw'] ?? null;
        if (
            isset($this->hmacSecretRaw) &&
            $this->hmacSecretRaw !== null &&
            strlen($this->hmacSecretRaw) < 32
        ) {
            throw new SecurePayloadException(
                'HMAC Secret terlalu pendek. Minimum 32 karakter (rekomendasikan 64 byte hex).',
                SecurePayloadException::BAD_REQUEST
            );
        }
        $this->aeadKeyB64 = $opts['aeadKeyB64'] ?? null;
        $this->ed25519SecretKeyB64 = $opts['ed25519SecretKeyB64'] ?? null;
        $this->ed25519PublicKeyServerB64 = $opts['ed25519PublicKeyServerB64'] ?? null;
        $this->ed25519SecretKeyServerB64 = $opts['ed25519SecretKeyServerB64'] ?? null;
        $this->mldsaSecretKeyB64 = $opts['mldsaSecretKeyB64'] ?? null;
        $this->mldsaPublicKeyB64 = $opts['mldsaPublicKeyB64'] ?? null;
        $this->mldsaSecretKeyServerB64 = $opts['mldsaSecretKeyServerB64'] ?? null;
        $this->mldsaPublicKeyServerB64 = $opts['mldsaPublicKeyServerB64'] ?? null;
        $pq = $opts['pqSigner'] ?? null;
        $this->pqSigner = $pq instanceof PqSignerInterface ? $pq : null;
        $this->signAlg = $opts['signAlg'] ?? 'hmac';
        $this->keyLoader = $opts['keyLoader'] ?? null;
        $this->replayStore = $opts['replayStore'] ?? null;
        $this->replayTtl = isset($opts['replayTtl']) ? (int) $opts['replayTtl'] : 120;
        $this->clockSkew = isset($opts['clockSkew']) ? (int) $opts['clockSkew'] : 60;

        // Daftar header kritikal yang diikat ke AAD. Disaring agar hanya berisi
        // nama header non-kosong (string) demi konsistensi binding client-server.
        $this->bindHeaders = [];
        if (isset($opts['bindHeaders']) && is_array($opts['bindHeaders'])) {
            foreach ($opts['bindHeaders'] as $h) {
                if (is_string($h) && $h !== '') {
                    $this->bindHeaders[] = $h;
                }
            }
        }

        $this->deriveKeys = !empty($opts['deriveKeys']);

        $hook = $opts['onSecurityEvent'] ?? null;
        $this->onSecurityEvent = is_callable($hook) ? $hook : null;
        $this->clock = $opts['clock'] ?? static fn (): int => time();
        $this->nonceGenerator = $opts['nonceGenerator'] ?? static fn (): string => Digest::genNonceB64();
        $this->respNonceGenerator = $opts['respNonceGenerator'] ?? static fn (): string => Digest::genNonceB64();

        $transport = $opts['httpTransport'] ?? null;
        if ($transport !== null && !$transport instanceof HttpTransportInterface && !is_callable($transport)) {
            throw new SecurePayloadException(
                'httpTransport harus HttpTransportInterface atau callable factory',
                SecurePayloadException::BAD_REQUEST
            );
        }
        $this->httpTransport = $transport;

        if (!in_array($this->mode, ['hmac', 'aead', 'both'], true)) {
            throw new SecurePayloadException('Mode tidak valid: ' . $this->mode, SecurePayloadException::BAD_REQUEST);
        }
        if (!in_array($this->signAlg, ['hmac', 'ed25519', SecurePayload::SIGN_ALG_HYBRID], true)) {
            throw new SecurePayloadException('signAlg tidak valid: ' . $this->signAlg, SecurePayloadException::BAD_REQUEST);
        }
        if ($this->signAlg === SecurePayload::SIGN_ALG_HYBRID && $this->pqSigner === null) {
            throw new SecurePayloadException(
                'signAlg hybrid-mldsa44-ed25519 memerlukan opsi pqSigner (PqSignerInterface)',
                SecurePayloadException::BAD_REQUEST
            );
        }
        // Validasi panjang secret key Ed25519 client jika disuplai (signing request).
        if (
            $this->ed25519SecretKeyB64 !== null &&
            $this->ed25519SecretKeyB64 !== ''
        ) {
            $skRaw = base64_decode($this->ed25519SecretKeyB64, true);
            if (!is_string($skRaw) || strlen($skRaw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                throw new SecurePayloadException(
                    'Secret key Ed25519 tidak valid (harus base64 dari 64 byte)',
                    SecurePayloadException::BAD_REQUEST
                );
            }
        }
        // Validasi public key Ed25519 server jika disuplai (verifikasi response di client).
        if (
            $this->ed25519PublicKeyServerB64 !== null &&
            $this->ed25519PublicKeyServerB64 !== ''
        ) {
            $pkRaw = base64_decode($this->ed25519PublicKeyServerB64, true);
            if (!is_string($pkRaw) || strlen($pkRaw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new SecurePayloadException(
                    'Public key Ed25519 server tidak valid (harus base64 dari 32 byte)',
                    SecurePayloadException::BAD_REQUEST
                );
            }
        }
        // Validasi secret key Ed25519 server jika disuplai (signing response di server).
        if (
            $this->ed25519SecretKeyServerB64 !== null &&
            $this->ed25519SecretKeyServerB64 !== ''
        ) {
            $skSrvRaw = base64_decode($this->ed25519SecretKeyServerB64, true);
            if (!is_string($skSrvRaw) || strlen($skSrvRaw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                throw new SecurePayloadException(
                    'Secret key Ed25519 server tidak valid (harus base64 dari 64 byte)',
                    SecurePayloadException::BAD_REQUEST
                );
            }
        }
        if ($this->version === '') {
            throw new SecurePayloadException('Versi tidak boleh kosong', SecurePayloadException::BAD_REQUEST);
        }
    }

    /**
     * Factory konfigurasi dengan validasi identik __construct.
     *
     * @param array<string,mixed> $opts
     */
    public static function fromOptions(array $opts): self
    {
        return new self($opts);
    }

    /** @return 'hmac'|'aead'|'both' */
    public function getMode(): string
    {
        return $this->mode;
    }

    /** @return 'hmac'|'ed25519'|'hybrid-mldsa44-ed25519' */
    public function getSignAlg(): string
    {
        return $this->signAlg;
    }

    public function getPqSigner(): ?PqSignerInterface
    {
        return $this->pqSigner;
    }

    public function getMldsaPublicKeyB64(): ?string
    {
        return $this->mldsaPublicKeyB64;
    }

    public function getMldsaSecretKeyB64(): ?string
    {
        return $this->mldsaSecretKeyB64;
    }

    public function getMldsaPublicKeyServerB64(): ?string
    {
        return $this->mldsaPublicKeyServerB64;
    }

    public function getMldsaSecretKeyServerB64(): ?string
    {
        return $this->mldsaSecretKeyServerB64;
    }

    /**
     * Nama algoritma untuk header X-Signature-Algorithm sesuai signAlg.
     */
    public function expectedSignatureAlgHeader(): string
    {
        if ($this->signAlg === 'ed25519') {
            return SecurePayload::ED25519_ALG;
        }
        if ($this->signAlg === SecurePayload::SIGN_ALG_HYBRID) {
            return SecurePayload::HYBRID_ALG;
        }
        return SecurePayload::HMAC_ALG;
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function getKeyId(): ?string
    {
        return $this->keyId;
    }

    public function getHmacSecretRaw(): ?string
    {
        return $this->hmacSecretRaw;
    }

    public function getAeadKeyB64(): ?string
    {
        return $this->aeadKeyB64;
    }

    public function getEd25519SecretKeyB64(): ?string
    {
        return $this->ed25519SecretKeyB64;
    }

    public function getEd25519PublicKeyServerB64(): ?string
    {
        return $this->ed25519PublicKeyServerB64;
    }

    public function getEd25519SecretKeyServerB64(): ?string
    {
        return $this->ed25519SecretKeyServerB64;
    }

    /** @return callable(string,string): array<string,mixed>|null */
    public function getKeyLoader()
    {
        return $this->keyLoader;
    }

    /** @return callable(string,int): bool|null */
    public function getReplayStore()
    {
        return $this->replayStore;
    }

    public function getReplayTtl(): int
    {
        return $this->replayTtl;
    }

    public function getClockSkew(): int
    {
        return $this->clockSkew;
    }

    /** @return list<string> */
    public function getBindHeaders(): array
    {
        return $this->bindHeaders;
    }

    public function getDeriveKeys(): bool
    {
        return $this->deriveKeys;
    }

    /** @return callable(): int */
    public function getClock()
    {
        return $this->clock;
    }

    /** @return callable(): string */
    public function getNonceGenerator()
    {
        return $this->nonceGenerator;
    }

    /** @return callable(): string */
    public function getRespNonceGenerator()
    {
        return $this->respNonceGenerator;
    }

    /** @return HttpTransportInterface|callable():HttpTransportInterface|null */
    public function getHttpTransport()
    {
        return $this->httpTransport;
    }

    /**
     * Emit event keamanan ke hook `onSecurityEvent` bila terpasang.
     *
     * Murni observasional. Exception apa pun dari callback ditelan agar tidak
     * pernah mengubah hasil/keamanan verifikasi. Pemanggil WAJIB hanya mengisi
     * $context dengan data non-rahasia (clientId/keyId/alasan/timestamp) — tidak
     * pernah secret, plaintext, atau ciphertext.
     *
     * @param array<string,mixed> $context
     */
    public function emitEvent(string $event, array $context = []): void
    {
        if ($this->onSecurityEvent === null) {
            return;
        }
        try {
            call_user_func($this->onSecurityEvent, $event, $context);
        } catch (\Throwable $e) {
            // Sengaja diabaikan: observability tidak boleh memengaruhi verifikasi.
        }
    }

    /**
     * Menandatangani pesan kanonik sesuai signAlg yang dikonfigurasi (Client-Side).
     *
     * @return array{0:string,1:string} Tuple [signature base64, nama algoritma untuk header]
     */
    public function signCanonical(string $msg): array
    {
        if ($this->signAlg === SecurePayload::SIGN_ALG_HYBRID) {
            return $this->signHybrid($msg, false);
        }
        if ($this->signAlg === 'ed25519') {
            $this->ensureSodium();
            $sk = $this->getEd25519SecretKeyRaw();
            $sig = sodium_crypto_sign_detached($msg, $sk);
            return [base64_encode($sig), SecurePayload::ED25519_ALG];
        }

        $signKey = $this->deriveSubkey((string) $this->hmacSecretRaw, SecurePayload::KDF_PURPOSE_SIGN_REQ);
        $hmac = hash_hmac('sha256', $msg, $signKey, true);
        return [base64_encode($hmac), SecurePayload::HMAC_ALG];
    }

    /**
     * Tanda tangan hybrid: base64(ed25519_sig (64) || mldsa_sig).
     *
     * @return array{0:string,1:string}
     */
    public function signHybrid(string $msg, bool $forResponse): array
    {
        $this->ensureSodium();
        if ($this->pqSigner === null) {
            throw new SecurePayloadException(
                'pqSigner wajib untuk signAlg hybrid',
                SecurePayloadException::BAD_REQUEST
            );
        }
        if ($forResponse) {
            $sk = $this->getEd25519SecretKeyServerRaw();
        } else {
            $sk = $this->getEd25519SecretKeyRaw();
        }
        $edSig = sodium_crypto_sign_detached($msg, $sk);
        $pqSig = $this->pqSigner->sign($msg);
        if (strlen($pqSig) !== PqSignerInterface::MLDSA44_SIG_BYTES) {
            throw new SecurePayloadException(
                'Panjang signature ML-DSA tidak valid (ekspektasi ' . PqSignerInterface::MLDSA44_SIG_BYTES . ' byte)',
                SecurePayloadException::SERVER_ERROR
            );
        }
        return [base64_encode($edSig . $pqSig), SecurePayload::HYBRID_ALG];
    }

    /**
     * Verifikasi signature hybrid terhadap public key Ed25519 + ML-DSA.
     */
    public function verifyHybrid(string $msg, string $sigB64, string $ed25519Pub, string $mldsaPub): bool
    {
        $this->ensureSodium();
        if ($this->pqSigner === null) {
            throw new SecurePayloadException(
                'pqSigner wajib untuk verifikasi hybrid',
                SecurePayloadException::SERVER_ERROR
            );
        }
        $raw = base64_decode($sigB64, true);
        $need = SODIUM_CRYPTO_SIGN_BYTES + PqSignerInterface::MLDSA44_SIG_BYTES;
        if (!is_string($raw) || strlen($raw) !== $need) {
            return false;
        }
        $edSig = substr($raw, 0, SODIUM_CRYPTO_SIGN_BYTES);
        $pqSig = substr($raw, SODIUM_CRYPTO_SIGN_BYTES);
        if (!sodium_crypto_sign_verify_detached($edSig, $msg, $ed25519Pub)) {
            return false;
        }
        return $this->pqSigner->verify($msg, $pqSig, $mldsaPub);
    }

    public function getEd25519SecretKeyRaw(): string
    {
        $sk = base64_decode($this->ed25519SecretKeyB64 ?? '', true);
        if (!is_string($sk) || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SecurePayloadException(
                'Secret key Ed25519 tidak valid/tersedia (harus base64 dari 64 byte)',
                SecurePayloadException::BAD_REQUEST
            );
        }
        return $sk;
    }

    /**
     * Decode secret key Ed25519 server untuk signing response.
     *
     * @param string|null $fromLoader Nilai dari keyLoader; fallback ke kunci instance.
     */
    public function getEd25519SecretKeyServerRaw(?string $fromLoader = null): string
    {
        $b64 = ($fromLoader !== null && $fromLoader !== '') ? $fromLoader : ($this->ed25519SecretKeyServerB64 ?? '');
        $sk = base64_decode($b64, true);
        if (!is_string($sk) || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SecurePayloadException(
                'Secret key Ed25519 server tidak valid/tersedia (harus base64 dari 64 byte)',
                SecurePayloadException::SERVER_ERROR
            );
        }
        return $sk;
    }

    public function getAeadKeyRaw(): string
    {
        $aeadKeyRaw = base64_decode($this->aeadKeyB64 ?? '', true);
        if (!is_string($aeadKeyRaw) || strlen($aeadKeyRaw) !== 32) {
            throw new SecurePayloadException('Kunci AEAD tidak valid (harus 32 byte base64)', SecurePayloadException::BAD_REQUEST);
        }
        return $aeadKeyRaw;
    }

    /**
     * Terapkan derivasi subkey HKDF bila opsi `deriveKeys` aktif; jika tidak,
     * kembalikan material apa adanya (kompatibel dengan perilaku lama).
     */
    public function deriveSubkey(string $material, string $purpose): string
    {
        if (!$this->deriveKeys) {
            return $material;
        }
        return Hkdf::deriveKey($material, $purpose . '|v' . $this->version);
    }

    public function ensureSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new SecurePayloadException('Ekstensi sodium diperlukan untuk mode AEAD/BOTH', SecurePayloadException::SERVER_ERROR);
        }
    }

    /**
     * Kumpulkan nilai header yang diikat ke AAD AEAD.
     *
     * @param array<string,string> $headers
     * @return array<string,string> Map nama-header(lowercase) => nilai, terurut.
     */
    public function collectBoundHeaders(array $headers): array
    {
        if ($this->bindHeaders === []) {
            return [];
        }
        $norm = [];
        foreach ($headers as $k => $v) {
            if (is_string($k)) {
                $norm[strtolower($k)] = (string) $v;
            }
        }
        $out = [];
        foreach ($this->bindHeaders as $name) {
            $lname = strtolower($name);
            $out[$lname] = $norm[$lname] ?? '';
        }
        ksort($out);
        return $out;
    }

    /**
     * Menyelesaikan kunci untuk membangun response di sisi server.
     * Mengutamakan keyLoader (multi-client); fallback ke kunci instance.
     *
     * @return array{0:?string,1:?string,2:?string} Tuple [hmacSecret, aeadKeyB64, ed25519SecretKeyServerB64]
     */
    public function resolveResponseKeys(string $cid, string $kid): array
    {
        if ($this->keyLoader) {
            $keys = (array) call_user_func($this->keyLoader, $cid, $kid);
            return [
                $keys['hmacSecret'] ?? null,
                $keys['aeadKeyB64'] ?? null,
                $keys['ed25519SecretKeyServerB64'] ?? null,
            ];
        }
        return [$this->hmacSecretRaw, $this->aeadKeyB64, $this->ed25519SecretKeyServerB64];
    }
}
