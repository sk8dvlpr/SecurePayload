<?php

declare(strict_types=1);

namespace SecurePayload\Delivery;

use SecurePayload\Delivery\Internal\LinkCodec;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\EventEmitter;

/**
 * Verifikator token tautan aman.
 *
 * Pasangan SecureLinkIssuer: memvalidasi format token, signature HMAC-SHA256
 * atas string kanonik, kecocokan file_id, kedaluwarsa, binding pemegang, lalu
 * sekali-pakai (via replayStore callable — semantik sama dengan replay store
 * protokol utama: fn(cacheKey, ttl): bool, true = pertama kali/boleh lanjut).
 * Modul ini STANDALONE: tidak bergantung pada facade SecurePayload
 * maupun protokol request/response.
 *
 * Fail-closed: semua kegagalan verifikasi menghasilkan array ok=false dengan
 * status 403 + alasan singkat (TIDAK melempar exception) dan meng-emit event
 * `file_access_denied`. Sukses meng-emit `file_accessed`.
 */
final class SecureLinkVerifier
{
    /**
     * Nama event keamanan. Nilai string disalin literal agar modul ini
     * standalone; test unit menjaga kesetaraannya dengan konstanta facade.
     */
    private const EVENT_FILE_ACCESSED = 'file_accessed';
    private const EVENT_FILE_ACCESS_DENIED = 'file_access_denied';

    /** Panjang minimum HMAC secret (byte), konsisten dengan SecurePayloadConfig. */
    private const MIN_SECRET_LENGTH = 32;

    /** Prefix cache key anti-replay single-use; sisanya sha256 hex dari jti. */
    private const REPLAY_KEY_PREFIX = 'sp-link:';

    private string $hmacSecret;

    /** @var callable|null fn(string $cacheKey, int $ttl): bool — WAJIB untuk token single-use */
    private $replayStore;

    /** @var callable callable():int */
    private $clock;

    private EventEmitter $events;

    /**
     * @param string        $hmacSecret  Secret HMAC yang sama dengan Issuer (minimal 32 karakter).
     * @param callable|null $replayStore fn(string $cacheKey, int $ttl): bool — true bila key
     *                                   belum pernah dipakai (dan sekaligus menandainya).
     *                                   Tanpa ini, semua token single-use DITOLAK (fail-closed).
     * @param array{clock?:callable, onSecurityEvent?:callable} $opts
     *        clock          : callable():int sumber waktu (default time()).
     *        onSecurityEvent: handler (string $event, array $context) — WAJIB non-secret.
     *
     * @throws SecurePayloadException BAD_REQUEST bila secret terlalu pendek atau opts tidak valid.
     */
    public function __construct(string $hmacSecret, ?callable $replayStore = null, array $opts = [])
    {
        if (strlen($hmacSecret) < self::MIN_SECRET_LENGTH) {
            throw new SecurePayloadException(
                'HMAC Secret terlalu pendek. Minimum 32 karakter (rekomendasikan 64 byte hex).',
                SecurePayloadException::BAD_REQUEST
            );
        }
        if (isset($opts['clock']) && !is_callable($opts['clock'])) {
            throw new SecurePayloadException('clock wajib berupa callable', SecurePayloadException::BAD_REQUEST);
        }
        if (isset($opts['onSecurityEvent']) && !is_callable($opts['onSecurityEvent'])) {
            throw new SecurePayloadException('onSecurityEvent wajib berupa callable', SecurePayloadException::BAD_REQUEST);
        }
        $this->hmacSecret = $hmacSecret;
        $this->replayStore = $replayStore;
        $this->clock = $opts['clock'] ?? static fn (): int => time();
        $this->events = new EventEmitter($opts['onSecurityEvent'] ?? null);
    }

    /**
     * Verifikasi token akses file. Urutan pemeriksaan fail-closed (berhenti
     * pada kegagalan pertama; setiap penolakan meng-emit event denied):
     *
     * 1. format_token         — bukan 3 segmen / prefix selain sp1 / base64url rusak /
     *                            payload bukan JSON dengan klaim bertipe benar.
     * 2. signature_invalid    — HMAC kanonik tidak cocok (hash_equals) ATAU secret beda.
     * 3. file_mismatch        — file_id parameter != file_id klaim di token.
     * 4. token_expired        — exp <= now (token pada detik exp sudah kedaluwarsa).
     * 5. binding_mismatch     — klaim bound_to != null wajib sama persis dengan param
     *                            boundTo (hash_equals); token TAK terikat + param boundTo
     *                            non-null juga DITOLAK (link tak terikat tidak boleh
     *                            diklaim terikat — konsisten ketat). Dicek SEBELUM
     *                            konsumsi replayStore agar request dengan boundTo salah
     *                            tidak membakar token single-use (DoS ke pemegang sah).
     * 6. replay_store_required— su=true tetapi replayStore tidak dipasang (fail-closed).
     * 7. token_reused         — su=true dan replayStore melaporkan jti sudah dipakai.
     *
     * @param string  $fileId  ID file yang diminta (harus persis sama dengan klaim token).
     * @param string  $token   Token dari Issuer.
     * @param ?string $boundTo Identitas pemegang yang diklaim (mis. client id sesi saat ini).
     *
     * @return array{ok:bool, status:int, error?:string, claims?:array<string,mixed>}
     *         ok=true → status=200 + claims {file_id,exp,iat,jti,su,bound_to};
     *         ok=false → status=403 + error (alasan di atas).
     */
    public function verify(string $fileId, string $token, ?string $boundTo = null): array
    {
        // 1. Format token: struktur, versi, dan dekode base64url ketat.
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] !== LinkCodec::VERSION) {
            return $this->deny('format_token', $fileId);
        }
        $payloadJson = LinkCodec::decodeB64Url($parts[1]);
        $sigGiven = LinkCodec::decodeB64Url($parts[2]);
        if ($payloadJson === null || $sigGiven === null) {
            return $this->deny('format_token', $fileId);
        }

        // Struktur klaim: JSON object dengan tipe tepat; segala penyimpangan
        // diperlakukan sebagai format_token karena klaim tak bisa dipercaya.
        $raw = json_decode($payloadJson, true);
        if (!is_array($raw)) {
            return $this->deny('format_token', $fileId);
        }
        $claimFileId = $raw['file_id'] ?? null;
        $exp = $raw['exp'] ?? null;
        $iat = $raw['iat'] ?? null;
        $jti = $raw['jti'] ?? null;
        $su = $raw['su'] ?? null;
        $claimBoundTo = $raw['bound_to'] ?? null;
        if (
            !is_string($claimFileId) || $claimFileId === ''
            || !is_int($exp)
            || !is_int($iat)
            || !is_string($jti) || preg_match('/^[a-f0-9]{32}$/', $jti) !== 1
            || !is_bool($su)
            || ($claimBoundTo !== null && !is_string($claimBoundTo))
        ) {
            return $this->deny('format_token', $fileId);
        }

        // 2. Signature HMAC atas string kanonik (bukan byte JSON).
        $canonical = LinkCodec::canonicalString([
            'file_id' => $claimFileId,
            'exp' => $exp,
            'jti' => $jti,
            'su' => $su,
            'bound_to' => $claimBoundTo,
        ]);
        if (!hash_equals(LinkCodec::sign($canonical, $this->hmacSecret), $sigGiven)) {
            return $this->deny('signature_invalid', $fileId);
        }

        // 3. Kecocokan file yang diminta dengan yang tercantum di token.
        if (!hash_equals($claimFileId, $fileId)) {
            return $this->deny('file_mismatch', $fileId);
        }

        // 4. Kedaluwarsa: exp harus masih di masa depan.
        $now = ($this->clock)();
        if ($exp <= $now) {
            return $this->deny('token_expired', $fileId);
        }

        // 5. Binding pemegang: dua arah ketat (null vs non-null keduanya mismatch).
        // Sengaja SEBELUM konsumsi replayStore: request dengan boundTo salah tidak
        // boleh membakar jti single-use (mencegah DoS ke pemegang sah).
        if ($claimBoundTo !== null) {
            if ($boundTo === null || !hash_equals($claimBoundTo, $boundTo)) {
                return $this->deny('binding_mismatch', $fileId);
            }
        } elseif ($boundTo !== null) {
            return $this->deny('binding_mismatch', $fileId);
        }

        // 6–7. Sekali-pakai: tanpa store, token su DITOLAK (fail-closed).
        $store = $this->replayStore;
        if ($su) {
            if ($store === null) {
                return $this->deny('replay_store_required', $fileId);
            }
            // Key TIDAK menyertakan exp/timestamp: satu jti = satu pakai, titik.
            $cacheKey = self::REPLAY_KEY_PREFIX . hash('sha256', $jti);
            // TTL store = sisa umur token (min 1 detik) agar entri tak hidup lebih lama dari token.
            $ttlRemaining = max(1, $exp - $now);
            if (!(bool) call_user_func($store, $cacheKey, $ttlRemaining)) {
                return $this->deny('token_reused', $fileId);
            }
        }

        $claims = [
            'file_id' => $claimFileId,
            'exp' => $exp,
            'iat' => $iat,
            'jti' => $jti,
            'su' => $su,
            'bound_to' => $claimBoundTo,
        ];
        $this->events->emit(self::EVENT_FILE_ACCESSED, ['file_id' => $claimFileId]);
        return ['ok' => true, 'status' => 200, 'claims' => $claims];
    }

    /**
     * Emit event penolakan lalu kembalikan hasil gagal standar (403).
     *
     * @return array{ok:bool, status:int, error:string}
     */
    private function deny(string $reason, string $fileId): array
    {
        $this->events->emit(self::EVENT_FILE_ACCESS_DENIED, ['reason' => $reason, 'file_id' => $fileId]);
        return ['ok' => false, 'status' => 403, 'error' => $reason];
    }
}
