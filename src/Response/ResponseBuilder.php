<?php

declare(strict_types=1);

namespace SecurePayload\Response;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\SecurePayloadConfig;
use SecurePayload\Protocol\Aead;
use SecurePayload\Protocol\Digest;
use SecurePayload\Protocol\Messages;
use SecurePayload\SecurePayload;

/**
 * Pembangunan response aman (Server-Side).
 */
final class ResponseBuilder
{
    public function __construct(
        private SecurePayloadConfig $config,
    ) {
    }

    /**
     * Membangun Response Aman (Server-Side).
     *
     * @param array<string,string> $requestHeaders Header request masuk (untuk ambil clientId/keyId/nonce).
     * @param array<mixed>          $payload        Data response.
     *
     * @return array{0: array<string,string>, 1: string} Tuple [Headers response, Body string]
     * @throws SecurePayloadException Jika kredensial/kunci tidak tersedia atau enkripsi gagal.
     */
    public function buildResponse(array $requestHeaders, array $payload): array
    {
        // Normalisasi header request untuk pencarian case-insensitive.
        $H = [];
        foreach ($requestHeaders as $k => $v) {
            if (!is_string($k)) {
                continue;
            }
            $H[strtoupper($k)] = (string) $v;
        }

        $cid = $H[self::upper(SecurePayload::HX_CLIENT_ID)] ?? '';
        $kid = $H[self::upper(SecurePayload::HX_KEY_ID)] ?? '';
        $reqNonceB64 = $H[self::upper(SecurePayload::HX_NONCE)] ?? '';
        if ($reqNonceB64 === '') {
            throw new SecurePayloadException('Nonce request tidak ditemukan untuk binding response', SecurePayloadException::BAD_REQUEST);
        }

        // Muat kunci response (server memakai keyLoader; fallback ke kunci instance).
        [$hmacRaw, $aeadB64, $ed25519SecretServerB64] = $this->config->resolveResponseKeys($cid, $kid);

        $ver = $this->config->getVersion();
        $respTs = (string) ($this->config->getClock())();
        $respNonceB64 = ($this->config->getRespNonceGenerator())();

        $headers = [
            SecurePayload::HX_RESP_TIMESTAMP => $respTs,
            SecurePayload::HX_RESP_NONCE => $respNonceB64,
            SecurePayload::HX_RESP_SIG_VER => $ver,
        ];

        $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($plain === false) {
            throw new SecurePayloadException('Gagal encode JSON response', SecurePayloadException::BAD_REQUEST);
        }

        // --- Enkripsi (mode aead / both) ---
        $bodyOut = $plain;
        if ($this->config->getMode() === 'aead' || $this->config->getMode() === 'both') {
            $this->config->ensureSodium();
            $keyRaw = base64_decode($aeadB64 ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
                throw new SecurePayloadException('Kunci AEAD response tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
            }
            $keyRaw = $this->config->deriveSubkey($keyRaw, SecurePayload::KDF_PURPOSE_AEAD_RESP);
            $aeadNonce = Aead::respAeadNonceFrom($respNonceB64, $reqNonceB64);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plain,
                Aead::buildResponseAeadAad($ver, $reqNonceB64, $respTs),
                $aeadNonce,
                $keyRaw
            );
            $bodyOut = json_encode(['__aead_b64' => base64_encode($ciphertext)], JSON_UNESCAPED_SLASHES);
            $headers[SecurePayload::HX_RESP_AEAD_ALG] = SecurePayload::AEAD_ALG;
            $headers[SecurePayload::HX_RESP_AEAD_NONCE] = base64_encode($aeadNonce);
        }

        // --- Tanda Tangan (mode hmac / both) — algoritma mengikuti signAlg ---
        if ($this->config->getMode() === 'hmac' || $this->config->getMode() === 'both') {
            $digestB64 = Digest::bodyDigestB64($plain);
            $msg = Messages::respMessage($ver, $reqNonceB64, $respTs, $respNonceB64, $digestB64);

            if ($this->config->getSignAlg() === SecurePayload::SIGN_ALG_HYBRID) {
                $this->config->ensureSodium();
                $sk = $this->config->getEd25519SecretKeyServerRaw($ed25519SecretServerB64);
                $pq = $this->config->getPqSigner();
                if ($pq === null) {
                    throw new SecurePayloadException('pqSigner wajib untuk signAlg hybrid', SecurePayloadException::SERVER_ERROR);
                }
                $edSig = sodium_crypto_sign_detached($msg, $sk);
                $pqSig = $pq->sign($msg);
                if (strlen($pqSig) !== \SecurePayload\Crypto\PqSignerInterface::MLDSA44_SIG_BYTES) {
                    throw new SecurePayloadException('Panjang signature ML-DSA tidak valid', SecurePayloadException::SERVER_ERROR);
                }
                $sigB64 = base64_encode($edSig . $pqSig);
                $headers[SecurePayload::HX_RESP_SIG_ALG] = SecurePayload::HYBRID_ALG;
            } elseif ($this->config->getSignAlg() === 'ed25519') {
                $this->config->ensureSodium();
                $sk = $this->config->getEd25519SecretKeyServerRaw($ed25519SecretServerB64);
                $sigB64 = base64_encode(sodium_crypto_sign_detached($msg, $sk));
                $headers[SecurePayload::HX_RESP_SIG_ALG] = SecurePayload::ED25519_ALG;
            } else {
                if ($hmacRaw === null || $hmacRaw === '') {
                    throw new SecurePayloadException('Secret Key HMAC response tidak tersedia di server', SecurePayloadException::SERVER_ERROR);
                }
                if (strlen($hmacRaw) < 32) {
                    throw new SecurePayloadException('HMAC Secret response terlalu pendek (minimum 32 karakter)', SecurePayloadException::SERVER_ERROR);
                }
                $signKey = $this->config->deriveSubkey($hmacRaw, SecurePayload::KDF_PURPOSE_SIGN_RESP);
                $sigB64 = base64_encode(hash_hmac('sha256', $msg, $signKey, true));
                $headers[SecurePayload::HX_RESP_SIG_ALG] = SecurePayload::HMAC_ALG;
            }

            $headers[SecurePayload::HX_RESP_BODY_DIGEST] = 'sha256=' . $digestB64;
            $headers[SecurePayload::HX_RESP_SIGNATURE] = $sigB64;
        }

        return [$headers, $bodyOut];
    }

    private static function upper(string $s): string
    {
        return strtoupper($s);
    }
}
