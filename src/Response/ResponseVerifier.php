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
 * Verifikasi response aman (Client-Side).
 */
final class ResponseVerifier
{
    public function __construct(
        private SecurePayloadConfig $config,
    ) {
    }

    /**
     * Verifikasi Response dengan Exception jika tidak valid (Client-Side).
     *
     * @param array<string,string> $headers
     *
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Jika verifikasi gagal.
     */
    public function verifyResponseOrThrow(array $headers, string $rawBody, string $reqNonceB64): array
    {
        if ($reqNonceB64 === '') {
            throw new SecurePayloadException('Nonce request asal wajib diisi untuk verifikasi response', SecurePayloadException::BAD_REQUEST);
        }

        $H = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k)) {
                continue;
            }
            $H[strtoupper($k)] = (string) $v;
        }

        $ver = $H[self::upper(SecurePayload::HX_RESP_SIG_VER)] ?? '';
        $respTs = $H[self::upper(SecurePayload::HX_RESP_TIMESTAMP)] ?? '';
        $respNonceB64 = $H[self::upper(SecurePayload::HX_RESP_NONCE)] ?? '';

        if ($ver === '' || $respTs === '' || $respNonceB64 === '') {
            throw new SecurePayloadException('Header response tidak lengkap', SecurePayloadException::BAD_REQUEST);
        }
        if ($ver !== $this->config->getVersion()) {
            throw new SecurePayloadException('Versi protokol response tidak didukung', SecurePayloadException::BAD_REQUEST, ['terima' => $ver, 'ekspektasi' => $this->config->getVersion()]);
        }

        // Validasi kesegaran timestamp response (mencegah response usang diputar ulang).
        if (!preg_match('/^\d+$/', $respTs)) {
            throw new SecurePayloadException('Format timestamp response salah', SecurePayloadException::BAD_REQUEST, ['nilai' => $respTs]);
        }
        $ts = (int) $respTs;
        $now = ($this->config->getClock())();
        if ($ts > $now + $this->config->getClockSkew() || $ts < $now - ($this->config->getReplayTtl() + $this->config->getClockSkew())) {
            throw new SecurePayloadException('Timestamp response di luar batas wajar', SecurePayloadException::UNAUTHORIZED, ['ts' => $ts, 'now' => $now]);
        }

        $result = ['mode' => null, 'bodyPlain' => null, 'json' => null];

        $aeadAlg = $H[self::upper(SecurePayload::HX_RESP_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(SecurePayload::HX_RESP_AEAD_NONCE)] ?? '';

        // Mode aead/both: response WAJIB terenkripsi (anti-downgrade, sama seperti request).
        if (($this->config->getMode() === 'aead' || $this->config->getMode() === 'both') && $aeadAlg !== SecurePayload::AEAD_ALG) {
            throw new SecurePayloadException(
                'Mode ' . $this->config->getMode() . ' mewajibkan enkripsi AEAD pada response, namun header AEAD tidak ada/tidak dikenal',
                SecurePayloadException::UNAUTHORIZED
            );
        }

        $bodyForSig = $rawBody;

        if (($this->config->getMode() === 'aead' || $this->config->getMode() === 'both') && $aeadAlg === SecurePayload::AEAD_ALG) {
            $json = json_decode($rawBody, true);
            $blobB64 = is_array($json) ? ($json['__aead_b64'] ?? '') : '';
            if ($blobB64 === '') {
                throw new SecurePayloadException('Payload AEAD response tidak ditemukan', SecurePayloadException::BAD_REQUEST);
            }

            $this->config->ensureSodium();
            $keyRaw = base64_decode($this->config->getAeadKeyB64() ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
                throw new SecurePayloadException('Kunci AEAD client tidak valid/tersedia', SecurePayloadException::BAD_REQUEST);
            }
            $keyRaw = $this->config->deriveSubkey($keyRaw, SecurePayload::KDF_PURPOSE_AEAD_RESP);

            $nonceCalc = Aead::respAeadNonceFrom($respNonceB64, $reqNonceB64);
            $nonceHdr = base64_decode($aeadNonceHdrB64, true) ?: '';
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                throw new SecurePayloadException('Nonce response mismatch (integritas invalid)', SecurePayloadException::UNAUTHORIZED);
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) {
                throw new SecurePayloadException('Format base64 body response rusak', SecurePayloadException::BAD_REQUEST);
            }

            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ct,
                Aead::buildResponseAeadAad($ver, $reqNonceB64, $respTs),
                $nonceCalc,
                $keyRaw
            );
            if ($plain === false) {
                throw new SecurePayloadException('Gagal mendekripsi response (kunci salah atau data rusak)', SecurePayloadException::UNAUTHORIZED);
            }

            if ($this->config->getMode() === 'aead') {
                $result['mode'] = 'AEAD';
                $result['bodyPlain'] = $plain;
                $result['json'] = json_decode($plain, true);
                return $result;
            }
            // Mode both: plaintext hasil dekripsi dipakai untuk verifikasi HMAC.
            $bodyForSig = $plain;
        }

        // --- Verifikasi Tanda Tangan (mode hmac / both) — algoritma mengikuti signAlg ---
        if ($this->config->getMode() === 'hmac' || $this->config->getMode() === 'both') {
            $alg = $H[self::upper(SecurePayload::HX_RESP_SIG_ALG)] ?? '';
            $sigIn = $H[self::upper(SecurePayload::HX_RESP_SIGNATURE)] ?? '';
            $digH = $H[self::upper(SecurePayload::HX_RESP_BODY_DIGEST)] ?? '';

            $expectedAlg = $this->config->getSignAlg() === 'ed25519' ? SecurePayload::ED25519_ALG : SecurePayload::HMAC_ALG;
            if ($alg !== $expectedAlg || $sigIn === '' || $digH === '') {
                throw new SecurePayloadException(
                    'Header tanda tangan response tidak lengkap/salah algoritma',
                    SecurePayloadException::BAD_REQUEST,
                    ['terima' => $alg, 'ekspektasi' => $expectedAlg]
                );
            }

            $digHVal = str_starts_with($digH, 'sha256=') ? substr($digH, 7) : '';
            if ($digHVal === '') {
                throw new SecurePayloadException('Format digest response salah (harus sha256=...)', SecurePayloadException::BAD_REQUEST);
            }

            $calcDig = Digest::bodyDigestB64($bodyForSig);
            if (!hash_equals($digHVal, $calcDig)) {
                throw new SecurePayloadException('Integritas Body Digest response gagal', SecurePayloadException::UNPROCESSABLE);
            }

            $msg = Messages::respMessage($this->config->getVersion(), $reqNonceB64, $respTs, $respNonceB64, $calcDig);

            if ($this->config->getSignAlg() === 'ed25519') {
                $this->config->ensureSodium();
                $pub = base64_decode($this->config->getEd25519PublicKeyServerB64() ?? '', true);
                if (!is_string($pub) || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    throw new SecurePayloadException(
                        'Public key Ed25519 server tidak valid/tersedia di client',
                        SecurePayloadException::BAD_REQUEST
                    );
                }
                $sigRaw = base64_decode($sigIn, true);
                if (!is_string($sigRaw) || strlen($sigRaw) !== SODIUM_CRYPTO_SIGN_BYTES) {
                    throw new SecurePayloadException('Format signature Ed25519 response rusak', SecurePayloadException::BAD_REQUEST);
                }
                if (!sodium_crypto_sign_verify_detached($sigRaw, $msg, $pub)) {
                    throw new SecurePayloadException('Tanda Tangan response (Ed25519) tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            } else {
                $hmacRaw = $this->config->getHmacSecretRaw();
                if ($hmacRaw === null || $hmacRaw === '') {
                    throw new SecurePayloadException('Secret Key HMAC response tidak tersedia di client', SecurePayloadException::BAD_REQUEST);
                }

                $signKey = $this->config->deriveSubkey($hmacRaw, SecurePayload::KDF_PURPOSE_SIGN_RESP);
                $sigB64 = base64_encode(hash_hmac('sha256', $msg, $signKey, true));
                if (!hash_equals($sigB64, $sigIn)) {
                    throw new SecurePayloadException('Tanda Tangan response tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            }

            $result['mode'] = ($this->config->getMode() === 'both') ? 'BOTH' : 'HMAC';
            $result['bodyPlain'] = $bodyForSig;
            $result['json'] = json_decode($bodyForSig, true);
            return $result;
        }

        throw new SecurePayloadException('Tidak ditemukan header keamanan response yang valid', SecurePayloadException::BAD_REQUEST);
    }

    private static function upper(string $s): string
    {
        return strtoupper($s);
    }
}
