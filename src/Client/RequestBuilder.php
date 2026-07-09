<?php

declare(strict_types=1);

namespace SecurePayload\Client;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\SecurePayloadConfig;
use SecurePayload\Protocol\Aead;
use SecurePayload\Protocol\Canonical;
use SecurePayload\Protocol\Digest;
use SecurePayload\Protocol\Messages;
use SecurePayload\SecurePayload;

/**
 * Pembangunan header dan body request aman (Client-Side).
 */
final class RequestBuilder
{
    public function __construct(
        private SecurePayloadConfig $config,
    ) {
    }

    /**
     * Membangun Header Keamanan dan Body Request (Client-Side).
     *
     * @param array<string,string> $extraHeaders Header tambahan yang ikut dikirim.
     *
     * @return array{0: array<string,string>, 1: string} Tuple [Headers array, Body string]
     *
     * @throws SecurePayloadException Jika parameter salah atau enkripsi gagal
     */
    public function buildHeadersAndBody(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        // Validasi kebutuhan kredensial dasar
        if (($this->config->getClientId() ?? '') === '' || ($this->config->getKeyId() ?? '') === '') {
            throw new SecurePayloadException('clientId & keyId wajib diisi untuk mode client', SecurePayloadException::BAD_REQUEST);
        }

        $method = strtoupper($method);
        $parts = parse_url($url);
        if ($parts === false) {
            throw new SecurePayloadException('Format URL tidak valid', SecurePayloadException::BAD_REQUEST);
        }

        $path = Canonical::normalizePath($parts['path'] ?? '/');
        $qStr = '';
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $qArr);
            if (!is_array($qArr)) {
                $qArr = [];
            }
            $qStr = Canonical::canonicalQuery($qArr);
        }

        $ver = $this->config->getVersion();
        $ts = (string) ($this->config->getClock())();
        $nonceB64 = ($this->config->getNonceGenerator())();

        // Nilai header kritikal yang diikat ke AAD diambil dari header tambahan
        // yang akan benar-benar dikirim. Server membaca nilai yang sama dari
        // request masuk, sehingga AAD identik di kedua sisi.
        $boundHeaders = $this->config->collectBoundHeaders($extraHeaders);

        // Header dasar yang selalu ada. Header tambahan digabung lebih dahulu
        // agar header keamanan tidak bisa ditimpa oleh caller.
        $headers = array_merge($extraHeaders, [
            SecurePayload::HX_CLIENT_ID => (string) $this->config->getClientId(),
            SecurePayload::HX_KEY_ID => (string) $this->config->getKeyId(),
            SecurePayload::HX_TIMESTAMP => $ts,
            SecurePayload::HX_NONCE => $nonceB64,
            SecurePayload::HX_SIG_VER => $ver,
                // X-Canonical-Request dikirim sebagai debugging hint, BUKAN source of truth untuk keamanan server
            SecurePayload::HX_CANON_REQ => base64_encode($method . "\n" . $path . "\n" . $qStr),
        ]);

        // --- MODE: AEAD (Enkripsi Saja) ---
        if ($this->config->getMode() === 'aead') {
            $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($body === false) {
                throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
            }
            $this->config->ensureSodium();

            $aeadKeyRaw = $this->config->deriveSubkey($this->config->getAeadKeyRaw(), SecurePayload::KDF_PURPOSE_AEAD_REQ);
            $aeadNonce = Aead::aeadNonceFrom($nonceB64, $method, $path, $qStr);

            // Enkripsi body
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $body,
                Aead::buildRequestAeadAad($ver, $ts, $boundHeaders),
                $aeadNonce,
                $aeadKeyRaw
            );
            $bodyB64 = base64_encode($ciphertext);

            $headers[SecurePayload::HX_AEAD_ALG] = SecurePayload::AEAD_ALG;
            $headers[SecurePayload::HX_AEAD_NONCE] = base64_encode($aeadNonce);

            // Output body dibungkus JSON khusus
            return [$headers, json_encode(['__aead_b64' => $bodyB64], JSON_UNESCAPED_SLASHES)];
        }

        // --- MODE: BOTH (Enkripsi + HMAC) ---
        if ($this->config->getMode() === 'both') {
            $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($plain === false) {
                throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
            }
            $this->config->ensureSodium();

            $aeadKeyRaw = $this->config->deriveSubkey($this->config->getAeadKeyRaw(), SecurePayload::KDF_PURPOSE_AEAD_REQ);
            $aeadNonce = Aead::aeadNonceFrom($nonceB64, $method, $path, $qStr);

            // Enkripsi
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plain,
                Aead::buildRequestAeadAad($ver, $ts, $boundHeaders),
                $aeadNonce,
                $aeadKeyRaw
            );
            $ctB64 = base64_encode($ciphertext);
            $body = json_encode(['__aead_b64' => $ctB64], JSON_UNESCAPED_SLASHES);

            // Tanda tangan dilakukan terhadap Plaintext asli, bukan ciphertext
            // agar server memverifikasi makna data, bukan bungkusnya.
            $digestB64 = Digest::bodyDigestB64($plain);
            $msg = Messages::hmacMessage($ver, (string) $this->config->getClientId(), (string) $this->config->getKeyId(), $ts, $nonceB64, $method, $path, $qStr, $digestB64);
            [$sigB64, $sigAlg] = $this->config->signCanonical($msg);

            $headers[SecurePayload::HX_AEAD_ALG] = SecurePayload::AEAD_ALG;
            $headers[SecurePayload::HX_AEAD_NONCE] = base64_encode($aeadNonce);
            $headers[SecurePayload::HX_SIG_ALG] = $sigAlg;
            $headers[SecurePayload::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
            $headers[SecurePayload::HX_SIGNATURE] = $sigB64;

            return [$headers, $body];
        }

        // --- MODE: HMAC (Tanda Tangan Saja) ---
        $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($plain === false) {
            throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
        }

        $digestB64 = Digest::bodyDigestB64($plain);
        $msg = Messages::hmacMessage($ver, (string) $this->config->getClientId(), (string) $this->config->getKeyId(), $ts, $nonceB64, $method, $path, $qStr, $digestB64);
        [$sigB64, $sigAlg] = $this->config->signCanonical($msg);

        $headers[SecurePayload::HX_SIG_ALG] = $sigAlg;
        $headers[SecurePayload::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
        $headers[SecurePayload::HX_SIGNATURE] = $sigB64;

        return [$headers, $plain];
    }
}
