<?php

declare(strict_types=1);

namespace SecurePayload\Server;

use SecurePayload\Compression\PayloadCompressor;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\SecurePayloadConfig;
use SecurePayload\Protocol\Aead;
use SecurePayload\Protocol\Canonical;
use SecurePayload\Protocol\Digest;
use SecurePayload\Protocol\Messages;
use SecurePayload\Protocol\PayloadSchemaValidator;
use SecurePayload\SecurePayload;

/**
 * Verifikasi request masuk (Server-Side).
 */
final class RequestVerifier
{
    public function __construct(
        private SecurePayloadConfig $config,
        private ReplayGuard $replayGuard,
    ) {
    }

    /**
     * Verifikasi Request dengan Exception jika tidak valid.
     *
     * @param array<string,string> $headers
     * @param array|string $query
     *
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Jika verifikasi gagal.
     */
    public function verifyOrThrow(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        // Normalisasi header key menjadi uppercase untuk pencarian case-insensitive (pseudo)
        $H = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k)) {
                continue;
            }
            $H[strtoupper($k)] = (string) $v;
        }

        $ver = $H[self::upper(SecurePayload::HX_SIG_VER)] ?? '';
        $cid = $H[self::upper(SecurePayload::HX_CLIENT_ID)] ?? '';
        $kid = $H[self::upper(SecurePayload::HX_KEY_ID)] ?? '';
        $tsStr = $H[self::upper(SecurePayload::HX_TIMESTAMP)] ?? '';
        $nonceB64 = $H[self::upper(SecurePayload::HX_NONCE)] ?? '';

        // 1. Validasi Keberadaan Header
        if ($ver === '' || $cid === '' || $kid === '' || $tsStr === '' || $nonceB64 === '') {
            throw new SecurePayloadException('Header keamanan tidak lengkap', SecurePayloadException::BAD_REQUEST);
        }
        if ($ver !== $this->config->getVersion()) {
            throw new SecurePayloadException('Versi protokol tidak didukung', SecurePayloadException::BAD_REQUEST, ['terima' => $ver, 'ekspektasi' => $this->config->getVersion()]);
        }

        // 2. Validasi Timestamp
        if (!preg_match('/^\d+$/', $tsStr)) {
            throw new SecurePayloadException('Format timestamp salah', SecurePayloadException::BAD_REQUEST, ['nilai' => $tsStr]);
        }
        $ts = (int) $tsStr;
        $now = ($this->config->getClock())();

        // Cek range waktu: tidak boleh masa depan (skew) dan tidak boleh terlalu lampau (ttl + skew)
        if ($ts > $now + $this->config->getClockSkew() || $ts < $now - ($this->config->getReplayTtl() + $this->config->getClockSkew())) {
            $this->config->emitEvent(SecurePayload::EVENT_TIMESTAMP_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'ts' => $ts, 'now' => $now]);
            throw new SecurePayloadException('Timestamp di luar batas wajar (kadaluarsa atau jam salah)', SecurePayloadException::UNAUTHORIZED, ['ts' => $ts, 'now' => $now]);
        }

        // 3. Proteksi Replay Attack
        $this->replayGuard->checkReplay($cid, $kid, $tsStr, $nonceB64);

        // Menyiapkan parameter request kanonik dari input Server (BUKAN dari header X-Canonical-Request)
        $method = strtoupper($method);
        $path = Canonical::normalizePath($path ?: '/');

        if (is_array($query)) {
            $qStr = Canonical::canonicalQuery($query);
        } else {
            parse_str((string) $query, $qArr);
            $qStr = Canonical::canonicalQuery(is_array($qArr) ? $qArr : []);
        }

        // 4. Load Kunci
        $hmacRaw = null;
        $aeadB64 = null;
        $ed25519PubB64 = null;
        $mldsaPubB64 = null;
        $keyLoader = $this->config->getKeyLoader();
        if ($keyLoader) {
            $keys = (array) call_user_func($keyLoader, $cid, $kid);
            $hmacRaw = $keys['hmacSecret'] ?? null;
            $aeadB64 = $keys['aeadKeyB64'] ?? null;
            $ed25519PubB64 = $keys['ed25519PublicKeyB64'] ?? null;
            $mldsaPubB64 = $keys['mldsaPublicKeyB64'] ?? null;
        }
        if ($mldsaPubB64 === null || $mldsaPubB64 === '') {
            $mldsaPubB64 = $this->config->getMldsaPublicKeyB64();
        }

        $result = ['mode' => null, 'bodyPlain' => null, 'json' => null];

        // --- Verifikasi AEAD / BOTH ---
        $aeadAlg = $H[self::upper(SecurePayload::HX_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(SecurePayload::HX_AEAD_NONCE)] ?? '';

        // Mode 'aead' dan 'both' WAJIB terenkripsi. Jika header AEAD hilang atau
        // algoritmanya tidak dikenal, tolak request — JANGAN lewati blok ini diam-diam.
        // Tanpa pengecekan ini, mode 'both' bisa di-downgrade menjadi HMAC-only
        // sehingga server menerima body plaintext (kebocoran jaminan kerahasiaan).
        if (($this->config->getMode() === 'aead' || $this->config->getMode() === 'both') && $aeadAlg !== SecurePayload::AEAD_ALG) {
            throw new SecurePayloadException(
                'Mode ' . $this->config->getMode() . ' mewajibkan enkripsi AEAD, namun header AEAD tidak ada atau algoritmanya tidak dikenal',
                SecurePayloadException::UNAUTHORIZED
            );
        }

        // Deteksi apakah ini request terenkripsi
        if (($this->config->getMode() === 'aead' || $this->config->getMode() === 'both') && $aeadAlg === SecurePayload::AEAD_ALG) {
            $json = json_decode($rawBody, true);
            $blobB64 = is_array($json) ? ($json['__aead_b64'] ?? '') : '';
            if ($blobB64 === '') {
                throw new SecurePayloadException('Payload AEAD tidak ditemukan', SecurePayloadException::BAD_REQUEST);
            }

            $this->config->ensureSodium();
            $keyRaw = base64_decode($aeadB64 ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
                $this->config->emitEvent(SecurePayload::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'aead']);
                throw new SecurePayloadException('Kunci AEAD server tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
            }
            // Derivasi subkey HKDF (no-op bila deriveKeys nonaktif).
            $keyRaw = $this->config->deriveSubkey($keyRaw, SecurePayload::KDF_PURPOSE_AEAD_REQ);

            // Hitung ulang nonce yang seharusnya
            $nonceCalc = Aead::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $nonceHdr = base64_decode($aeadNonceHdrB64, true) ?: '';

            // Verifikasi integritas nonce (mencegah pemindahan nonce curian ke konteks lain)
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                $this->config->emitEvent(SecurePayload::EVENT_NONCE_MISMATCH, ['clientId' => $cid, 'keyId' => $kid]);
                throw new SecurePayloadException('Nonce mismatch (Integritas request invalid)', SecurePayloadException::UNAUTHORIZED);
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) {
                throw new SecurePayloadException('Format base64 body rusak', SecurePayloadException::BAD_REQUEST);
            }

            // AAD diturunkan dari timestamp request + header kritikal yang diikat.
            // Nilai dibaca dari header request masuk (sumber yang sama yang akan
            // dimanipulasi penyerang), sehingga setiap perubahan menggagalkan dekripsi.
            $boundHeaders = $this->config->collectBoundHeaders($headers);

            // Dekripsi
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ct,
                Aead::buildRequestAeadAad($ver, $tsStr, $boundHeaders),
                $nonceCalc,
                $keyRaw
            );

            if ($plain === false) {
                $this->config->emitEvent(SecurePayload::EVENT_DECRYPT_FAILED, ['clientId' => $cid, 'keyId' => $kid, 'scope' => 'request']);
                throw new SecurePayloadException('Gagal mendekripsi (Kunci salah atau data rusak)', SecurePayloadException::UNAUTHORIZED);
            }

            $used = ($this->config->getMode() === 'both') ? 'BOTH-AEAD' : 'AEAD';
            $result['mode'] = $used;

            if ($this->config->getMode() === 'aead') {
                // Selesai jika hanya AEAD. Integritas sudah dijamin tag AEAD;
                // dekompresi + validasi skema dieksekusi SETELAH titik ini.
                $plain = $this->finalizeBody($plain, $H);
                $result['bodyPlain'] = $plain;
                $result['json'] = json_decode($plain, true);
                $this->enforcePayloadSchema($result['json'], $cid, $kid);
                return $result;
            }

            // Jika BOTH, hasil dekripsi dipakai sebagai input verifikasi HMAC
            $rawBodyForHmac = $plain;

            // Verifikasi Digest Tambahan untuk integritas plaintext
            $digestHdr = $H[self::upper(SecurePayload::HX_BODY_DIGEST)] ?? '';
            // Hasil disimpan: byte yang sama diverifikasi ulang di blok HMAC
            // (mode both) — reuse menghemat satu pass SHA-256 penuh per request.
            $plainDigestB64 = Digest::bodyDigestB64($rawBodyForHmac);
            $calc = 'sha256=' . $plainDigestB64;
            if ($digestHdr !== $calc) {
                throw new SecurePayloadException('Integritas Body Digest gagal', SecurePayloadException::UNPROCESSABLE, ['expected' => $calc, 'got' => $digestHdr]);
            }
        }

        // --- Verifikasi Tanda Tangan (HMAC / Ed25519) untuk mode hmac / both ---
        if ($this->config->getMode() === 'hmac' || $this->config->getMode() === 'both') {
            $alg = $H[self::upper(SecurePayload::HX_SIG_ALG)] ?? '';
            $sigIn = $H[self::upper(SecurePayload::HX_SIGNATURE)] ?? '';
            $digH = $H[self::upper(SecurePayload::HX_BODY_DIGEST)] ?? '';

            // Algoritma ditentukan oleh konfigurasi server (signAlg), BUKAN oleh header.
            // Header yang tidak cocok ditolak untuk mencegah downgrade tanda tangan.
            $expectedAlg = $this->config->expectedSignatureAlgHeader();
            if ($alg !== $expectedAlg || $sigIn === '' || $digH === '') {
                throw new SecurePayloadException('Header tanda tangan tidak lengkap/salah algoritma', SecurePayloadException::BAD_REQUEST, ['terima' => $alg, 'ekspektasi' => $expectedAlg]);
            }

            $digHVal = str_starts_with($digH, 'sha256=') ? substr($digH, 7) : '';
            if ($digHVal === '') {
                throw new SecurePayloadException('Format digest salah (harus sha256=...)', SecurePayloadException::BAD_REQUEST);
            }

            // Gunakan plaintext hasil dekripsi (jika ada) atau raw body asli
            $bodyForHmac = isset($rawBodyForHmac) ? $rawBodyForHmac : $rawBody;

            // 1. Verifikasi Hash Body — bila plaintext sudah di-digest di jalur
            //    AEAD (mode both), hasilnya direuse; byte-identik karena variabel
            //    $rawBodyForHmac tidak pernah berubah di antara keduanya.
            $calcDig = isset($plainDigestB64) ? $plainDigestB64 : Digest::bodyDigestB64($bodyForHmac);
            if (!hash_equals($digHVal, $calcDig)) {
                throw new SecurePayloadException('Integritas Body Digest HMAC gagal', SecurePayloadException::UNPROCESSABLE);
            }

            // 2. Verifikasi Signature sesuai algoritma
            $msg = Messages::hmacMessage($this->config->getVersion(), $cid, $kid, $tsStr, $nonceB64, $method, $path, $qStr, $calcDig);

            if ($this->config->getSignAlg() === SecurePayload::SIGN_ALG_HYBRID) {
                $this->config->ensureSodium();
                $pub = base64_decode($ed25519PubB64 ?? '', true);
                $mldsaPub = base64_decode($mldsaPubB64 ?? '', true);
                if (!is_string($pub) || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    $this->config->emitEvent(SecurePayload::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'ed25519_public']);
                    throw new SecurePayloadException('Public key Ed25519 tidak valid/tersedia untuk hybrid', SecurePayloadException::SERVER_ERROR);
                }
                if (!is_string($mldsaPub) || $mldsaPub === '') {
                    $this->config->emitEvent(SecurePayload::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'mldsa_public']);
                    throw new SecurePayloadException('Public key ML-DSA tidak valid/tersedia untuk hybrid', SecurePayloadException::SERVER_ERROR);
                }
                if (!$this->config->verifyHybrid($msg, $sigIn, $pub, $mldsaPub)) {
                    $this->config->emitEvent(SecurePayload::EVENT_SIGNATURE_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'alg' => 'hybrid']);
                    throw new SecurePayloadException('Tanda Tangan (hybrid) tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            } elseif ($this->config->getSignAlg() === 'ed25519') {
                $this->config->ensureSodium();
                $pub = base64_decode($ed25519PubB64 ?? '', true);
                if (!is_string($pub) || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    $this->config->emitEvent(SecurePayload::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'ed25519_public']);
                    throw new SecurePayloadException('Public key Ed25519 server tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
                }
                $sigRaw = base64_decode($sigIn, true);
                if (!is_string($sigRaw) || strlen($sigRaw) !== SODIUM_CRYPTO_SIGN_BYTES) {
                    throw new SecurePayloadException('Format signature Ed25519 rusak', SecurePayloadException::BAD_REQUEST);
                }
                if (!sodium_crypto_sign_verify_detached($sigRaw, $msg, $pub)) {
                    $this->config->emitEvent(SecurePayload::EVENT_SIGNATURE_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'alg' => 'ed25519']);
                    throw new SecurePayloadException('Tanda Tangan (Ed25519) tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            } else {
                if ($hmacRaw !== null && strlen($hmacRaw) < 32) {
                    throw new SecurePayloadException(
                        'HMAC Secret yang dimuat dari keyLoader terlalu pendek (minimum 32 karakter).',
                        SecurePayloadException::SERVER_ERROR
                    );
                }
                if (!$hmacRaw) {
                    $this->config->emitEvent(SecurePayload::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'hmac']);
                    throw new SecurePayloadException('Secret Key HMAC tidak ditemukan di server', SecurePayloadException::SERVER_ERROR);
                }
                $signKey = $this->config->deriveSubkey((string) $hmacRaw, SecurePayload::KDF_PURPOSE_SIGN_REQ);
                $sigB64 = base64_encode(hash_hmac('sha256', $msg, $signKey, true));
                if (!hash_equals($sigB64, $sigIn)) {
                    $this->config->emitEvent(SecurePayload::EVENT_SIGNATURE_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'alg' => 'hmac']);
                    throw new SecurePayloadException('Tanda Tangan (Signature) tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            }

            $result['mode'] = ($this->config->getMode() === 'both' && isset($rawBodyForHmac)) ? 'BOTH' : 'HMAC';
            // Dekompresi + validasi skema SETELAH seluruh verifikasi integritas
            // (digest + signature) lolos, TEPAT SEBELUM hasil dikembalikan.
            $finalBody = $this->finalizeBody($bodyForHmac, $H);
            $result['bodyPlain'] = $finalBody;
            $result['json'] = json_decode($finalBody, true);
            $this->enforcePayloadSchema($result['json'], $cid, $kid);
            return $result;
        }

        throw new SecurePayloadException('Tidak ditemukan header keamanan yang valid', SecurePayloadException::BAD_REQUEST);
    }

    /**
     * Terapkan dekompresi payload bila header X-Payload-Encoding menyatakan encoding.
     *
     * WAJIB dipanggil hanya SETELAH seluruh verifikasi integritas (digest/HMAC/tag
     * AEAD) atas byte body berhasil — byte yang didekompresi harus terikat bukti
     * integritas lebih dahulu. Encoding tidak dikenal ditolak fail-closed (400,
     * termasuk nilai dipalsukan attacker); dekompresi gagal/melebihi batas → 422.
     *
     * @param array<string,string> $H Map header yang sudah dinormalisasi uppercase.
     */
    private function finalizeBody(string $body, array $H): string
    {
        $enc = $H[self::upper(SecurePayload::HX_PAYLOAD_ENCODING)] ?? '';
        if ($enc === '' || $enc === 'identity') {
            return $body;
        }
        return PayloadCompressor::decompress($body, $enc);
    }

    /**
     * Tegakkan opsi server `payloadSchema` atas JSON hasil decode.
     *
     * Hanya aktif bila schema diset — tanpa schema, perilaku existing (json apa
     * adanya, termasuk null) dipertahankan penuh. Dengan schema: json === null
     * (JSON rusak/literal null) ATAU hasil validate() gagal → event
     * `payload_schema_invalid` + exception 422 (fail-closed).
     *
     * @param mixed $json Hasil json_decode(body, true).
     */
    private function enforcePayloadSchema($json, string $cid, string $kid): void
    {
        $schema = $this->config->getPayloadSchema();
        if ($schema === null) {
            return;
        }
        $error = $json === null
            ? 'Payload bukan JSON yang valid'
            : PayloadSchemaValidator::validate($json, $schema);
        if ($error !== null) {
            $this->config->emitEvent(SecurePayload::EVENT_PAYLOAD_SCHEMA_INVALID, [
                'clientId' => $cid,
                'keyId' => $kid,
                'error' => $error,
            ]);
            throw new SecurePayloadException(
                'Struktur payload tidak sesuai payloadSchema: ' . $error,
                SecurePayloadException::UNPROCESSABLE
            );
        }
    }

    private static function upper(string $s): string
    {
        return strtoupper($s);
    }
}
