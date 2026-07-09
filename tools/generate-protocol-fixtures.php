<?php
declare(strict_types=1);

/**
 * Regenerates docs/fixtures/v3/* JSON test vectors from the PHP reference implementation.
 * Usage: php tools/generate-protocol-fixtures.php
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use SecurePayload\SecurePayload;

const FIX_TS = 1700000000;
const FIX_RESP_TS = 1700000060;
const FIX_NONCE_B64 = 'AQEBAQEBAQEBAQEBAQEBAQ=='; // 16x 0x01
const FIX_RESP_NONCE_B64 = 'AgICAgICAgICAgICAgICAg=='; // 16x 0x02
const CLIENT_ID = 'conf-client';
const KEY_ID = 'conf-key-v1';
const HMAC_SECRET = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

$root = dirname(__DIR__);
$aeadKeyB64 = base64_encode(str_repeat("\x11", 32));
$base = $root . '/docs/fixtures/v3';

function ensureDir(string $path): void
{
    if (!is_dir($path)) {
        mkdir($path, 0755, true);
    }
}

function writeJson(string $path, array $data): void
{
    file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
}

function standardKeys(string $aeadKeyB64): array
{
    if (!extension_loaded('sodium')) {
        throw new RuntimeException('ext-sodium required to generate Ed25519 keys');
    }
    $clientSeed = str_repeat("\x42", 32);
    $serverSeed = str_repeat("\x43", 32);
    $clientPair = sodium_crypto_sign_seed_keypair($clientSeed);
    $serverPair = sodium_crypto_sign_seed_keypair($serverSeed);

    return [
        'clientId' => CLIENT_ID,
        'keyId' => KEY_ID,
        'hmacSecret' => HMAC_SECRET,
        'aeadKeyB64' => $aeadKeyB64,
        'ed25519ClientSecretB64' => base64_encode(sodium_crypto_sign_secretkey($clientPair)),
        'ed25519ClientPublicB64' => base64_encode(sodium_crypto_sign_publickey($clientPair)),
        'ed25519ServerSecretB64' => base64_encode(sodium_crypto_sign_secretkey($serverPair)),
        'ed25519ServerPublicB64' => base64_encode(sodium_crypto_sign_publickey($serverPair)),
    ];
}

function clientOpts(array $keys, array $config, array $fixed): array
{
    $opts = [
        'mode' => $config['mode'],
        'version' => '3',
        'clientId' => CLIENT_ID,
        'keyId' => KEY_ID,
        'hmacSecretRaw' => $keys['hmacSecret'],
        'aeadKeyB64' => $keys['aeadKeyB64'],
        'clock' => static fn (): int => $fixed['timestamp'],
        'nonceGenerator' => static fn (): string => $fixed['nonce_b64'],
    ];
    if (!empty($config['deriveKeys'])) {
        $opts['deriveKeys'] = true;
    }
    if (!empty($config['bindHeaders'])) {
        $opts['bindHeaders'] = $config['bindHeaders'];
    }
    if (($config['signAlg'] ?? 'hmac') === 'ed25519') {
        $opts['signAlg'] = 'ed25519';
        $opts['ed25519SecretKeyB64'] = $keys['ed25519ClientSecretB64'];
        $opts['ed25519PublicKeyServerB64'] = $keys['ed25519ServerPublicB64'];
    }
    return $opts;
}

function serverOpts(array $keys, array $config, array $fixed, bool $forResponse = false): array
{
    $opts = [
        'mode' => $config['mode'],
        'version' => '3',
        'signAlg' => $config['signAlg'] ?? 'hmac',
        'deriveKeys' => !empty($config['deriveKeys']),
        'bindHeaders' => $config['bindHeaders'] ?? [],
        'clock' => static fn (): int => $forResponse ? $fixed['resp_timestamp'] : $fixed['timestamp'],
        'respNonceGenerator' => static fn (): string => $fixed['resp_nonce_b64'],
        'replayStore' => static fn (string $k, int $t): bool => true,
        'keyLoader' => static function (string $c, string $k) use ($keys, $config): array {
            $out = [
                'hmacSecret' => $keys['hmacSecret'],
                'aeadKeyB64' => $keys['aeadKeyB64'],
                'ed25519PublicKeyB64' => null,
                'ed25519SecretKeyServerB64' => null,
            ];
            if (($config['signAlg'] ?? 'hmac') === 'ed25519') {
                $out['ed25519PublicKeyB64'] = $keys['ed25519ClientPublicB64'];
                $out['ed25519SecretKeyServerB64'] = $keys['ed25519ServerSecretB64'];
            }
            return $out;
        },
    ];
    return $opts;
}

ensureDir($base . '/keys');
ensureDir($base . '/primitive');
ensureDir($base . '/wire');
ensureDir($base . '/negative');

$keys = standardKeys($aeadKeyB64);
writeJson($base . '/keys/standard.json', $keys);

$reqMethod = 'POST';
$reqPath = '/v1/pay';
$reqQuery = ['a' => '1', 'b' => '2'];
$reqPayload = ['amount' => 100];
$plainJson = json_encode($reqPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$qStr = SecurePayload::canonicalQuery($reqQuery);
$digestB64 = SecurePayload::bodyDigestB64($plainJson);
$hmacMsg = SecurePayload::hmacMessage('3', CLIENT_ID, KEY_ID, (string) FIX_TS, FIX_NONCE_B64, $reqMethod, $reqPath, $qStr, $digestB64);

$primitiveFixtures = [
    'normalize-path' => [
        'id' => 'normalize-path',
        'cases' => [
            ['input' => '/api/v1/resource', 'expected' => '/api/v1/resource'],
            ['input' => '/api/v1/', 'expected' => '/api/v1'],
            ['input' => '/', 'expected' => '/'],
            ['input' => '', 'expected' => '/'],
        ],
    ],
    'canonical-query' => [
        'id' => 'canonical-query',
        'cases' => [
            ['input' => ['z' => 'last', 'a' => 'first', 'm' => 'middle'], 'expected' => 'a=first&m=middle&z=last'],
            ['input' => [], 'expected' => ''],
            ['input' => ['key' => 'a b', 'arr' => ['x', 'y']], 'expected' => 'arr=x%2Cy&key=a%20b'],
        ],
    ],
    'body-digest' => [
        'id' => 'body-digest',
        'input' => ['payload' => $reqPayload, 'json' => $plainJson],
        'expected' => ['digest_b64' => $digestB64, 'header_value' => 'sha256=' . $digestB64],
    ],
    'hmac-message' => [
        'id' => 'hmac-message',
        'input' => [
            'version' => '3',
            'clientId' => CLIENT_ID,
            'keyId' => KEY_ID,
            'timestamp' => (string) FIX_TS,
            'nonce_b64' => FIX_NONCE_B64,
            'method' => $reqMethod,
            'path' => $reqPath,
            'query' => $reqQuery,
            'body_digest_b64' => $digestB64,
        ],
        'expected' => ['message' => $hmacMsg],
    ],
    'aead-nonce-request' => [
        'id' => 'aead-nonce-request',
        'input' => [
            'nonce_b64' => FIX_NONCE_B64,
            'method' => $reqMethod,
            'path' => $reqPath,
            'query_string' => $qStr,
        ],
        'expected' => ['nonce_hex' => bin2hex(SecurePayload::aeadNonceFrom(FIX_NONCE_B64, $reqMethod, $reqPath, $qStr))],
    ],
    'aead-aad-request' => [
        'id' => 'aead-aad-request',
        'input' => ['version' => '3', 'timestamp' => (string) FIX_TS, 'bound_headers' => ['x-request-id' => 'trace-abc-123']],
        'expected' => ['aad' => SecurePayload::buildRequestAeadAad('3', (string) FIX_TS, ['x-request-id' => 'trace-abc-123'])],
    ],
    'resp-message' => [
        'id' => 'resp-message',
        'input' => [
            'version' => '3',
            'req_nonce_b64' => FIX_NONCE_B64,
            'resp_timestamp' => (string) FIX_RESP_TS,
            'resp_nonce_b64' => FIX_RESP_NONCE_B64,
            'body_digest_b64' => SecurePayload::bodyDigestB64(json_encode(['status' => 'ok'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)),
        ],
        'expected' => [
            'message' => SecurePayload::respMessage(
                '3',
                FIX_NONCE_B64,
                (string) FIX_RESP_TS,
                FIX_RESP_NONCE_B64,
                SecurePayload::bodyDigestB64(json_encode(['status' => 'ok'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))
            ),
        ],
    ],
    'resp-aead-nonce' => [
        'id' => 'resp-aead-nonce',
        'input' => ['resp_nonce_b64' => FIX_RESP_NONCE_B64, 'req_nonce_b64' => FIX_NONCE_B64],
        'expected' => ['nonce_hex' => bin2hex(SecurePayload::respAeadNonceFrom(FIX_RESP_NONCE_B64, FIX_NONCE_B64))],
    ],
    'hkdf-derive' => [
        'id' => 'hkdf-derive',
        'cases' => [
            [
                'master' => HMAC_SECRET,
                'purpose' => SecurePayload::KDF_PURPOSE_SIGN_REQ . '|v3',
                'expected_hex' => bin2hex(SecurePayload::deriveKey(HMAC_SECRET, SecurePayload::KDF_PURPOSE_SIGN_REQ . '|v3')),
            ],
            [
                'master_hex' => bin2hex(base64_decode($aeadKeyB64, true)),
                'master' => base64_decode($aeadKeyB64, true),
                'purpose' => SecurePayload::KDF_PURPOSE_AEAD_REQ . '|v3',
                'expected_hex' => bin2hex(SecurePayload::deriveKey(base64_decode($aeadKeyB64, true), SecurePayload::KDF_PURPOSE_AEAD_REQ . '|v3')),
            ],
        ],
    ],
];

foreach ($primitiveFixtures as $name => $data) {
    writeJson($base . '/primitive/' . $name . '.json', $data);
}

$fixed = [
    'timestamp' => FIX_TS,
    'nonce_b64' => FIX_NONCE_B64,
    'resp_timestamp' => FIX_RESP_TS,
    'resp_nonce_b64' => FIX_RESP_NONCE_B64,
];

$wireMatrix = [
    'req-hmac-v3' => ['mode' => 'hmac', 'signAlg' => 'hmac', 'roundtrip' => false],
    'req-aead-v3' => ['mode' => 'aead', 'signAlg' => 'hmac', 'roundtrip' => false],
    'req-both-hmac-v3' => ['mode' => 'both', 'signAlg' => 'hmac', 'roundtrip' => false],
    'req-both-ed25519-v3' => ['mode' => 'both', 'signAlg' => 'ed25519', 'roundtrip' => false],
    'roundtrip-both-hmac-v3' => ['mode' => 'both', 'signAlg' => 'hmac', 'roundtrip' => true],
    'roundtrip-aead-v3' => ['mode' => 'aead', 'signAlg' => 'hmac', 'roundtrip' => true],
    'roundtrip-both-ed25519-v3' => ['mode' => 'both', 'signAlg' => 'ed25519', 'roundtrip' => true],
    'req-aead-bindheaders-v3' => ['mode' => 'aead', 'signAlg' => 'hmac', 'roundtrip' => false, 'bindHeaders' => ['X-Request-Id'], 'extraHeaders' => ['X-Request-Id' => 'trace-abc-123']],
    'req-both-derivekeys-v3' => ['mode' => 'both', 'signAlg' => 'hmac', 'roundtrip' => false, 'deriveKeys' => true],
];

$url = 'https://api.example/v1/pay?a=1&b=2';
$wireOutputs = [];

foreach ($wireMatrix as $id => $cfg) {
    $config = [
        'mode' => $cfg['mode'],
        'signAlg' => $cfg['signAlg'],
        'deriveKeys' => !empty($cfg['deriveKeys']),
        'bindHeaders' => $cfg['bindHeaders'] ?? [],
    ];
    $extra = $cfg['extraHeaders'] ?? [];
    $client = new SecurePayload(clientOpts($keys, $config, $fixed));
    [$headers, $body] = $client->buildHeadersAndBody($url, $reqMethod, $reqPayload, $extra);

    $expected = ['headers' => $headers, 'body' => $body];

    if (!empty($cfg['roundtrip'])) {
        $server = new SecurePayload(serverOpts($keys, $config, $fixed, true));
        [$respHeaders, $respBody] = $server->buildResponse($headers, ['status' => 'ok']);
        $expected['response'] = [
            'headers' => $respHeaders,
            'body' => $respBody,
            'payload' => ['status' => 'ok'],
        ];
    }

    $fixture = [
        'id' => $id,
        'protocol_version' => '3',
        'config' => $config,
        'keys_ref' => 'standard',
        'fixed' => $fixed,
        'request' => [
            'method' => $reqMethod,
            'path' => $reqPath,
            'query' => $reqQuery,
            'payload' => $reqPayload,
            'extra_headers' => $extra,
        ],
        'expected' => $expected,
    ];
    writeJson($base . '/wire/' . $id . '.json', $fixture);
    $wireOutputs[$id] = $fixture;
}

// Negative fixtures derived from req-both-hmac-v3
$baseWire = $wireOutputs['req-both-hmac-v3'];
$badSig = $baseWire;
$sig = $badSig['expected']['headers'][SecurePayload::HX_SIGNATURE];
$badSig['expected']['headers'][SecurePayload::HX_SIGNATURE] = substr($sig, 0, -1) . ($sig[-1] === 'A' ? 'B' : 'A');
$badSig['id'] = 'bad-signature';
$badSig['tamper'] = 'X-Signature last char flipped';
$badSig['expected_failure'] = 'signature_invalid';
writeJson($base . '/negative/bad-signature.json', $badSig);

$badNonce = $baseWire;
$badNonce['id'] = 'bad-aead-nonce';
$badNonce['tamper'] = 'X-AEAD-Nonce replaced with zeros';
$badNonce['expected']['headers'][SecurePayload::HX_AEAD_NONCE] = base64_encode(str_repeat("\0", 24));
$badNonce['expected_failure'] = 'decrypt_failed';
writeJson($base . '/negative/bad-aead-nonce.json', $badNonce);

$badTs = $baseWire;
$badTs['id'] = 'bad-timestamp-aead';
$badTs['tamper'] = 'X-Timestamp shifted +5 within freshness window';
$badTs['expected']['headers'][SecurePayload::HX_TIMESTAMP] = (string) (FIX_TS + 5);
$badTs['expected_failure'] = 'decrypt_failed';
writeJson($base . '/negative/bad-timestamp-aead.json', $badTs);

$downgrade = $wireOutputs['req-both-ed25519-v3'];
$downgrade['id'] = 'signalg-downgrade';
$downgrade['tamper'] = 'Server configured signAlg=hmac but request header ED25519';
$downgrade['server_config'] = ['signAlg' => 'hmac'];
$downgrade['expected_failure'] = 'signature_invalid';
writeJson($base . '/negative/signalg-downgrade.json', $downgrade);

echo "Generated fixtures in docs/fixtures/v3/\n";
