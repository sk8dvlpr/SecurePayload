<?php
declare(strict_types=1);

use SecurePayload\SecurePayload;

return [
    'mode' => env('SECUREPAYLOAD_MODE', 'both'),
    'version' => env('SECUREPAYLOAD_VERSION', SecurePayload::DEFAULT_VERSION),
    'sign_alg' => env('SECUREPAYLOAD_SIGN_ALG', 'hmac'),
    'derive_keys' => (bool) env('SECUREPAYLOAD_DERIVE_KEYS', false),
    'bind_headers' => [],
    'replay_ttl' => (int) env('SECUREPAYLOAD_REPLAY_TTL', 120),
    'clock_skew' => (int) env('SECUREPAYLOAD_CLOCK_SKEW', 60),

    'server' => [
        'key_provider' => env('SECUREPAYLOAD_SERVER_KEY_PROVIDER', 'env'),
        'db' => [
            'table' => env('SECUREPAYLOAD_KEYS_TABLE', 'secure_keys'),
            'use_key_lifecycle' => (bool) env('SECUREPAYLOAD_USE_KEY_LIFECYCLE', false),
            'use_ed25519' => (bool) env('SECUREPAYLOAD_USE_ED25519', false),
            'use_ed25519_server' => (bool) env('SECUREPAYLOAD_USE_ED25519_SERVER', false),
        ],
    ],

    'client' => [
        'base_url' => env('SECUREPAYLOAD_BASE_URL', ''),
        'client_id' => env('SECUREPAYLOAD_CLIENT_ID', ''),
        'key_id' => env('SECUREPAYLOAD_KEY_ID', ''),
        'hmac_secret' => env('SECUREPAYLOAD_HMAC_SECRET', ''),
        'hmac_secret_is_hex' => (bool) env('SECUREPAYLOAD_HMAC_SECRET_IS_HEX', false),
        'aead_key_b64' => env('SECUREPAYLOAD_AEAD_KEY_B64', ''),
        'ed25519_secret_b64' => env('SECUREPAYLOAD_ED25519_SECRET_B64', ''),
        'ed25519_public_server_b64' => env('SECUREPAYLOAD_ED25519_PUBLIC_SERVER_B64', ''),
    ],

    'replay_store' => [
        'driver' => env('SECUREPAYLOAD_REPLAY_DRIVER', 'file'),
    ],
];
