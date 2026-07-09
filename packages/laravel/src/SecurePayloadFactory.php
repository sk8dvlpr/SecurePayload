<?php
declare(strict_types=1);

namespace SecurePayload\Laravel;

use PDO;
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\SecurePayload;

final class SecurePayloadFactory
{
    public const REQUEST_ATTRIBUTE = 'securepayload';

    /**
     * @param array<string,mixed> $config
     */
    public static function createServer(array $config, ?PDO $pdo = null): SecurePayload
    {
        $opts = self::baseOptions($config);
        $opts['keyLoader'] = self::buildKeyLoader($config, $pdo);

        return new SecurePayload($opts);
    }

    /**
     * @param array<string,mixed> $config
     */
    public static function createClient(array $config): SecurePayload
    {
        $client = $config['client'] ?? [];
        $opts = self::baseOptions($config);
        $opts['clientId'] = (string) ($client['client_id'] ?? '');
        $opts['keyId'] = (string) ($client['key_id'] ?? '');
        $opts['hmacSecretRaw'] = self::resolveHmacSecret($client);
        $aead = (string) ($client['aead_key_b64'] ?? '');
        if ($aead !== '') {
            $opts['aeadKeyB64'] = $aead;
        }
        $edSk = (string) ($client['ed25519_secret_b64'] ?? '');
        if ($edSk !== '') {
            $opts['ed25519SecretKeyB64'] = $edSk;
        }
        $edPkSrv = (string) ($client['ed25519_public_server_b64'] ?? '');
        if ($edPkSrv !== '') {
            $opts['ed25519PublicKeyServerB64'] = $edPkSrv;
        }

        return new SecurePayload($opts);
    }

    /**
     * @param iterable<string, array<int, string>|string> $headers
     * @return array<string, string>
     */
    public static function normalizeHeaders(iterable $headers): array
    {
        $out = [];
        foreach ($headers as $k => $vals) {
            if (!is_string($k)) {
                continue;
            }
            $out[strtoupper($k)] = is_array($vals) ? implode(',', $vals) : (string) $vals;
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $config
     * @return array<string, mixed>
     */
    private static function baseOptions(array $config): array
    {
        return [
            'mode' => (string) ($config['mode'] ?? 'both'),
            'version' => (string) ($config['version'] ?? SecurePayload::DEFAULT_VERSION),
            'signAlg' => (string) ($config['sign_alg'] ?? 'hmac'),
            'deriveKeys' => !empty($config['derive_keys']),
            'bindHeaders' => is_array($config['bind_headers'] ?? null) ? $config['bind_headers'] : [],
            'replayTtl' => (int) ($config['replay_ttl'] ?? 120),
            'clockSkew' => (int) ($config['clock_skew'] ?? 60),
        ];
    }

    /**
     * @param array<string,mixed> $config
     */
    private static function buildKeyLoader(array $config, ?PDO $pdo): callable
    {
        $server = $config['server'] ?? [];
        $provider = (string) ($server['key_provider'] ?? 'env');

        if ($provider === 'db') {
            if ($pdo === null) {
                throw new \InvalidArgumentException('PDO diperlukan untuk key_provider=db');
            }
            $db = $server['db'] ?? [];
            $dbProvider = new DbKeyProvider($pdo, [
                'table' => $db['table'] ?? 'secure_keys',
                'useKeyLifecycle' => !empty($db['use_key_lifecycle']),
                'useEd25519' => !empty($db['use_ed25519']),
                'useEd25519Server' => !empty($db['use_ed25519_server']),
            ]);

            return static fn (string $cid, string $kid): array => $dbProvider->load($cid, $kid);
        }

        $envProvider = new EnvKeyProvider();

        return static fn (string $cid, string $kid): array => $envProvider->load($cid, $kid);
    }

    /**
     * @param array<string,mixed> $client
     */
    private static function resolveHmacSecret(array $client): ?string
    {
        $secret = (string) ($client['hmac_secret'] ?? '');
        if ($secret === '') {
            return null;
        }
        if (!empty($client['hmac_secret_is_hex'])) {
            $bin = hex2bin($secret);

            return $bin !== false ? $bin : $secret;
        }

        return $secret;
    }
}
