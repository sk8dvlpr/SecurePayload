<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Conformance;

final class FixtureLoader
{
    private static ?string $fixturesRoot = null;

    public static function root(): string
    {
        if (self::$fixturesRoot === null) {
            self::$fixturesRoot = dirname(__DIR__, 2) . '/docs/fixtures/v3';
        }
        return self::$fixturesRoot;
    }

    /**
     * @return array<string,mixed>
     */
    public static function loadKeys(string $ref = 'standard'): array
    {
        $path = self::root() . '/keys/' . $ref . '.json';
        if (!is_file($path)) {
            throw new \RuntimeException("Keys fixture not found: $path");
        }
        $data = json_decode((string) file_get_contents($path), true);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid keys fixture: $path");
        }
        return $data;
    }

    /**
     * @return list<string>
     */
    public static function listJsonFiles(string $subdir): array
    {
        $dir = self::root() . '/' . $subdir;
        if (!is_dir($dir)) {
            return [];
        }
        $files = glob($dir . '/*.json') ?: [];
        sort($files);
        return $files;
    }

    /**
     * @return array<string,mixed>
     */
    public static function loadFile(string $path): array
    {
        $data = json_decode((string) file_get_contents($path), true);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid fixture JSON: $path");
        }
        return $data;
    }

    /**
     * @param array<string,mixed> $keys
     * @param array<string,mixed> $config
     * @param array<string,mixed> $fixed
     * @return array<string,mixed>
     */
    public static function clientOpts(array $keys, array $config, array $fixed, array $extra = []): array
    {
        $opts = [
            'mode' => $config['mode'],
            'version' => $config['protocol_version'] ?? '3',
            'clientId' => $keys['clientId'],
            'keyId' => $keys['keyId'],
            'hmacSecretRaw' => $keys['hmacSecret'],
            'aeadKeyB64' => $keys['aeadKeyB64'],
            'clock' => static fn (): int => (int) $fixed['timestamp'],
            'nonceGenerator' => static fn (): string => (string) $fixed['nonce_b64'],
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

    /**
     * @param array<string,mixed> $keys
     * @param array<string,mixed> $config
     * @param array<string,mixed> $fixed
     * @return array<string,mixed>
     */
    public static function serverOpts(array $keys, array $config, array $fixed, bool $forResponse = false): array
    {
        $signAlg = $config['server_config']['signAlg'] ?? ($config['signAlg'] ?? 'hmac');
        return [
            'mode' => $config['mode'],
            'version' => $config['protocol_version'] ?? '3',
            'signAlg' => $signAlg,
            'deriveKeys' => !empty($config['deriveKeys']),
            'bindHeaders' => $config['bindHeaders'] ?? [],
            'clock' => static fn (): int => (int) ($forResponse ? $fixed['resp_timestamp'] : $fixed['timestamp']),
            'respNonceGenerator' => static fn (): string => (string) $fixed['resp_nonce_b64'],
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static function (string $c, string $k) use ($keys, $signAlg): array {
                $out = [
                    'hmacSecret' => $keys['hmacSecret'],
                    'aeadKeyB64' => $keys['aeadKeyB64'],
                    'ed25519PublicKeyB64' => null,
                    'ed25519SecretKeyServerB64' => null,
                ];
                if ($signAlg === 'ed25519') {
                    $out['ed25519PublicKeyB64'] = $keys['ed25519ClientPublicB64'];
                    $out['ed25519SecretKeyServerB64'] = $keys['ed25519ServerSecretB64'];
                }
                return $out;
            },
        ];
    }
}
