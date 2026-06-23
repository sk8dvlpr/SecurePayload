<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use SecurePayload\ReplayStore\Psr16ReplayStore;
use SecurePayload\SecurePayload;

/**
 * Integrasi Phase 4 — adapter replay-store PSR-16.
 *
 * Memastikan:
 *  - nonce baru lolos, nonce yang diputar ulang ditolak (deteksi replay),
 *  - deteksi bekerja LINTAS instance SecurePayload yang berbagi satu cache
 *    (mensimulasikan beberapa server/worker di belakang Redis/Memcached bersama),
 *  - jalur atomik (add()) dipakai bila cache menyediakannya.
 */
final class Psr16ReplayStoreTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    /** Cache PSR-16 in-memory sederhana (tanpa add() atomik → jalur best-effort). */
    private function plainCache(): CacheInterface
    {
        return new class implements CacheInterface {
            /** @var array<string,mixed> */
            private array $data = [];
            public function get(string $key, mixed $default = null): mixed
            {
                return $this->data[$key] ?? $default;
            }
            public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
            {
                $this->data[$key] = $value;
                return true;
            }
            public function delete(string $key): bool
            {
                unset($this->data[$key]);
                return true;
            }
            public function clear(): bool
            {
                $this->data = [];
                return true;
            }
            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                $out = [];
                foreach ($keys as $k) {
                    $out[$k] = $this->data[$k] ?? $default;
                }
                return $out;
            }
            public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
            {
                foreach ($values as $k => $v) {
                    $this->data[$k] = $v;
                }
                return true;
            }
            public function deleteMultiple(iterable $keys): bool
            {
                foreach ($keys as $k) {
                    unset($this->data[$k]);
                }
                return true;
            }
            public function has(string $key): bool
            {
                return array_key_exists($key, $this->data);
            }
        };
    }

    /** Cache PSR-16 in-memory yang JUGA mengekspos add() atomik. */
    private function atomicCache(): CacheInterface
    {
        return new class implements CacheInterface {
            /** @var array<string,mixed> */
            private array $data = [];
            public function add(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
            {
                if (array_key_exists($key, $this->data)) {
                    return false;
                }
                $this->data[$key] = $value;
                return true;
            }
            public function get(string $key, mixed $default = null): mixed
            {
                return $this->data[$key] ?? $default;
            }
            public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
            {
                $this->data[$key] = $value;
                return true;
            }
            public function delete(string $key): bool
            {
                unset($this->data[$key]);
                return true;
            }
            public function clear(): bool
            {
                $this->data = [];
                return true;
            }
            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                $out = [];
                foreach ($keys as $k) {
                    $out[$k] = $this->data[$k] ?? $default;
                }
                return $out;
            }
            public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
            {
                foreach ($values as $k => $v) {
                    $this->data[$k] = $v;
                }
                return true;
            }
            public function deleteMultiple(iterable $keys): bool
            {
                foreach ($keys as $k) {
                    unset($this->data[$k]);
                }
                return true;
            }
            public function has(string $key): bool
            {
                return array_key_exists($key, $this->data);
            }
        };
    }

    private function client(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
    }

    private function server(CacheInterface $cache): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'hmac',
            'replayStore' => new Psr16ReplayStore($cache),
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);
    }

    public function testInvokeReturnsTrueOnceThenFalse(): void
    {
        $store = new Psr16ReplayStore($this->plainCache());
        $this->assertTrue($store('sp_key_abc', 120), 'Nonce pertama harus dianggap baru.');
        $this->assertFalse($store('sp_key_abc', 120), 'Nonce yang sama harus ditolak sebagai replay.');
    }

    public function testAtomicPathDetectedAndWorks(): void
    {
        $store = new Psr16ReplayStore($this->atomicCache());
        $this->assertTrue($store->isAtomic(), 'Cache dengan add() harus memakai jalur atomik.');
        $this->assertTrue($store('sp_atomic_1', 60));
        $this->assertFalse($store('sp_atomic_1', 60));
    }

    public function testBestEffortPathDetectedForPlainCache(): void
    {
        $store = new Psr16ReplayStore($this->plainCache());
        $this->assertFalse($store->isAtomic(), 'Cache PSR-16 murni memakai jalur best-effort.');
    }

    public function testReplayDetectedAcrossInstancesPlainCache(): void
    {
        $cache = $this->plainCache();
        $client = $this->client();
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);

        // Dua instance server berbeda berbagi satu cache (mensimulasikan multi-server).
        $serverA = $this->server($cache);
        $serverB = $this->server($cache);

        $resA = $serverA->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertTrue($resA['ok'], 'Request pertama harus lolos.');

        $resB = $serverB->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($resB['ok'], 'Request yang sama di instance lain harus terdeteksi replay.');
        $this->assertStringContainsString('Replay', $resB['error']);
    }

    public function testReplayDetectedAcrossInstancesAtomicCache(): void
    {
        $cache = $this->atomicCache();
        $client = $this->client();
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/y', 'POST', ['n' => 2]);

        $serverA = $this->server($cache);
        $serverB = $this->server($cache);

        $this->assertTrue($serverA->verify($headers, $body, 'POST', '/v1/y', [])['ok']);
        $resB = $serverB->verify($headers, $body, 'POST', '/v1/y', []);
        $this->assertFalse($resB['ok']);
        $this->assertStringContainsString('Replay', $resB['error']);
    }

    public function testDistinctNoncesBothPass(): void
    {
        $cache = $this->plainCache();
        $client = $this->client();
        $server = $this->server($cache);

        [$h1, $b1] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        [$h2, $b2] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $this->assertNotSame($h1[SecurePayload::HX_NONCE], $h2[SecurePayload::HX_NONCE]);

        $this->assertTrue($server->verify($h1, $b1, 'POST', '/v1/x', [])['ok']);
        $this->assertTrue($server->verify($h2, $b2, 'POST', '/v1/x', [])['ok'], 'Nonce berbeda harus sama-sama lolos.');
    }
}
