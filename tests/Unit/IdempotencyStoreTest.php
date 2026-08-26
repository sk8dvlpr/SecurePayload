<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use SecurePayload\Idempotency\ArrayIdempotencyStore;
use SecurePayload\Idempotency\Psr16IdempotencyStore;

/**
 * Unit store idempotensi.
 */
final class IdempotencyStoreTest extends TestCase
{
    /** Fake PSR-16 array cache sederhana. */
    private function cache(): CacheInterface
    {
        return new class implements CacheInterface {
            /** @var array<string,mixed> */
            public array $data = [];
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
            /** @return iterable<string,mixed> */
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

    // --- ArrayIdempotencyStore ---

    public function testArrayStoreUnknownKeyNull(): void
    {
        $store = new ArrayIdempotencyStore();
        $this->assertNull($store->get('belum-ada'));
    }

    public function testArrayStoreSetGetRoundtrip(): void
    {
        $store = new ArrayIdempotencyStore();
        $result = ['status' => 'paid', 'amount' => 15000];
        $store->set('order-1', $result, 300);
        $this->assertSame($result, $store->get('order-1'));
    }

    public function testArrayStoreOverwriteTerakhirMenang(): void
    {
        $store = new ArrayIdempotencyStore();
        $store->set('k', ['v' => 1], 60);
        $store->set('k', ['v' => 2], 60);
        $this->assertSame(['v' => 2], $store->get('k'));
    }

    public function testArrayStoreTtlNolTanpaKedaluwarsa(): void
    {
        $store = new ArrayIdempotencyStore();
        $store->set('persist', ['ok' => true], 0);
        $this->assertSame(['ok' => true], $store->get('persist'));
    }

    public function testArrayStoreKedaluwarsaLazyExpire(): void
    {
        $store = new ArrayIdempotencyStore();
        $store->set('sementara', ['x' => 1], 30);
        $this->assertSame(['x' => 1], $store->get('sementara'));

        // Backdate expiresAt via refleksi agar uji kedaluwarsa deterministik tanpa sleep.
        $prop = (new \ReflectionClass($store))->getProperty('items');
        $items = $prop->getValue($store);
        $items['sementara']['expiresAt'] = time() - 1;
        $prop->setValue($store, $items);

        $this->assertNull($store->get('sementara'), 'Entri kedaluwarsa harus dianggap tidak ada.');
    }

    // --- Psr16IdempotencyStore ---

    public function testPsr16StoreSetGetDenganPrefix(): void
    {
        $cache = $this->cache();
        $store = new Psr16IdempotencyStore($cache);
        $store->set('req-abc', ['hasil' => 'A'], 600);

        $this->assertSame(['hasil' => 'A'], $store->get('req-abc'));
        // Nilai tersimpan di-cache dengan prefiks namespace.
        $this->assertTrue($cache->has('sp-idem-req-abc'));
    }

    public function testPsr16StorePrefixIsolasi(): void
    {
        $cache = $this->cache();
        $a = new Psr16IdempotencyStore($cache, 'app-a:');
        $b = new Psr16IdempotencyStore($cache, 'app-b:');
        $a->set('k', ['dari' => 'a'], 60);
        $this->assertNull($b->get('k'), 'Prefiks berbeda harus terisolasi.');
        $this->assertSame(['dari' => 'a'], $a->get('k'));
    }

    public function testPsr16NilaiNonArrayDianggapNull(): void
    {
        $cache = $this->cache();
        $cache->set('sp-idem-rusak', 'string-korup');
        $store = new Psr16IdempotencyStore($cache);
        $this->assertNull($store->get('rusak'), 'Nilai korup/non-array harus fail-closed sebagai miss.');
    }

    public function testRetryKeduaMengembalikanHasilTersimpan(): void
    {
        // Pola konsumsi standar: get → eksekusi bila null → set → retry get.
        foreach ([new ArrayIdempotencyStore(), new Psr16IdempotencyStore($this->cache())] as $i => $store) {
            $eksekusi = 0;
            $proses = static function () use (&$eksekusi): array {
                $eksekusi++;
                return ['status' => 'sukses', 'attempt' => $eksekusi];
            };

            $pertama = $store->get('idem-1');
            if ($pertama === null) {
                $hasil = $proses();
                $store->set('idem-1', $hasil, 3600);
            }

            // Retry dengan kunci sama TIDAK mengeksekusi ulang — balas dari cache.
            $kedua = $store->get('idem-1');
            if ($kedua === null) {
                $proses();
            }

            $this->assertSame(1, $eksekusi, "Store #$i: proses hanya boleh dieksekusi sekali.");
            $this->assertSame($store->get('idem-1'), ['status' => 'sukses', 'attempt' => 1]);
        }
    }
}
