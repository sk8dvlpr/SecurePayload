<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Protocol\PayloadSchemaValidator;

/**
   * Unit PayloadSchemaValidator.
  
   * Konvensi return: null = valid; string = pesan error Indonesia.
   * Setiap keyword diuji sisi valid dan invalid-nya.
  */
final class PayloadSchemaValidatorTest extends TestCase
{
    public function testTypeStringValidDanInvalid(): void
    {
        $schema = ['type' => 'string'];
        $this->assertNull(PayloadSchemaValidator::validate('halo', $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate(123, $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate(['a'], $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate(null, $schema));
    }

    public function testTypePerTipePrimitif(): void
    {
        $this->assertNull(PayloadSchemaValidator::validate(5, ['type' => 'integer']));
        $this->assertNotNull(PayloadSchemaValidator::validate(5.5, ['type' => 'integer']), 'Float bukan integer.');
        $this->assertNull(PayloadSchemaValidator::validate(5.5, ['type' => 'number']));
        $this->assertNull(PayloadSchemaValidator::validate(5, ['type' => 'number']));
        $this->assertNull(PayloadSchemaValidator::validate(true, ['type' => 'boolean']));
        $this->assertNotNull(PayloadSchemaValidator::validate(1, ['type' => 'boolean']), '1 bukan boolean.');
        $this->assertNull(PayloadSchemaValidator::validate(null, ['type' => 'null']));
        $this->assertNull(PayloadSchemaValidator::validate(['a' => 1], ['type' => 'object']));
        $this->assertNotNull(PayloadSchemaValidator::validate([1, 2], ['type' => 'object']));
        $this->assertNull(PayloadSchemaValidator::validate([1, 2], ['type' => 'array']));
        $this->assertNotNull(PayloadSchemaValidator::validate(['a' => 1], ['type' => 'array']));
    }

    public function testTypeSebagaiDaftar(): void
    {
        $schema = ['type' => ['string', 'integer']];
        $this->assertNull(PayloadSchemaValidator::validate('x', $schema));
        $this->assertNull(PayloadSchemaValidator::validate(10, $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate([], $schema));
    }

    public function testTipeTakDikenalDitolakFailClosed(): void
    {
        // Nama tipe tak dikenal (tunggal maupun di dalam daftar) = konfigurasi
        // salah → error fail-closed, terlepas dari urutan maupun nilai yang dicek.
        $this->assertNotNull(PayloadSchemaValidator::validate('x', ['type' => 'teks']));
        $this->assertNotNull(PayloadSchemaValidator::validate(1, ['type' => ['integer', 'teks']]));
        $this->assertNotNull(PayloadSchemaValidator::validate('apa pun', ['type' => ['teks', 'integer']]));

        // Daftar berisi hanya tipe valid tetap bekerja (semantik anyOf).
        $this->assertNull(PayloadSchemaValidator::validate(1, ['type' => ['string', 'integer']]));
    }

    public function testRequiredKurang(): void
    {
        $schema = [
            'type' => 'object',
            'required' => ['orderId', 'amount'],
        ];
        $this->assertNull(PayloadSchemaValidator::validate(['orderId' => 'A', 'amount' => 1], $schema));
        $err = PayloadSchemaValidator::validate(['orderId' => 'A'], $schema);
        $this->assertNotNull($err);
        $this->assertStringContainsString("'amount'", $err);
    }

    public function testRequiredEntryNonString_DitolakFailClosed(): void
    {
        // Entry non-string di `required` = konfigurasi skema salah → error,
        // bukan diloloskan diam-diam (konsisten dengan type/pattern/enum).
        $schema = [
            'type' => 'object',
            'required' => ['orderId', 42],
        ];
        $err = PayloadSchemaValidator::validate(['orderId' => 'A'], $schema);
        $this->assertNotNull($err);
        $this->assertStringContainsString('required', $err);

        // Nilai apa pun tetap ditolak selama konfigurasi required salah.
        $this->assertNotNull(PayloadSchemaValidator::validate(['orderId' => 'A', '42' => 1], $schema));

        // Nested: entry non-string di sub-skema juga ditolak dengan lokasi yang tepat.
        $nested = [
            'type' => 'object',
            'properties' => [
                'child' => ['type' => 'object', 'required' => [false]],
            ],
        ];
        $err2 = PayloadSchemaValidator::validate(['child' => []], $nested);
        $this->assertNotNull($err2);
        $this->assertStringContainsString('child', (string) $err2);
    }

    public function testEnum(): void
    {
        $schema = ['enum' => ['merah', 'kuning', 'hijau']];
        $this->assertNull(PayloadSchemaValidator::validate('kuning', $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate('biru', $schema));
        // Pencocokan ketat: "1" ≠ 1 dan true ≠ 1.
        $this->assertNotNull(PayloadSchemaValidator::validate('1', ['enum' => [1]]));
        $this->assertNotNull(PayloadSchemaValidator::validate(true, ['enum' => [1]]));
    }

    public function testMinimumMaximum(): void
    {
        $schema = ['type' => 'integer', 'minimum' => 1, 'maximum' => 10];
        $this->assertNull(PayloadSchemaValidator::validate(1, $schema), 'Batas inkklusif.');
        $this->assertNull(PayloadSchemaValidator::validate(10, $schema));
        $this->assertStringContainsString('>=', (string) PayloadSchemaValidator::validate(0, $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate(-5, $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate(11, $schema));
        $this->assertNull(PayloadSchemaValidator::validate(3.5, ['type' => 'number', 'minimum' => 3]));
    }

    public function testMinMaxLength(): void
    {
        $schema = ['type' => 'string', 'minLength' => 2, 'maxLength' => 5];
        $this->assertNull(PayloadSchemaValidator::validate('abc', $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate('a', $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate('abcdef', $schema));
    }

    public function testPattern(): void
    {
        $schema = ['type' => 'string', 'pattern' => '/^ID-\d{4}$/'];
        $this->assertNull(PayloadSchemaValidator::validate('ID-2026', $schema));
        $this->assertNotNull(PayloadSchemaValidator::validate('XX-2026', $schema));
        // Regex konfigurasi rusak → gagal fail-closed (bukan lolos diam-diam).
        $this->assertNotNull(PayloadSchemaValidator::validate('ID-2026', ['pattern' => '/[unclosed/']));
    }

    public function testItemsNested(): void
    {
        $schema = [
            'type' => 'object',
            'required' => ['items'],
            'properties' => [
                'items' => [
                    'type' => 'array',
                    'minItems' => 1,
                    'maxItems' => 3,
                    'items' => [
                        'type' => 'object',
                        'required' => ['sku'],
                        'properties' => [
                            'sku' => ['type' => 'string'],
                            'qty' => ['type' => 'integer', 'minimum' => 1],
                        ],
                    ],
                ],
            ],
        ];

        $valid = ['items' => [['sku' => 'A1', 'qty' => 2], ['sku' => 'B2']]];
        $this->assertNull(PayloadSchemaValidator::validate($valid, $schema));

        // qty di bawah minimum di elemen nested — error harus menyebut jalur.
        $err = PayloadSchemaValidator::validate(['items' => [['sku' => 'A1', 'qty' => 0]]], $schema);
        $this->assertNotNull($err);
        $this->assertStringContainsString('items[0].qty', $err);

        // sku hilang pada elemen kedua.
        $err2 = PayloadSchemaValidator::validate(['items' => [['sku' => 'A1'], ['qty' => 1]]], $schema);
        $this->assertStringContainsString("items[1]", (string) $err2);

        // maxItems dilanggar.
        $this->assertNotNull(PayloadSchemaValidator::validate(['items' => [[], [], [], []]], $schema));

        // minItems dilanggar (array kosong).
        $this->assertNotNull(PayloadSchemaValidator::validate(['items' => []], $schema));
    }

    public function testAdditionalPropertiesFalseMenolakFieldEkstra(): void
    {
        $schema = [
            'type' => 'object',
            'properties' => ['nama' => ['type' => 'string']],
            'additionalProperties' => false,
        ];
        $this->assertNull(PayloadSchemaValidator::validate(['nama' => 'budi'], $schema));
        $err = PayloadSchemaValidator::validate(['nama' => 'budi', 'umur' => 30], $schema);
        $this->assertNotNull($err);
        $this->assertStringContainsString("'umur'", $err);

        // additionalProperties tidak diset / true → field ekstra diperbolehkan.
        $this->assertNull(PayloadSchemaValidator::validate(['lain' => 1], ['properties' => []]));
        $this->assertNull(PayloadSchemaValidator::validate(['lain' => 1], ['additionalProperties' => true]));
    }

    public function testKedalamanMelebihiMaxDepth(): void
    {
        // Skema & data bersarang simetris n level: {child: {child: ... {}}}
        $buatSkema = static function (int $n) {
            $leaf = ['type' => 'object'];
            for ($i = 0; $i < $n; $i++) {
                $leaf = ['type' => 'object', 'properties' => ['child' => $leaf]];
            }
            return $leaf;
        };
        $buatData = static function (int $n) {
            $val = [];
            for ($i = 0; $i < $n; $i++) {
                $val = ['child' => $val];
            }
            return $val;
        };

        // Kedalaman 5 lolos dengan batas default 16 maupun custom yang cukup.
        $this->assertNull(PayloadSchemaValidator::validate($buatData(5), $buatSkema(5)));
        $this->assertNull(PayloadSchemaValidator::validate($buatData(5), $buatSkema(5), 6));

        // Melebihi maxDepth → ditolak dengan pesan kedalaman (bukan tipe).
        $err = PayloadSchemaValidator::validate($buatData(6), $buatSkema(6), 5);
        $this->assertNotNull($err);
        $this->assertStringContainsString('Kedalaman', $err);
    }

    public function testSkemaKompleksValidReturnNull(): void
    {
        $schema = [
            'type' => 'object',
            'required' => ['orderId', 'status'],
            'properties' => [
                'orderId' => ['type' => 'string', 'pattern' => '/^ORD-/'],
                'status' => ['enum' => ['baru', 'lunas']],
                'total' => ['type' => 'number', 'minimum' => 0],
                'catatan' => ['type' => ['string', 'null'], 'maxLength' => 255],
            ],
            'additionalProperties' => false,
        ];
        $json = ['orderId' => 'ORD-1', 'status' => 'lunas', 'total' => 99.5, 'catatan' => null];
        $this->assertNull(PayloadSchemaValidator::validate($json, $schema), 'Struktur sesuai skema harus mengembalikan null.');

        // Skema kosong = tanpa constraint apa pun.
        $this->assertNull(PayloadSchemaValidator::validate('apa pun', []));
    }
}
