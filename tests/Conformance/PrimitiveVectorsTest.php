<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Conformance;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class PrimitiveVectorsTest extends TestCase
{
    public function testNormalizePathVectors(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/normalize-path.json');
        foreach ($data['cases'] as $case) {
            $this->assertSame($case['expected'], SecurePayload::normalizePath($case['input']));
        }
    }

    public function testCanonicalQueryVectors(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/canonical-query.json');
        foreach ($data['cases'] as $case) {
            $this->assertSame($case['expected'], SecurePayload::canonicalQuery($case['input']));
        }
    }

    public function testBodyDigestVector(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/body-digest.json');
        $this->assertSame($data['expected']['digest_b64'], SecurePayload::bodyDigestB64($data['input']['json']));
    }

    public function testHmacMessageVector(): void
    {
        $in = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/hmac-message.json')['input'];
        $expected = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/hmac-message.json')['expected']['message'];
        $qStr = SecurePayload::canonicalQuery($in['query']);
        $msg = SecurePayload::hmacMessage(
            $in['version'],
            $in['clientId'],
            $in['keyId'],
            $in['timestamp'],
            $in['nonce_b64'],
            $in['method'],
            $in['path'],
            $qStr,
            $in['body_digest_b64']
        );
        $this->assertSame($expected, $msg);
    }

    public function testAeadNonceRequestVector(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/aead-nonce-request.json');
        $nonce = SecurePayload::aeadNonceFrom(
            $data['input']['nonce_b64'],
            $data['input']['method'],
            $data['input']['path'],
            $data['input']['query_string']
        );
        $this->assertSame($data['expected']['nonce_hex'], bin2hex($nonce));
    }

    public function testAeadAadRequestVector(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/aead-aad-request.json');
        $aad = SecurePayload::buildRequestAeadAad(
            $data['input']['version'],
            $data['input']['timestamp'],
            $data['input']['bound_headers']
        );
        $this->assertSame($data['expected']['aad'], $aad);
    }

    public function testRespMessageVector(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/resp-message.json');
        $in = $data['input'];
        $msg = SecurePayload::respMessage(
            $in['version'],
            $in['req_nonce_b64'],
            $in['resp_timestamp'],
            $in['resp_nonce_b64'],
            $in['body_digest_b64']
        );
        $this->assertSame($data['expected']['message'], $msg);
    }

    public function testRespAeadNonceVector(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/resp-aead-nonce.json');
        $nonce = SecurePayload::respAeadNonceFrom($data['input']['resp_nonce_b64'], $data['input']['req_nonce_b64']);
        $this->assertSame($data['expected']['nonce_hex'], bin2hex($nonce));
    }

    public function testHkdfDeriveVectors(): void
    {
        $data = FixtureLoader::loadFile(FixtureLoader::root() . '/primitive/hkdf-derive.json');
        foreach ($data['cases'] as $case) {
            $derived = SecurePayload::deriveKey($case['master'], $case['purpose']);
            $this->assertSame($case['expected_hex'], bin2hex($derived));
        }
    }
}
