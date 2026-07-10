# RFC 9421 Bridge (SecurePayload)

Bridge aditif antara header SecurePayload dan [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures (`hmac-sha256`).

**Versi library:** 2.11.0+  
**Kelas:** `SecurePayload\Interop\Rfc9421Bridge`

## Tujuan

- **Export:** ubah header SP (`X-Signature`, identitas, dll.) menjadi `Signature-Input`, `Signature`, dan `Content-Digest`.
- **Verify:** jika `Signature-Input` ada, validasi `Content-Digest` + komponen wajib, petakan identitas ke header SP, lalu panggil `SecurePayload::verify()` (fail-closed).

Bridge **tidak** mengganti protokol SP. Verifikasi kriptografi tetap di jalur SP.

## Content-Digest

Format (RFC 9530):

```
Content-Digest: sha-256=:<base64(SHA-256(body))>:
```

## Signature-Input (export)

Label `sp1`. Komponen yang dicakup:

| Komponen | Wajib |
|----------|-------|
| `@method` | ya |
| `@path` | ya |
| `@query` | ya |
| `content-digest` | ya |
| `x-client-id` | jika `X-Client-Id` ada |
| `x-key-id` | jika `X-Key-Id` ada |

Contoh:

```http
Signature-Input: sp1=("@method" "@path" "@query" "content-digest" "x-client-id" "x-key-id");created=1700000000;keyid="k1";alg="hmac-sha256"
Signature: sp1=:<X-Signature base64>:
Content-Digest: sha-256=:<base64>:
```

Nilai `Signature` adalah `X-Signature` SP (bukan signature base RFC yang dihitung ulang).

## API

```php
use SecurePayload\Interop\Rfc9421Bridge;

// Client / gateway: setelah buildHeadersAndBody
[$spHeaders, $body] = $client->buildHeadersAndBody($url, 'POST', $payload);
$rfcHeaders = Rfc9421Bridge::exportFromSecureHeaders($spHeaders, 'POST', '/path', 'a=1', $body);

// Server: terima request dengan Signature-Input
$result = Rfc9421Bridge::verifyMapped($server, $httpHeaders, $rawBody, 'POST', '/path', $query);
```

## Fail-closed

`verifyMapped` menolak jika:

- Komponen wajib hilang dari `Signature-Input`
- `Content-Digest` tidak cocok dengan SHA-256 body
- `SecurePayload::verify()` gagal (timestamp, replay, signature, dll.)

Tanpa `Signature-Input`, bridge mendelegasikan langsung ke `$server->verify()`.

## Contoh

Lihat `examples/interop/rfc9421.php`.
