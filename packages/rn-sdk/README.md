# @sk8dvlpr/securepayload-rn

React Native / TypeScript client SDK (protocol v3/v4) untuk SecurePayload.
**Client-only portable core** — build request aman (`buildHeadersAndBody`) dan verifikasi response (`verifyResponse`), tanpa satu pun import `node:*`.

## Kenapa SDK terpisah?

`@sk8dvlpr/securepayload-node` memakai `node:crypto`, yang tidak tersedia di Hermes/JSC. Paket ini adalah fork mini portabel:

| Fungsi | node-sdk | rn-sdk |
|---|---|---|
| SHA-256 / HMAC / HKDF | `node:crypto` | `@noble/hashes` (pure TS) |
| XChaCha20-Poly1305 | `@stablelib/xchacha20poly1305` | sama (sudah pure JS) |
| Ed25519 & random bytes | `node:crypto` + `tweetnacl` | `tweetnacl` |
| Base64 / UTF-8 | `Buffer` | implementasi internal murni JS |

Kebenaran byte-level dijaga `tests/drift.test.ts`: untuk vektor sama, output rn-core **byte-identik** dengan node-sdk core (yang sendirinya conformance terhadap fixture PHP di `docs/fixtures/v3`).

## Install

```bash
npm i @sk8dvlpr/securepayload-rn
# polyfill CSPRNG bila runtime Anda belum punya globalThis.crypto.getRandomValues:
npm i react-native-get-random-values
```

```ts
// entry index.js — SEBELUM import securepayload-rn
import 'react-native-get-random-values';
```

## Penggunaan

```ts
import { SecurePayloadClient, sendSecureRequest } from '@sk8dvlpr/securepayload-rn';

const client = new SecurePayloadClient({
  mode: 'both',            // 'hmac' | 'aead' | 'both'
  version: '3',
  clientId: 'mobile-app-1',
  keyId: 'key-v1',
  hmacSecretRaw: '<secret min 32 karakter>',
  aeadKeyB64: '<base64 kunci AEAD 32 byte>',
  deriveKeys: false,
});

// Opsi A: manual dengan fetch biasa
const [headers, body] = await client.buildHeadersAndBody(
  'https://api.example.com/v1/pay?ref=abc',
  'POST',
  { amount: 100 },
);

const res = await fetch('https://api.example.com/v1/pay?ref=abc', {
  method: 'POST',
  headers: { ...headers, 'Content-Type': 'application/json' },
  body,
});
const raw = await res.text();
const verified = client.verifyResponse(rawHeaders(res), raw, headers['X-Nonce']);
if (!verified.ok) throw new Error(`Response tampered: ${verified.error}`);
console.log(verified.json); // payload asli hasil dekripsi

// Opsi B: helper transport sekali panggil
const result = await sendSecureRequest(client, 'https://api.example.com/v1/pay', { amount: 100 });
if (result.verification?.ok) console.log(result.verification.json);
```

### Metro

Tidak ada konfigurasi khusus: semua dependensi pure-JS, tanpa modul Node. Field `"react-native"` di package.json mengarah ke source TS sehingga Metro membundel langsung.

## Batasan (jujur)

- **Logic-tested in Node via fixtures v3; device smoke test manual.** Semua test (65) berjalan di Node/Vitest termasuk drift byte-identik vs node-sdk. Belum ada pengujian otomatis on-device (Hermes/JSC) — lakukan smoke run di emulator sebelum produksi.
- **v1 client-only**: tidak ada `verify()` server / `buildResponse()`. Mobile jarang jadi server; adapter replay store disediakan untuk kasus khusus.
- **CSPRNG wajib tersedia**: nonce default memakai `globalThis.crypto.getRandomValues`, fallback ke PRNG internal `tweetnacl`. Di runtime yang punya keduanya aman; pastikan minimal satu sumber entropi OS benar-benar ada (Hermes murni belum punya — pakai `react-native-get-random-values` atau `expo-crypto`).
- **tweetnacl bundling**: `require('crypto')` opsional di dalam tweetnacl bisa membuat Metro error resolve. Bila terjadi, alias-kan via `metro.config.js` (`resolver.resolveRequest`) ke stub, karena rn-sdk sendiri tidak menyentuh module itu.
- **Kompresi payload (compress di PHP SDK) tidak didukung** — fitur PHP-only; jangan aktifkan `compress` di server untuk klien ini.
- **Hybrid PQ (`hybrid-mldsa44-ed25519`) tidak didukung** — hanya `signAlg: 'hmac' | 'ed25519'`.
- **Base64 decode ketat**: input base64 dari pihak ketiga harus berpadding standar RFC 4648 (semua output SDK lain sudah demikian).

## API utama

- `new SecurePayloadClient(options)` — mode/signAlg/version/kredensial/clock/nonceGenerator injectable.
- `client.buildHeadersAndBody(url, method, payload, extraHeaders?)` → `[headers, body]`
- `client.verifyResponse(headers, rawBody, reqNonceB64)` → `{ ok, mode?, bodyPlain?, json?, status?, error? }`
- `client.verifyResponseOrThrow(...)` — semantik `ResponseVerifier.php`.
- `sendSecureRequest(client, url, payload, { fetchImpl?, ... })` — fetch + verifikasi otomatis.
- `createInMemoryReplayStore()` — adapter `(cacheKey, ttl) => boolean`.
- Primitif: `normalizePath`, `canonicalQuery`, `bodyDigestB64`, `hmacMessage`, `respMessage`, `aeadNonceFrom`, `respAeadNonceFrom`, `buildRequestAeadAad`, `buildResponseAeadAad`, `deriveSubkey`, `signHmac`.

## Development

```bash
cd packages/rn-sdk
npm install
npx vitest run   # 4 suite: fixture, drift, guard, transport
```

- `tests/drift.test.ts` — kunci kebenaran: rn-core == node-sdk core/client (impor langsung kedua paket).
- `tests/guard.test.ts` — statis: src/** bebas `node:*`, builtin Node bare import, `Buffer`, `process`, `require()`.
