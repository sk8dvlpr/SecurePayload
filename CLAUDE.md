# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sk8dvlpr/securepayload` is a framework-agnostic PHP 8.0+ library (single core class plus a KMS subsystem) for securing S2S / client-server HTTP requests with HMAC-SHA256 signing, XChaCha20-Poly1305 AEAD encryption, and anti-replay protection. Distributed via Packagist; no application/runtime — it's a library consumed by other apps.

Note: source comments, docblocks, and exception messages are written in **Indonesian**. Match that language when editing existing code so the style stays consistent.

## Commands

```bash
composer install                      # install dev deps (phpunit, phpstan)

composer test                         # run full PHPUnit suite
vendor/bin/phpunit                    # same
vendor/bin/phpunit --testsuite Unit   # one suite: Unit | Integration | Security
vendor/bin/phpunit tests/Unit/SecurePayloadTest.php          # single file
vendor/bin/phpunit --filter testVerifyRejectsReplay          # single test by name

composer stan                         # PHPStan level 5 on src/
vendor/bin/phpstan analyse -c phpstan.neon

find src -name "*.php" -print0 | xargs -0 -n1 php -l          # syntax lint (mirrors CI)
```

CI (`.github/workflows/ci.yml`) runs validate → install → `php -l` → PHPStan → PHPUnit across PHP 8.0–8.3. `composer.json` pins `platform.php` to `8.0.28`, so locally-installed deps resolve against 8.0 even on a newer interpreter — keep new code 8.0-compatible.

Dev-only files (`tests/`, `examples/`, `.github/`, `phpunit.xml.dist`, `phpstan.neon`, `CLAUDE.md`) are excluded from the Composer dist via `.gitattributes` `export-ignore` — consumers get only `src/`.

## Architecture

### Core protocol (`src/SecurePayload.php`)

One ~1100-line `final class SecurePayload` is the whole protocol. It is both the client (build/sign/encrypt) and the server (verify/decrypt) side, selected by which methods you call.

- **Modes**: `'hmac'` (sign only), `'aead'` (encrypt only), `'both'` (encrypt + sign). Set at construction.
- **Client entry points**: `buildHeadersAndBody()` (core), `send()` (cURL wrapper), `buildFilePayload()`/`sendFile()` (file attachments).
- **Server entry points**: `verify()` (safe, returns `['ok'=>bool, ...]`), `verifyOrThrow()` (throws `SecurePayloadException`), `verifySimple()`, `verifyFilePayload()`.

Security headers are `X-Client-Id`, `X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature-*`, `X-Body-Digest`, `X-Canonical-Request`, `X-AEAD-*` (the `HX_*` constants).

Invariants that must stay true when modifying signing/verifying — these are the security contract:

- **Canonicalization is symmetric.** Client and server must produce identical canonical method/path/query. `normalizePath()`, `canonicalQuery()` (ksort + rawurlencode), `hmacMessage()`, and `aeadNonceFrom()` are the shared formatters — changing one side without the other silently breaks all verification.
- **The server derives method/path/query from its own request input, NOT from the `X-Canonical-Request` header.** That header is a debug hint only. `verifyOrThrow()` requires the caller to pass `$method`/`$path`/`$query` explicitly. Do not "fix" verification by reading them from headers — that reintroduces a signature-spoofing vuln (see `tests/Security/SignatureSpoofingTest.php`).
- **HMAC signs the plaintext, not the ciphertext** (in `both` mode), so verification asserts the meaning of the data. The AEAD nonce is derived from the client nonce bound to method/path/query (`aeadNonceFrom`) and re-verified via `hash_equals` to prevent nonce relocation.
- Use `hash_equals` for every secret/signature comparison.
- HMAC secrets are rejected if `< 32` chars (both at construction and when loaded via keyLoader). AEAD keys must decode to exactly 32 bytes.

### Replay protection (`checkReplay`)

Default is a **file-based** nonce cache in `sys_get_temp_dir()` with `flock` + double-checked locking and probabilistic GC. This is per-host and **does not work across multiple servers / load balancers**. For production multi-server, callers must inject a `replayStore` callback `fn(string $cacheKey, int $ttl): bool` (returns true if nonce is new) backed by Redis/Memcached. Preserve this extension point.

The replay key is `hash(clientId|keyId|nonce)` — deliberately **excludes the timestamp**, so a nonce is single-use regardless of the (unauthenticated, in `aead` mode) timestamp header. Nonces are remembered for `replayTtl + clockSkew` (the full window in which a timestamp can still pass freshness), not just `replayTtl`. Do not reintroduce the timestamp into the key or shorten the memory window — that reopens a replay bypass.

Timestamp window: rejects future beyond `clockSkew` (default 60s) and past beyond `replayTtl + clockSkew` (replayTtl default 120s).

### Key management (`src/KMS/`)

The server loads per-(clientId, keyId) secrets through a `keyLoader` callable returning `['hmacSecret'=>?string, 'aeadKeyB64'=>?string]`. Providers implementing `SecureKeyProvider`:

- `EnvKeyProvider` — reads `SECUREPAYLOAD_{CID}_{KID}_HMAC_SECRET` / `_AEAD_KEY_B64` env vars.
- `DbKeyProvider` — PDO-backed (`secure_keys` table by default; column names configurable). Table/column names are validated against `^[A-Za-z_][A-Za-z0-9_]*$` since they're interpolated into SQL (values are always bound). If a row stores a *wrapped* AEAD key (`wrapped_b64` + `kek_id`) instead of plaintext, it is unwrapped via an injected `Kms`.

Key-wrapping (encrypting the AEAD data-key with a KEK):
- `Kms` interface: `wrap()` / `unwrap()` with an AAD context array.
- `LocalKms` — XChaCha20-Poly1305 wrapping using KEKs from env (`SECURE_KEKS` list + `SECURE_KEK_{id}_B64`). AAD is `ksort`ed + json-encoded; the same context must be supplied to unwrap. The standard context is `['client_id'=>..., 'key_id'=>..., 'purpose'=>'securepayload-aead-key']`.
- `KeyManager` — generates HMAC+AEAD key pairs, optionally wraps the AEAD key, and emits ready-to-run `INSERT` SQL (`GeneratedKeyResult::toSqlInsert()`), nulling the plaintext AEAD column when a wrapped key exists.

### File transfer

Files are base64-embedded into the JSON payload under `_attachment` (`name/size/type/content`), then signed/encrypted like any payload — entire file is held in memory (+33% base64 overhead), so it's unsuitable for large files. `verifyFilePayload()` adds size limits, extension allow/block lists, and `strict_mime` magic-byte sniffing (anti-spoofing: rejects mismatches between extension and sniffed MIME, and blocks dangerous MIME types regardless of extension).

## Conventions

- `declare(strict_types=1)` everywhere; classes are `final`.
- Errors throw `SecurePayloadException` carrying an HTTP-style code (`BAD_REQUEST` 400, `UNAUTHORIZED` 401, `UNPROCESSABLE` 422, `SERVER_ERROR` 500) and a `context` array surfaced in `verify()`'s `debug` field.
- `ext-sodium` is a soft dependency (`suggest`, guarded by `ensureSodium()`) — only required for `aead`/`both` modes. Keep HMAC-only paths working without it.
- Framework integration examples (Laravel, Lumen, CI4, Symfony, Slim, native) live in `examples/` and are documentation, not autoloaded code.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **SecurePayload** (947 symbols, 2689 relationships, 70 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/SecurePayload/context` | Codebase overview, check index freshness |
| `gitnexus://repo/SecurePayload/clusters` | All functional areas |
| `gitnexus://repo/SecurePayload/processes` | All execution flows |
| `gitnexus://repo/SecurePayload/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
