---
name: securepayload-development
description: Guides implementing features, fixes, and tests in SecurePayload. Use when adding code, fixing bugs, writing tests, changing wire format, or preparing commits for this library.
---

# SecurePayload — Development Workflow

## Before Editing Code

1. Read `.claude/skills/securepayload/securepayload-architecture/SKILL.md` if unfamiliar with the area.
2. Check `docs/ROADMAP.md` — is this change part of a planned phase?
3. Run GitNexus **impact analysis** on symbols you will modify:
   ```
   impact({target: "symbolName", direction: "upstream", repo: "SecurePayload"})
   ```
4. Report blast radius to user; **stop and warn** on HIGH/CRITICAL risk.
5. If touching signing/verify/replay/AEAD: read `securepayload-security-review` skill.

## Commands

```bash
composer install
composer test                                    # full PHPUnit
vendor/bin/phpunit --testsuite Conformance       # protocol v3 fixture vectors
vendor/bin/phpunit --testsuite Security          # security regressions
vendor/bin/phpunit --testsuite Integration
vendor/bin/phpunit tests/Unit/SecurePayloadTest.php
vendor/bin/phpunit --filter testName
composer stan                                    # PHPStan level 5
find src -name "*.php" -print0 | xargs -0 -n1 php -l
```

CI mirrors: validate → install → `php -l` → PHPStan → PHPUnit on PHP 8.0–8.3.

## Code Conventions

- `declare(strict_types=1)` everywhere; classes `final`.
- **Indonesian** for docblocks, comments, and exception messages (match existing style).
- PHP **8.0-compatible** — `composer.json` pins `platform.php` to `8.0.28`.
- Minimize scope — smallest correct diff; no unrelated changes.
- `tests/`, `examples/`, dev configs are `export-ignore` in dist — consumers get only `src/`.

## Classifying Changes

| Type | Wire impact | Required actions |
|------|-------------|------------------|
| **Aditif** | None | Tests + CHANGELOG Added |
| **Observational** | None | Tests; must not alter verify path |
| **Opt-in** | Only when enabled | Document sync requirement (client+server) |
| **Breaking wire** | Ciphertext/signature incompatible | Bump `DEFAULT_VERSION`; Security tests; migration note |

Examples:
- Phase 8 `onSecurityEvent` — aditif
- Phase 5 `deriveKeys` — opt-in (fails closed if mismatched)
- Phase 3 AAD binding — breaking (v2 → v3)

## Adding a Feature Checklist

```
- [ ] Impact analysis run and reported
- [ ] Security invariants preserved (see architecture skill)
- [ ] Unit test(s) in tests/Unit/
- [ ] Integration round-trip if client+server path changes
- [ ] Security test if threat model affected (tests/Security/)
- [ ] PHPStan clean (composer stan)
- [ ] CHANGELOG.md entry with phase label if applicable
- [ ] docs/ROADMAP.md status updated if completing a phase
- [ ] CLAUDE.md updated if new invariant or public API
- [ ] detect_changes() before commit
```

## Touching `SecurePayload.php`

The core class is ~2100 lines. Before large additions:
- Prefer extracting private helpers over growing monolith (roadmap: refactor before Phase 9).
- Never break public method signatures without major version plan.
- Shared formatters: `normalizePath`, `canonicalQuery`, `hmacMessage`, `aeadNonceFrom` — change both build and verify paths together.

## Constructor Options Reference

| Option | Default | Notes |
|--------|---------|-------|
| `mode` | `both` | `hmac` \| `aead` \| `both` |
| `signAlg` | `hmac` | `hmac` \| `ed25519` |
| `version` | `3` | Must match client & server |
| `replayTtl` | `120` | seconds |
| `clockSkew` | `60` | seconds |
| `bindHeaders` | `[]` | AAD-bound header names |
| `deriveKeys` | `false` | HKDF subkey separation |
| `clock` | `time()` | Injectable timestamp for tests/fixtures |
| `nonceGenerator` | `genNonceB64()` | Injectable request nonce |
| `respNonceGenerator` | `genNonceB64()` | Injectable response nonce |

## Test Suites

| Suite | When to run |
|-------|-------------|
| `Unit` | Any code change in `src/` |
| `Integration` | Round-trip, HKDF, replay store, file stream, response |
| `Security` | Any change to verify, sign, replay, AAD, downgrade paths |
| `Conformance` | Protocol v3 JSON fixtures (`docs/fixtures/v3/`); run after wire/format changes |

Key security tests:
- `SignatureSpoofingTest.php`
- `DowngradeAndReplayTest.php`
- `AadBindingTest.php`
- `ResponseSecurityTest.php`
- `HkdfMismatchTest.php`
- `FileStreamSecurityTest.php`

## Commit Protocol

1. Run `detect_changes({scope: "compare", base_ref: "main", repo: "SecurePayload"})` before commit.
2. Verify only expected symbols/flows changed.
3. Do not commit unless user requests.
4. Commit message: focus on **why**, mention phase if applicable.

## Common Pitfalls

- Reading method/path from `X-Canonical-Request` on server → signature spoofing.
- Including timestamp in replay cache key → replay bypass.
- Signing ciphertext in `both` mode → breaks security contract.
- Shortening replay memory below `replayTtl + clockSkew`.
- Using `version => '2'` expecting old AAD behavior after v2.2 — AAD binding is unconditional in v3.
- Forgetting `ext-sodium` guard (`ensureSodium()`) on AEAD paths.

## Related Skills

- Architecture: `securepayload-architecture`
- Security review: `securepayload-security-review`
- Roadmap: `securepayload-roadmap`
- Integration examples: `securepayload-integration`
