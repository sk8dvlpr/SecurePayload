---
name: securepayload-roadmap
description: SecurePayload development roadmap, phase status, priorities, and scope boundaries. Use when planning features, scoping PRs, deciding what to build next, or checking if a proposed change fits the library scope.
---

# SecurePayload — Roadmap

**Source of truth:** `docs/ROADMAP.md` — update that file when phases complete.

**Current release:** 2.7.0 | **Protocol version:** 3

## Completed (Do Not Re-Implement)

Phases 1–14 are shipped. Phase 15 (Enterprise Ops) is next. See CHANGELOG.md v2.0.0–v2.7.1.

## Next Phases (Priority Order)

### Phase 14 — Cross-Language SDKs ✅
Node.js SDK (`packages/node-sdk`) and Go SDK (`packages/go-sdk`) shipped with conformance v3 + PHP interop + CI. **Requires Phase 11** ✅.

### Phase 15 — Enterprise Ops 📋
GCP/Azure KMS, Prometheus metrics via `onSecurityEvent`.

## Recommended Sequence

```
9 → 10 → 11 → 12 → 13 → 14 → 15
```

Phase 11 complete: `docs/PROTOCOL.md`, `docs/fixtures/v3/`, `tests/Conformance/`.

## Out of Scope

Do **not** add to this library:
- OAuth 2.0 / OIDC server
- Full API gateway
- User session management
- Weak crypto (AES-CBC, HS256-as-JWT, MD5, SHA-1)

## Scoping a PR

Ask:
1. Which phase does this belong to?
2. Is it aditif, opt-in, or breaking wire?
3. Does it need `DEFAULT_VERSION` bump?
4. Which test suites must pass?
5. Does ROADMAP.md + CHANGELOG + CLAUDE.md need updates?

## Phase Completion Checklist

When marking a phase done in `docs/ROADMAP.md`:

1. All features implemented and tested
2. CHANGELOG.md entry with `### Added` / `### Security` / `### Changed`
3. `docs/ROADMAP.md` status → ✅ Done
4. `CLAUDE.md` architecture section updated
5. `securepayload-architecture` skill updated if new APIs
6. Full `composer test` + `composer stan`
7. `detect_changes()` clean vs expectations

## CHANGELOG Phase Labels

Use consistent labels in CHANGELOG entries:
- `(Phase N)` in heading or Added section
- Note if wire format unchanged vs breaking
- Document client/server sync requirements for opt-in features

## Versioning Guidance

| Change | Version bump |
|--------|--------------|
| Aditif, no wire change | Minor (2.x.0) |
| Breaking wire / DEFAULT_VERSION | Major (3.0.0) or explicit migration in minor with version flag |
| Security fix | Patch + Security section |

## Future Ideas (Not Scheduled)

- RFC 9421 HTTP Message Signatures bridge
- Post-quantum hybrid signing
- Webhook verifier wrapper
- Multipart stream upload (manifest + file in one request)
- mTLS + SecurePayload documentation

Track new ideas in `docs/ROADMAP.md` under a "Backlog" section only after team agreement.
