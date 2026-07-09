# SecurePayload — Agent Guide

Library: `sk8dvlpr/securepayload` v2.9.0 | Protocol version: `3`

## Before Any Code Change

1. Read `.claude/skills/securepayload/securepayload-development/SKILL.md`
2. Run GitNexus `impact({target: "symbolName", direction: "upstream", repo: "SecurePayload"})` on symbols you will edit
3. If touching verify/build/sign/AEAD/replay: read `securepayload-security-review` skill
4. Run `composer test` and `composer stan` before considering work complete
5. Run `detect_changes({scope: "compare", base_ref: "main", repo: "SecurePayload"})` before commit

## Security Invariants (Never Break)

- Server derives `method`/`path`/`query` from request input — **NOT** `X-Canonical-Request`
- Replay key excludes timestamp; TTL = `replayTtl + clockSkew`
- HMAC signs plaintext in `both` mode
- All secret/signature comparisons use `hash_equals`
- `signAlg` determined by server config (anti-downgrade) — applies to request **and** response
- `deriveKeys` and `bindHeaders` must match on client and server
- Ed25519 request: client keypair; Ed25519 response: server keypair (`ed25519PublicKeyServerB64` / `ed25519SecretKeyServerB64`)

## Roadmap

Phases 1–16 done. Phase 17 (ecosystem) next. Full plan: `docs/ROADMAP.md`

## SecurePayload Skills

| Task | Skill file |
|------|------------|
| Architecture / how X works | `.claude/skills/securepayload/securepayload-architecture/SKILL.md` |
| Implement feature / fix bug | `.claude/skills/securepayload/securepayload-development/SKILL.md` |
| Plan next phase / scope PR | `.claude/skills/securepayload/securepayload-roadmap/SKILL.md` |
| Security review | `.claude/skills/securepayload/securepayload-security-review/SKILL.md` |
| Framework integration | `.claude/skills/securepayload/securepayload-integration/SKILL.md` |

## Conventions

- Docblocks and exception messages in **Indonesian**
- PHP 8.0+ compatible (`platform.php` pinned to 8.0.28)
- `declare(strict_types=1)`; classes `final`

---

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **SecurePayload** (2127 symbols, 5794 relationships, 176 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
