---
id: DS001
title: "DS001 — Coding Style"
order: 1
---

# DS001 — Coding Style

## Introduction

This document defines the coding conventions, module structure, and test organization rules for LightDSU v1. All contributors and agents must follow these conventions.

## Core Content

### Language and Runtime

- **Language**: JavaScript (CommonJS)
- **Runtime**: Node.js 18+
- **Strict mode**: `"use strict"` at the top of every file
- **No transpilation**: Plain Node.js, no Babel, no TypeScript

### Module Structure

```
src/
  index.js              — public API exports
  engine.js             — LightDSUEngine class
  dsu.js                — MountedLightDSU class
  ssi.js                — SSI parsing and serialization
  eventCodec.js         — EventSSI binary encoding/decoding
  anchor.js             — Anchor file operations and verification
  brickmap.js           — BrickMap structure and operations
  access.js             — Access control, scope matching, hashing
  storage.js            — Filesystem layout, brick I/O, locking
  errors.js             — Error codes and LightDSUError class
  utils.js              — Path normalization, canonical JSON
  actorMessage.js       — Actor message encoding
  defaultDidStrategy.js — Default Ed25519-based DID strategy
  provenancePayloadCodec.js — ProvenancePayloadV1 binary codec
  provenanceProfiles.js — Profile registry and validators
  crypto/
    primitives.js       — SHA-256, HKDF, HMAC, AES-256-GCM, Ed25519
    base58.js           — Base58 encoding/decoding
```

### Naming Conventions

- **Classes**: PascalCase (`LightDSUEngine`, `MountedLightDSU`)
- **Functions**: camelCase (`parseSSI`, `encodeEventPayload`)
- **Private methods**: `#` prefix (`#assertWritable`, `#commitVersion`)
- **Constants**: UPPER_SNAKE_CASE (`EVENT_TYPES`, `PERMISSIONS`)
- **Error codes**: `ERR_` prefix (`ERR_INVALID_SSI`, `ERR_ACCESS_DENIED`)

### Error Handling

- All errors use `LightDSUError` with a `code` property from `ERROR_CODES`.
- Use `throwError(code, message)` from `errors.js` for consistent error creation.
- Async errors propagate through Promise rejection.
- Never swallow errors silently; always propagate or wrap with context.

### Code Style

- **Indentation**: 2 spaces
- **Semicolons**: Required
- **Quotes**: Double quotes for strings
- **Line length**: Max 120 characters
- **No trailing whitespace**
- **One `module.exports` per file** at the bottom

### Test Organization

- Tests use Node.js built-in `node:test` and `node:assert/strict`.
- Test files live in `test/` with `.test.js` suffix.
- Each test file corresponds to a module or feature area.
- Tests are isolated: each creates a temporary directory via `fs.mkdtemp`.
- Run with `npm test` which executes `node --test`.

### Documentation

- All documentation, specs, and comments must be written in **English**.
- DS specifications are the source of truth for documented behavior.
- When source code changes, both HTML documentation and DS specifications must be updated.

## Decisions & Questions

### Question #1: Why CommonJS instead of ES modules?

**Response:** LightDSU targets Node.js 18+ and prioritizes compatibility with existing Node.js ecosystems. CommonJS is the default module system and works without configuration. ES modules can be adopted in a future major version if needed.

## Conclusion

These conventions ensure consistency, readability, and maintainability across the LightDSU codebase. All new code must follow these rules.
