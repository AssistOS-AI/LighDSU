---
id: DS003
title: "DS003 — Cryptographic Derivations"
order: 3
---

# DS003 — Cryptographic Derivations

## Introduction

All cryptographic keys in LightDSU are derived from the `lkeySecret`. This document specifies the derivation chain, the cryptographic suite, and the purpose of each derived key.

## Core Content

### Cryptographic Suite (v1 Fixed)

| Algorithm | Purpose |
|-----------|---------|
| SHA-256 | Hashing, event hashing, brick hashing, anchorId |
| HKDF-SHA256 | Key derivation |
| HMAC-SHA256 | DID hashing, resource hashing |
| Ed25519 | Anchor signing, actor signing (via DID strategy) |
| AES-256-GCM | Brick encryption, BrickMap encryption |
| Base58 | SSI payload encoding |

### Derivation Chain

All derivations start strictly from `lkeySecret`:

```
lkeySecret (32 bytes, random)
  │
  ├── HKDF(lkeySecret, salt=empty, info="anchor-signing", len=32)
  │     └── anchorSigningSeed (32 bytes)
  │           └── Ed25519 key pair
  │                 ├── anchorPrivate
  │                 └── anchorPublic (32 bytes)
  │                       └── anchorId = SHA256(anchorPublic) (32 bytes)
  │
  └── HKDF(lkeySecret, salt=empty, info="read-key", len=32)
        └── rkeySecret (32 bytes)
              │
              ├── HKDF(rkeySecret, salt=anchorId, info="brickmap", len=32)
              │     └── brickMapKey (32 bytes) — encrypts/decrypts BrickMap
              │
              └── HKDF(rkeySecret, salt=anchorId, info="access-index", len=32)
                    └── accessIndexKey (32 bytes) — HMAC key for DID/resource hashing
```

### Key Purposes

| Key | Purpose |
|-----|---------|
| `lkeySecret` | Root secret; full control over DSU |
| `anchorSigningSeed` | Seed for Ed25519 anchor key pair |
| `anchorPrivate` | Signs EventSSI anchor signatures |
| `anchorPublic` | Verifies anchor signatures; used to compute anchorId |
| `anchorId` | Unique identifier for the anchor file |
| `rkeySecret` | Read-only secret; derives BrickMap and access keys |
| `brickMapKey` | Encrypts/decrypts the BrickMap brick |
| `accessIndexKey` | HMAC key for hashing DIDs and resource scopes |

### Domain Independence

The `domain` field does **not** participate in any key derivation. It is purely a contextual label in the SSI format and engine configuration.

### rkey Derivation (from rkey payload)

When loading a DSU with an rkey:
1. Parse rkey payload: first 32 bytes = `rkeySecret`, next 32 bytes = `anchorPublic`.
2. Compute `anchorId = SHA256(anchorPublic)`.
3. Derive `brickMapKey = HKDF(rkeySecret, anchorId, "brickmap", 32)`.
4. Derive `accessIndexKey = HKDF(rkeySecret, anchorId, "access-index", 32)`.

### lza Derivation (from lza payload)

When loading a DSU with an lza:
1. Parse lza payload: 32 bytes = `anchorPublic`.
2. Compute `anchorId = SHA256(anchorPublic)`.
3. No further key derivation; lza cannot decrypt content.

### Implementation

- `src/crypto/primitives.js` — `sha256`, `hkdf`, `hmacSha256`, `aes256gcmEncrypt`, `aes256gcmDecrypt`, `ed25519KeyPairFromSeed`, `ed25519Sign`, `ed25519Verify`, `randomBytes`
- `src/engine.js` — `#deriveFromLkeySecret`, `#deriveFromRkeyPayload`, `#deriveFromLzaPayload`

## Decisions & Questions

### Question #1: Why use empty salt for the first HKDF derivations?

**Response:** The spec explicitly uses `salt = empty` for `anchorSigningSeed` and `rkeySecret` derivations. This ensures deterministic derivation from lkeySecret alone. The `anchorId` is used as salt for subsequent derivations, binding the BrickMap and access keys to the specific anchor.

### Question #2: Why is domain excluded from key derivation?

**Response:** Domain is a contextual label, not a cryptographic secret. Including it in key derivation would create false security (domain is visible in the SSI) and would complicate cross-domain migration scenarios.

## Conclusion

The derivation chain ensures that all keys are deterministically derived from the lkeySecret, with clear separation between signing (anchor), encryption (brickMap), and access control (accessIndex) purposes.
