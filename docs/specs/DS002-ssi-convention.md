---
id: DS002
title: "DS002 — SSI Convention"
order: 2
---

# DS002 — SSI Convention

## Introduction

LightDSU uses a compact SSI (Self-Sovereign Identifier) convention inspired by OpenDSU. SSIs encode key material, anchor references, and event data in a colon-delimited string format with Base58-encoded payloads.

## Core Content

### SSI Format

```
ssi:<type>:<domain>:<payloadB58>:v1
```

For events:
```
ssi:event:<domain>:<payloadB58>:<signatureB58>:v1
```

### SSI Types

| Type | Format | Payload |
|------|--------|---------|
| `lkey` | `ssi:lkey:<domain>:<base58(lkeySecret)>:v1` | 32 bytes lkeySecret |
| `rkey` | `ssi:rkey:<domain>:<base58(rkeySecret \| anchorPublic)>:v1` | 32 bytes rkeySecret + 32 bytes anchorPublic |
| `lza` | `ssi:lza:<domain>:<base58(anchorPublic)>:v1` | 32 bytes anchorPublic |
| `event` | `ssi:event:<domain>:<base58(eventPayload)>:<base58(anchorSignature)>:v1` | Binary event payload + Ed25519 signature |

### Domain

- `domain` is a textual field in the SSI.
- The engine is initialized with a domain and only accepts SSIs from that domain.
- Domain cannot contain `:` characters.
- Domain does **not** participate in key derivation. It is part of the SSI and engine context only.

### Parsing Rules

1. Split by `:`.
2. Validate prefix is `ssi`.
3. Validate type is one of `lkey`, `rkey`, `lza`, `event`.
4. For `event`: expect 6 parts (ssi, event, domain, payload, signature, version).
5. For key types: expect 5 parts (ssi, type, domain, payload, version).
6. Decode Base58 payload and signature.
7. Invalid Base58 input is rejected with `ERR_INVALID_SSI`.
8. Validate version is `v1`.
9. Validate domain matches engine domain.

### SSI Capabilities

| SSI | Create DSU | Read Files | Write Files | Grant/Revoke | Verify Anchor | Derive Keys |
|-----|-----------|------------|-------------|--------------|---------------|-------------|
| lkey | Yes | Yes | Yes | Yes | Yes | Yes |
| rkey | No | Yes* | No | No | Yes | Derive lza |
| lza | No | No | No | No | Yes | No |

\* Read access is subject to access control evaluation.

### Implementation

- `src/ssi.js` — `parseSSI`, `makeLKeySSI`, `makeRKeySSI`, `makeLzaSSI`, `makeEventSSI`, `ensureVersion`, `ensureDomain`
- `src/crypto/base58.js` — `encode`, `decode`

## Decisions & Questions

### Question #1: Why Base58 instead of Base64?

**Response:** Base58 avoids visually ambiguous characters (0/O, I/l, +/) and is URL-safe without encoding. It is consistent with the OpenDSU convention and cryptocurrency address formats.

### Question #2: Why does rkey contain anchorPublic?

**Response:** The rkey must be able to compute anchorId (SHA256 of anchorPublic) for key derivation and to verify EventSSI signatures. Including anchorPublic in the rkey payload makes rkey self-contained for read-only operations.

## Conclusion

The SSI convention provides a compact, self-contained format for key material and event data. The hierarchical structure (lkey -> rkey -> lza) enforces capability-based access control.
