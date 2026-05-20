---
id: DS007
title: "DS007 — Bricks"
order: 7
---

# DS007 — Bricks

## Introduction

Bricks are the fundamental storage unit in LightDSU. Each brick is an AES-256-GCM encrypted envelope identified by the SHA-256 hash of its contents. Bricks are content-addressed: the hash of the encrypted envelope is the brick's identifier.

## Core Content

### Brick Envelope Format

```
┌─────────────┬──────────────┬──────────┐
│ nonce (12)  │  ciphertext  │ tag (16) │
└─────────────┴──────────────┴──────────┘
```

| Component | Size | Description |
|-----------|------|-------------|
| nonce | 12 bytes | Random nonce for AES-256-GCM |
| ciphertext | variable | Encrypted plaintext |
| tag | 16 bytes | GCM authentication tag |

### Brick Hash

```
brickHash = SHA256(nonce || ciphertext || tag)
```

The hash is computed over the **entire envelope**, not just the ciphertext. This ensures that the brick identifier is bound to the specific encryption parameters.

### Encryption

```
AES-256-GCM(key, nonce, plaintext, aad)
```

| Context | Key | AAD |
|---------|-----|-----|
| File chunks | `fileKey` (per-file random 32 bytes) | `"<path>:<offset>"` |
| BrickMap | `brickMapKey` (derived from rkeySecret) | `"brickmap"` |
| Provenance | `brickMapKey` | `"provenance"` |

### Storage Layout

```
<bricksRoot>/
  <prefix>/
    <brickHash>.ldb
```

- `prefix` is the first 2 characters of the hex brick hash.
- Files have `.ldb` extension.
- Bricks are written atomically via `tmp/` directory.
- Duplicate bricks are not overwritten (idempotent writes).

### Brick Operations

| Operation | Description |
|-----------|-------------|
| `writeBrick(storageRoot, envelope)` | Writes envelope, returns hex hash |
| `readBrick(storageRoot, brickHashHex)` | Reads and verifies envelope |
| `listBrickHashes(storageRoot)` | Lists all brick hashes in storage |
| `removeBrick(storageRoot, brickHashHex)` | Removes a brick file |

### Verification

When reading a brick:
1. Read the file from disk.
2. Compute `SHA256(fileContents)`.
3. Compare with expected `brickHashHex`.
4. If mismatch, throw `ERR_BRICK_HASH_MISMATCH`.

### Chunking

Files are split into chunks for storage:
- Default chunk size: 256 KB (262,144 bytes).
- Each chunk is encrypted separately with the same `fileKey` but a different AAD.
- AAD for chunk: `"<normalizedPath>:<offset>"`.
- Empty files produce a single zero-length chunk.

### Implementation

- `src/storage.js` — `writeBrick`, `readBrick`, `listBrickHashes`, `removeBrick`
- `src/crypto/primitives.js` — `aes256gcmEncrypt`, `aes256gcmDecrypt`, `sha256`
- `src/dsu.js` — Chunking logic in `writeFile` and `readFile`

## Decisions & Questions

### Question #1: Why hash the entire envelope instead of just the ciphertext?

**Response:** Hashing the entire envelope (nonce + ciphertext + tag) ensures that the brick identifier is bound to the specific encryption. If only the ciphertext were hashed, the same plaintext encrypted with different nonces would produce the same hash, which could lead to confusion. The envelope hash uniquely identifies the encrypted object.

### Question #2: Why use AAD with path and offset?

**Response:** Including the path and offset in the AAD binds each chunk to its specific location in the filesystem. This prevents chunk replay attacks where a chunk from one file or position is substituted into another.

## Conclusion

Bricks provide a simple, secure, content-addressed storage layer. The envelope format ensures integrity and authenticity, while the hash-based addressing enables deduplication and efficient lookup.
