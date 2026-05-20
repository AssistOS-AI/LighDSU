---
id: DS013
title: "DS013 — Error Codes"
order: 13
---

# DS013 — Error Codes

## Introduction

LightDSU uses a standardized set of error codes for all error conditions. Each error is a `LightDSUError` instance with a `code` property and a descriptive message.

## Core Content

### Error Codes

| Code | Description | Thrown By |
|------|-------------|-----------|
| `ERR_INVALID_SSI` | SSI format, type, or payload is invalid | SSI parsing, engine config |
| `ERR_INVALID_SCOPE` | Scope object is malformed or unsupported | Access API, GC authorization |
| `ERR_DOMAIN_MISMATCH` | SSI domain does not match engine domain | SSI validation, loadDSU |
| `ERR_UNSUPPORTED_VERSION` | SSI version is not v1 | SSI validation |
| `ERR_ANCHOR_NOT_FOUND` | Anchor file does not exist | Anchor reading |
| `ERR_EVENT_PARSE_FAILED` | Event payload cannot be decoded | Event decoding |
| `ERR_EVENT_SIGNATURE_INVALID` | Anchor or actor signature verification failed | Anchor verification |
| `ERR_EVENT_CHAIN_INVALID` | Event chain integrity check failed | Chain verification |
| `ERR_BRICK_NOT_FOUND` | Brick file does not exist | Brick reading |
| `ERR_BRICK_HASH_MISMATCH` | Brick content hash does not match filename | Brick verification |
| `ERR_DECRYPTION_FAILED` | AES-GCM decryption failed | Brick/BrickMap decryption |
| `ERR_ACCESS_DENIED` | Permission check failed | Access control |
| `ERR_READ_ONLY_DSU` | Operation not allowed on read-only mount | rkey/lza operations |
| `ERR_BATCH_ALREADY_STARTED` | beginBatch called while batch is active | Batch API |
| `ERR_NO_BATCH_IN_PROGRESS` | commitBatch/cancelBatch called without active batch | Batch API |
| `ERR_CONCURRENT_COMMIT` | Concurrent commit detected (anchor changed) | Anchor appending |
| `ERR_INVALID_PATH` | Path is invalid, escapes root, or entry not found | Filesystem API |
| `ERR_INVALID_PERMISSION` | Permission bitmap contains undefined bits | Access API |
| `ERR_INVALID_PROVENANCE_PROFILE` | Provenance payload, profile, or decoding is invalid | Provenance API |
| `ERR_PROVENANCE_VALIDATION_FAILED` | Provenance validation failed | validateProvenance |
| `ERR_UNSUPPORTED_PROFILE` | Profile ID is not recognized | Provenance API |

### Error Class

```js
class LightDSUError extends Error {
  constructor(code, message, details) {
    super(message || code);
    this.name = "LightDSUError";
    this.code = code;
    this.details = details;
  }
}
```

### Error Helper

```js
function throwError(code, message, details) {
  throw new LightDSUError(code, message, details);
}
```

### Error Handling Patterns

1. **Synchronous errors**: Thrown directly (e.g., SSI parsing, path validation).
2. **Asynchronous errors**: Rejected via Promise (e.g., file I/O, anchor verification).
3. **Retry errors**: `ERR_CONCURRENT_COMMIT` triggers automatic retry (up to 3 attempts). VERSION_COMMIT retries rebuild from the latest committed BrickMap before retrying.
4. **Non-retryable errors**: All other errors propagate immediately.

### Implementation

- `src/errors.js` — `ERROR_CODES`, `LightDSUError`, `throwError`

## Decisions & Questions

### Question #1: Why use string error codes instead of numeric codes?

**Response:** String codes are self-documenting, easier to debug, and do not require a separate error code registry. They are consistent with Node.js error conventions (e.g., `ENOENT`, `EEXIST`).

## Conclusion

The error code system provides clear, actionable error information for all failure modes. Each code maps to a specific condition, enabling precise error handling in client code.
