---
id: DS014
title: "DS014 — Retention and Garbage Collection"
order: 14
---

# DS014 — Retention and Garbage Collection

## Introduction

LightDSU supports configurable retention policies that determine how historical bricks are managed. Garbage collection removes unreferenced bricks based on the active retention mode.

## Core Content

### Retention Modes

| Mode | Value | Description |
|------|-------|-------------|
| `keep-all` | 0x0 | Retains all bricks; no deletion |
| `purge-obsolete` | 0x1 | Keeps only bricks referenced by the current BrickMap and active events |
| `retention-window` | 0x2 | Keeps bricks from the last N versions (default: 10) |
| `crypto-shred` | 0x3 | Same as purge-obsolete; future: cryptographic erasure of deleted data |

### Retention Mode Location

The retention mode is stored in the BrickMap manifest:

```
brickMap.manifest.retentionMode
```

### Policy Word Encoding

The retention mode is encoded in bits 8-11 of the policy word:

```
retentionMode = (policyWord >>> 8) & 0x0f
```

### Garbage Collection Algorithm

#### keep-all

1. Collect all referenced hashes:
   - All `brickMapHash` from VERSION_COMMIT events.
   - All `payloadHash` from events.
   - All brick hashes from the current BrickMap entries.
2. Do not remove any bricks.
3. Report: `removedBricks = 0`, `retainedBricks = total`, `referencedBricks = count`.

#### purge-obsolete

1. Collect referenced hashes:
   - Current BrickMap hash.
   - All brick hashes from current BrickMap entries.
   - All `payloadHash` from events.
2. Scan all bricks in storage.
3. Remove bricks not in the referenced set.
4. Report: `removedBricks`, `retainedBricks`, `referencedBricks`.

#### retention-window

1. Collect referenced hashes:
   - BrickMap hashes from the last N VERSION_COMMIT events (default N=10).
   - File bricks referenced by each retained historical BrickMap snapshot.
   - All `payloadHash` from events.
   - Current BrickMap and its file bricks.
2. Remove unreferenced bricks.
3. Report: `removedBricks`, `retainedBricks`, `referencedBricks`.

#### crypto-shred

Currently behaves identically to `purge-obsolete`. Future implementations may add cryptographic erasure (overwriting brick content before deletion).

### GC Report

```
{
  mode: string,
  removedBricks: number,
  retainedBricks: number,
  referencedBricks: number
}
```

### Explicit Invocation

Garbage collection is an explicit operation:

```js
dsu.runGarbageCollection() -> GCReport
```

It is not triggered automatically. This gives the operator full control over when storage is reclaimed. GC is a destructive maintenance operation and requires a writable `lkey` mount plus ADMIN access on the DSU root.

### Implementation

- `src/dsu.js` — `runGarbageCollection` method
- `src/constants.js` — `RETENTION_MODE`
- `src/storage.js` — `listBrickHashes`, `removeBrick`

## Decisions & Questions

### Question #1: Why is garbage collection explicit rather than automatic?

**Response:** Automatic GC could interfere with concurrent operations and would require careful synchronization. Explicit GC gives the operator control over timing and allows GC to run during maintenance windows. It also avoids the complexity of tracking brick references in real-time.

### Question #2: Why does keep-all not remove any bricks?

**Response:** The `keep-all` mode is designed for full auditability and historical reconstruction. All historical versions remain accessible. This mode is appropriate for regulated environments where data retention is mandatory.

## Conclusion

The retention and garbage collection system provides flexible storage management while maintaining data integrity. Operators can choose between full retention, version-window retention, or aggressive cleanup based on their requirements.
