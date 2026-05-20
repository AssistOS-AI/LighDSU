---
id: DS006
title: "DS006 — BrickMap"
order: 6
---

# DS006 — BrickMap

## Introduction

The BrickMap is the central data structure that maintains the virtual filesystem of a DSU. It is stored as an encrypted brick and contains the directory tree, file metadata, chunk references, and file encryption keys.

## Core Content

### Encryption

The BrickMap is encrypted with `brickMapKey`:

```
brickMapKey = HKDF(rkeySecret, anchorId, "brickmap", 32)
```

### Logical Structure

```
BrickMap
  seq: number
  manifest: {
    retentionMode: string
    createdAt: number
    updatedAt: number
    provenancePolicy: {
      requiredProfiles: number[]
      operationProfileMap: object
      regulatedMode: { gxp, glp, healthcare }
      minimumPayloadFields: object
      auditMode: string
    }
  }
  metadata: object
  entries: {
    "<path>": Entry
  }
```

### Entry Types

#### Folder Entry

```
{
  type: "folder",
  createdAt: number,    // timestampMs
  updatedAt: number,    // timestampMs
  metadata: object
}
```

#### File Entry

```
{
  type: "file",
  size: number,          // plain size in bytes
  createdAt: number,
  updatedAt: number,
  mediaType: string,
  fileKey: string,       // Base58-encoded 32-byte key
  chunks: [Chunk],
  metadata: object
}
```

#### Chunk

```
{
  brickHash: string,     // hex SHA-256 of the brick envelope
  offset: number,        // offset in the plain file
  plainSize: number,     // size of the plain chunk
  cipherSize: number,    // size of the encrypted envelope
  nonce: string          // hex nonce for this chunk
}
```

### Serialization

- **Serialize**: Canonical JSON (sorted keys) → Buffer
- **Deserialize**: Buffer → JSON.parse

Canonical JSON ensures deterministic serialization for encryption and hashing.
`manifest.updatedAt` is refreshed on each committed BrickMap snapshot, and `seq` is incremented before the snapshot is encrypted and stored.

### Operations

| Operation | Description |
|-----------|-------------|
| `createEmptyBrickMap()` | Creates initial BrickMap with root folder |
| `ensureFolder(brickMap, path)` | Creates folder and all parent folders |
| `setFileEntry(brickMap, path, data)` | Sets or updates a file entry |
| `getFileEntry(brickMap, path)` | Retrieves a file entry |
| `statEntry(brickMap, path)` | Returns stat info for any entry |
| `deleteEntry(brickMap, path)` | Removes entry and all children |
| `renameEntry(brickMap, src, dst)` | Moves entry (recursive for folders) |
| `listEntries(brickMap, folderPath)` | Lists direct children of a folder |
| `listByType(brickMap, folderPath, type)` | Lists children filtered by type |
| `decodeFileKey(entry)` | Decodes Base58 fileKey to Buffer |

### Versioning

For v1, each VERSION_COMMIT references a **complete BrickMap snapshot**. There are no incremental diffs. This simplifies reconstruction and testing.

When a VERSION_COMMIT races with another writer, the retrying mount reloads the latest committed BrickMap and replays its local BrickMap diff onto that snapshot before retrying. Disjoint path changes are preserved; overlapping path edits resolve to the retrying mount's current working copy.

### FileKey Storage

The `fileKey` is stored **inside** the encrypted BrickMap, encoded as Base58. This means:
- Anyone who can decrypt the BrickMap can access file keys.
- lkey and rkey holders can decrypt the BrickMap.
- lza holders cannot decrypt the BrickMap and therefore cannot access file keys.

### Implementation

- `src/brickmap.js` — All BrickMap operations
- `src/utils.js` — `canonicalJSONStringify`, `normalizePath`, `dirnameSafe`
- `src/dsu.js` — `decryptBrickMap` static method

## Decisions & Questions

### Question #1: Why store fileKey in the BrickMap instead of per-brick?

**Response:** Storing the fileKey in the BrickMap follows the OpenDSU model where the BrickMap holds the keys for referenced bricks. This allows a single fileKey to encrypt all chunks of a file, simplifying key management. Per-brick keys would require storing the key in each brick's metadata or a separate key index.

### Question #2: Why complete snapshots instead of incremental diffs?

**Response:** Complete snapshots simplify reconstruction, versioning, and testing. Incremental diffs would require a merge algorithm and would complicate the BrickMap format. For v1, the simplicity of snapshots is preferred. Incremental BrickMap updates can be introduced in a future version without changing the anchor model.

### Question #3: How are concurrent BrickMap commits resolved?

**Response:** v1 still stores full snapshots, but it no longer retries blindly on stale state. On concurrent VERSION_COMMIT conflicts, the retrying mount reloads the latest committed snapshot and reapplies its local BrickMap changes before emitting a new VERSION_COMMIT. This preserves independent path changes while keeping the implementation smaller than a full operational-transform or diff-based merge engine.

## Conclusion

The BrickMap is the heart of the LightDSU virtual filesystem. Its encrypted, snapshot-based design ensures that every version of the DSU is fully reconstructible from the anchor chain and brick storage.
