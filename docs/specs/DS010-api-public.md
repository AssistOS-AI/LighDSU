---
id: DS010
title: "DS010 — Public API"
order: 10
---

# DS010 — Public API

## Introduction

This document specifies the complete public API of LightDSU v1, organized by component: Engine, Mounted DSU, Filesystem, Batch, Access, and Provenance.

## Core Content

### Engine API

#### `LightDSUEngine.open(config) -> engine`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config.storageRoot` | string | Yes | Root directory for DSU storage |
| `config.domain` | string | Yes | SSI domain (no `:` characters) |
| `config.didStrategy` | DIDStrategy | No | Defaults to `DefaultDidStrategy` |
| `config.currentDID` | string | No | Defaults to `"did:lightdsu:default"` |

Creates the storage layout if it does not exist.

#### `engine.createDSU() -> CreateDSUResult`

Returns:
```
{
  dsu: MountedLightDSU,
  lkeySSI: string,
  rkeySSI: string,
  lzaSSI: string,
  anchorId: string  // hex
}
```

Emits GENESIS, VERSION_COMMIT, and GRANT events.

#### `engine.loadDSU(keySSI) -> MountedLightDSU`

Parses the SSI, verifies domain, reads the anchor, verifies all events, and mounts the DSU.

#### `engine.parseSSI(serializedSSI) -> ParsedSSI`

Parses and validates an SSI string against the engine's domain.

#### `engine.setCurrentDID(did) -> void`

Updates the engine's current DID context.

#### `engine.close() -> void`

No-op in v1. Reserved for future resource cleanup.

### Mounted DSU

#### `dsu.readFile(path, options?) -> Buffer`

| Option | Type | Description |
|--------|------|-------------|
| `audit` | boolean | Force access logging |

Checks READ permission. Decrypts and reassembles chunks. Logs ACCESS_LOG if audit mode requires it.

#### `dsu.writeFile(path, data, options?) -> void`

| Option | Type | Description |
|--------|------|-------------|
| `mediaType` | string | MIME type |
| `metadata` | object | Custom metadata |
| `chunkSize` | number | Chunk size in bytes (default 256 KB) |

Checks WRITE permission. Generates fileKey, chunks data, encrypts each chunk as a brick, updates BrickMap. Auto-commits if not in batch mode.
If a concurrent VERSION_COMMIT wins the anchor race, the mount reloads the latest BrickMap snapshot, reapplies its local BrickMap changes, and retries the commit.

#### `dsu.appendToFile(path, data, options?) -> void`

Reads existing content, appends new data, writes as new file. Propagates decryption/hash errors (does not silently fallback).

#### `dsu.createFolder(path) -> void`

Checks WRITE permission. Creates folder and all parent folders.

#### `dsu.delete(path) -> void`

Checks DELETE permission. Removes entry and all children from BrickMap.

#### `dsu.rename(sourcePath, targetPath) -> void`

Checks WRITE permission. Moves entry recursively. Blocks overwrite and self-nesting.

#### `dsu.stat(path) -> StatResult`

Returns entry info: `path`, `type`, `size` (files), `createdAt`, `updatedAt`, `metadata`, `chunks` (files).

#### `dsu.readDir(path) -> DirEntry[]`

Checks LIST permission. Returns direct children: `{ name, path, type }`.

#### `dsu.listFiles(path) -> string[]`

Checks LIST permission. Returns file paths under the given folder.

#### `dsu.listFolders(path) -> string[]`

Checks LIST permission. Returns folder paths under the given folder.

### Batch API

#### `dsu.beginBatch() -> void`

Starts batch mode. Takes a snapshot of the current BrickMap.

#### `dsu.commitBatch() -> CommitResult`

Commits all changes as a single VERSION_COMMIT event. Returns `{ seq, brickMapHash, eventHash }`.

#### `dsu.cancelBatch() -> void`

Discards batch changes. Restores BrickMap from snapshot.

#### `dsu.hasUncommittedChanges() -> boolean`

Returns true if there are uncommitted modifications.

### Access API

#### `dsu.grantAccess(subjectDID, scope, permissions, options?) -> GrantResult`

| Option | Type | Description |
|--------|------|-------------|
| `payloadHash` | string | Optional payload hash hex |

Checks GRANT permission. Emits GRANT event. Returns `{ seq, grantId }`.
Malformed scopes are rejected with `ERR_INVALID_SCOPE`. Invalid permission masks are rejected with `ERR_INVALID_PERMISSION`.

#### `dsu.revokeAccess(subjectDID, scope, permissions, options?) -> RevokeResult`

| Option | Type | Description |
|--------|------|-------------|
| `grantId` | string | Target specific grant |

Checks REVOKE permission. Emits REVOKE event. Returns `{ seq }`.

#### `dsu.checkAccess(subjectDID, scope, permissions) -> AccessDecision`

Returns `{ allowed, reason }`.

#### `dsu.listAccess() -> AccessEntry[]`

Returns all active grants with their details.

### Provenance API

#### `dsu.appendProvenance(resource, provenanceInput, options?) -> ProvenanceResult`

| Option | Type | Description |
|--------|------|-------------|
| `attachToCommit` | boolean | Also commit a VERSION_COMMIT |

Checks PROVENANCE_APPEND permission. Validates the payload against the selected profile, encodes ProvenancePayloadV1, encrypts it as a brick, and emits a PROVENANCE event.

#### `dsu.getProvenance(query?) -> ProvenanceRecord[]`

| Query Field | Type | Description |
|-------------|------|-------------|
| `payloadHash` | string | Filter by payload hash |
| `resourceHash` | string | Filter by resource hash |
| `profileId` | number | Filter by profile |

Decodes all PROVENANCE events and their payload bricks. Undecodable payloads are surfaced as errors; they are not silently downgraded to a legacy format.

#### `dsu.getHistory(query?) -> HistoryRecord[]`

| Query Field | Type | Description |
|-------------|------|-------------|
| `eventType` | number | Filter by event type |

Returns summary of all events in the anchor.

#### `dsu.validateProvenance(resourceOrVersion, options?) -> ProvenanceValidationReport`

Three-level validation: cryptographic, structural, domain-specific.

#### `dsu.listProvenanceProfiles() -> ProvenanceProfileDescriptor[]`

Returns all registered provenance profiles.

#### `dsu.getProvenancePolicy() -> ProvenancePolicy`

Returns the current provenance policy from the BrickMap manifest.

#### `dsu.updateProvenancePolicy(policyUpdate, options?) -> PolicyUpdateResult`

Checks ADMIN permission. Updates the BrickMap manifest. Emits POLICY_UPDATE event.

### Utility Methods

#### `dsu.verifyAnchor() -> { valid, latestSeq, latestEventHash }`

Re-reads and verifies the anchor chain.

#### `dsu.getLatestEventHash() -> string`

Returns the hex event hash of the latest event.

#### `dsu.runGarbageCollection() -> GCReport`

Requires a writable `lkey` mount with ADMIN access. Removes unreferenced bricks based on retention mode. In `retention-window`, the collector preserves both retained historical BrickMap bricks and the file bricks referenced by those retained snapshots.

#### `dsu.exportState() -> { anchorId, mode, latestSeq }`

Returns a summary of the DSU state.

#### `dsu.setCurrentDID(did) -> void`

Updates the DID context for this mounted DSU.

### Implementation

- `src/engine.js` — Engine class
- `src/dsu.js` — MountedLightDSU class
- `src/index.js` — Public exports

## Decisions & Questions

### Question #1: Why don't filesystem methods accept a DID parameter?

**Response:** The engine model uses an implicit `currentDID` set at initialization. This simplifies the API and matches the typical single-actor-per-session pattern. DID appears explicitly only in access administration methods (`grantAccess`, `revokeAccess`, `checkAccess`).

## Conclusion

The public API provides a complete interface for DSU management, filesystem operations, access control, and provenance tracking. All methods enforce permission checks and maintain cryptographic integrity.
