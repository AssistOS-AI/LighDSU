---
id: DS000
title: "DS000 — Vision"
order: 0
---

# DS000 — Vision

## Introduction

LightDSU is a local library for storing, versioning, auditing, and controlling access to encrypted DSUs (Data Security Units). The model is inspired by OpenDSU: a DSU is a data unit stored as encrypted bricks, and the BrickMap is the special brick that maintains the virtual file system structure, brick references, and symmetric keys needed for reconstruction.

LightDSU preserves these concepts and removes distributed components from the core. Version 1 implements local-only storage, compact SSIs, line-oriented local anchors, signed EventSSIs, encrypted BrickMap, and virtual filesystem APIs.

## Core Content

### Purpose

Provide a self-contained, cryptographically verifiable data storage layer that supports:

- **Encrypted brick storage**: All data is stored as AES-256-GCM encrypted, content-addressed bricks.
- **Hierarchical key management**: lkey (full control), rkey (read-only), lza (zero-access verification).
- **Append-only audit anchors**: Every mutation is recorded as a signed EventSSI in a line-oriented anchor file.
- **Virtual filesystem**: A BrickMap-based virtual file system with chunking, versioning, and access control.
- **Provenance profiles**: Structured provenance metadata mapped to external standards (W3C PROV, FHIR, GxP, RO-Crate, GA4GH, ISO 8000, OECD GLP, AI/ML).

### Design Principles

1. **Local-first**: No distributed consensus, no network dependencies. All state is local filesystem.
2. **Cryptographic integrity**: Every brick is content-addressed; every event is signed; every chain is verifiable.
3. **Separation of concerns**: Anchor (events) is separate from BrickMap (filesystem state) which is separate from bricks (data).
4. **Extensible provenance**: Profile-based provenance payloads stored as encrypted bricks, referenced compactly in the anchor.
5. **DID-pluggable**: The engine accepts any DID strategy implementation for actor signatures.

### Relationship to OpenDSU

| OpenDSU Concept | LightDSU v1 |
|-----------------|-------------|
| SeedSSI | lkey |
| SReadSSI | rkey |
| SzaSSI | lza |
| Anchor (distributed) | Local `.la` file |
| BrickMap (encrypted) | BrickMap (encrypted with brickMapKey) |
| Bricks (encrypted) | Bricks (encrypted with fileKey or brickMapKey) |
| KeySSI derivation | HKDF-SHA256 from lkeySecret |

### Scope Boundaries

**In scope for v1:**
- Local storage layout (anchors, bricks, tmp, locks)
- SSI family (lkey, rkey, lza, event)
- EventSSI encoding and verification
- BrickMap snapshot per version
- Filesystem API (read, write, append, folder, delete, rename, stat, list)
- Batch API (begin, commit, cancel)
- Access control (grant, revoke, check, list)
- Provenance API (append, get, validate, profiles, policy)
- Garbage collection (keep-all, purge-obsolete, retention-window, crypto-shred)

**Out of scope for v1:**
- Distributed anchors or consensus
- Network replication
- Key rotation with re-encryption (KEY_EPOCH is reserved)
- Incremental BrickMap diffs (snapshots only)

## Decisions & Questions

### Question #1: Should actorMessage use binary concatenation or canonical JSON?

**Response:** The specification describes actorMessage as binary concatenation (`eventType | seq | timestampMs | ...`), but the implementation uses canonical JSON. This decision was made for interoperability and debuggability. The canonical JSON approach is deterministic and easier to verify across implementations. This is documented as a deliberate deviation from the original spec wording.

### Question #2: Should createDSU emit a GRANT event automatically?

**Response:** Yes. The specification suggests "a GRANT immediately after GENESIS" as the cleaner approach for auditability. The implementation emits GENESIS, VERSION_COMMIT, and GRANT events during createDSU, granting the creator full administrative rights over the DSU root.

## Conclusion

LightDSU v1 provides a complete, self-contained local DSU engine with cryptographic integrity, hierarchical access control, and extensible provenance. It preserves the essential OpenDSU architecture while simplifying the operational model to local-only storage.
