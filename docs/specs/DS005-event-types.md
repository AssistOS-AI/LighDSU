---
id: DS005
title: "DS005 — Event Types"
order: 5
---

# DS005 — Event Types

## Introduction

LightDSU defines eight event types that cover the full lifecycle of a DSU: creation, versioning, access control, auditing, provenance, policy management, and key rotation.

## Core Content

### Event Type Constants

| Value | Name | Description |
|-------|------|-------------|
| 0x01 | GENESIS | First event of an anchor |
| 0x02 | VERSION_COMMIT | New DSU version published |
| 0x03 | GRANT | Access permission granted |
| 0x04 | REVOKE | Access permission revoked |
| 0x05 | ACCESS_LOG | Semantic access recorded |
| 0x06 | PROVENANCE | Provenance metadata attached |
| 0x07 | POLICY_UPDATE | DSU policy changed |
| 0x08 | KEY_EPOCH | Key epoch change (reserved for v1) |

### GENESIS (0x01)

The first event of every anchor.

**Required fields:**
- `anchorPublic` (flag 0x0400)

**Optional fields:**
- `policyWord` (flag 0x0020)
- `payloadHash` (flag 0x0002)

**Constraints:**
- `seq = 0`
- `prevEventHash = 32 zero bytes`
- `anchorId = SHA256(anchorPublic)`
- Anchor file: `anchors/<anchorId>.la`

### VERSION_COMMIT (0x02)

Publishes a new version of the DSU.

**Required fields:**
- `brickMapHash` (flag 0x0001) — hash of the encrypted BrickMap brick
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `payloadHash` (flag 0x0002)

The `brickMapHash` references the encrypted brick containing the complete BrickMap snapshot for this version.

### GRANT (0x03)

Grants permissions to a DID over a resource scope.

**Required fields:**
- `subjectHash` (flag 0x0004) — HMAC of the beneficiary DID
- `resourceHash` (flag 0x0008) — HMAC of the resource scope
- `permissions` (flag 0x0010) — permission bitmap
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `payloadHash` (flag 0x0002)
- `extension` (flag 0x0800) — contains scope JSON

The grant ID is the `eventHash` of the GRANT event.

### REVOKE (0x04)

Revokes previously granted permissions.

**Required fields:**
- `subjectHash` (flag 0x0004)
- `resourceHash` (flag 0x0008)
- `permissions` (flag 0x0010)
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `grantId` (flag 0x0080) — targets a specific grant
- `payloadHash` (flag 0x0002)
- `extension` (flag 0x0800)

If `grantId` is present, revocation targets that specific grant. If absent, revocation targets all active grants matching `subjectHash + resourceHash + permissions`.

### ACCESS_LOG (0x05)

Records semantic access when the DSU policy requires audit.

**Required fields:**
- `subjectHash` (flag 0x0004)
- `resourceHash` (flag 0x0008)
- `permissions` (flag 0x0010)
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `payloadHash` (flag 0x0002)
- `extension` (flag 0x0800)

Logged operations: `readFile`, `export`, `deriveDataset`, `runAnalysis`, `share`. Internal brick reads are not logged.

### PROVENANCE (0x06)

Attaches profile-based provenance metadata to a DSU version or virtual resource.

**Required fields:**
- `payloadHash` (flag 0x0002) — hash of encrypted provenance brick
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `resourceHash` (flag 0x0008)
- `extension` (flag 0x0800)

The full provenance object is stored as an encrypted payload brick following `ProvenancePayloadV1`.

### POLICY_UPDATE (0x07)

Updates the DSU policy.

**Required fields:**
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `policyWord` (flag 0x0020)
- `payloadHash` (flag 0x0002)
- `extension` (flag 0x0800)

### KEY_EPOCH (0x08)

Marks a key epoch change. Reserved for v1; used for controlled rotations and future re-encryption.

**Required fields:**
- `keyEpoch` (flag 0x0040)
- `actorHash` (flag 0x0100)
- `actorSignature` (flag 0x0200)

**Optional fields:**
- `payloadHash` (flag 0x0002)

### AnchorState Reduction

The anchor is reduced to an `AnchorState` object:

| Field | Type | Description |
|-------|------|-------------|
| `latestSeq` | number | Highest sequence number |
| `latestEventHash` | Buffer | Hash of the latest event |
| `latestBrickMapHash` | string (hex) | BrickMap hash from latest VERSION_COMMIT |
| `activeGrants` | Map | Currently valid grants |
| `revokedGrants` | Set | Revoked grant IDs |
| `policy` | u32 | Current policy word |
| `keyEpoch` | u32 | Current key epoch |

### Implementation

- `src/constants.js` — `EVENT_TYPES`
- `src/anchor.js` — `reduceAnchorState`
- `src/engine.js` — createDSU event emission
- `src/dsu.js` — event recording for all operations

## Decisions & Questions

### Question #1: Should POLICY_UPDATE always include policyWord?

**Response:** The specification lists `policyWord` as optional for POLICY_UPDATE. The implementation may set it when the policy word changes, but not all policy updates affect the policy word (e.g., provenance policy changes stored in the BrickMap manifest). The `extension` field can carry additional context about what policy aspect changed.

### Question #2: Why is KEY_EPOCH reserved for v1?

**Response:** Key rotation with re-encryption requires careful handling of historical brick decryption. v1 focuses on the core storage model; KEY_EPOCH provides the event type infrastructure for future key rotation implementations.

## Conclusion

The eight event types cover the complete DSU lifecycle. Each event type carries only the fields it needs, controlled by the flags bitmask, and all events are cryptographically chained and signed.
