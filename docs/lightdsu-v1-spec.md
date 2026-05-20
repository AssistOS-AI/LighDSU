# LightDSU v1 — Consolidated Technical Summary

This document is a compact, self-contained summary of LightDSU v1. The authoritative contract remains the DS specification set in `docs/specs/`.

## 1. Scope

LightDSU is a local library for storing, versioning, auditing, and controlling access to encrypted DSUs inspired by OpenDSU:

- A **DSU** is a data unit segmented into encrypted bricks.
- The **BrickMap** is an encrypted snapshot of the virtual filesystem, including file metadata, chunk references, and file keys.
- The **anchor** is a local append-only chain of signed `ssi:event` lines.

Version 1 is intentionally local-only and includes:

- local storage layout (`anchors`, `bricks`, `tmp`, `locks`)
- compact SSI family (`lkey`, `rkey`, `lza`, `event`)
- Ed25519-signed EventSSI records
- AES-256-GCM encrypted BrickMap and data bricks
- filesystem, batch, access-control, provenance, and garbage-collection APIs

## 2. SSI Convention

- `ssi:lkey:<domain>:<base58(lkeySecret)>:v1`
- `ssi:rkey:<domain>:<base58(rkeySecret|anchorPublic)>:v1`
- `ssi:lza:<domain>:<base58(anchorPublic)>:v1`
- `ssi:event:<domain>:<base58(eventPayload)>:<base58(anchorSignature)>:v1`

Engine initialization:

```js
LightDSUEngine.open({
  storageRoot,
  domain,
  didStrategy,
  currentDID
});
```

## 3. Cryptographic Derivations

- `anchorSigningSeed = HKDF(lkeySecret, empty, "anchor-signing", 32)`
- `rkeySecret = HKDF(lkeySecret, empty, "read-key", 32)`
- `anchorPrivate, anchorPublic = Ed25519.fromSeed(anchorSigningSeed)`
- `anchorId = SHA256(anchorPublic)`
- `brickMapKey = HKDF(rkeySecret, anchorId, "brickmap", 32)`
- `accessIndexKey = HKDF(rkeySecret, anchorId, "access-index", 32)`

Fixed v1 suite:

- SHA-256
- HKDF-SHA256
- HMAC-SHA256
- Ed25519
- AES-256-GCM
- Base58

## 4. EventSSI Payload

Header:

- `u8 eventType`
- `u16 flags`
- `uvarint seq`
- `u48 timestampMs`
- `bytes32 prevEventHash`

Optional fields in fixed order:

- `brickMapHash`, `payloadHash`, `subjectHash`, `resourceHash`, `permissions`, `policyWord`
- `keyEpoch`, `grantId`, `actorHash`, `actorSignature`, `anchorPublic`, `extension`

Signatures and hashes:

- `anchorSignature = Ed25519.sign(anchorPrivate, eventPayload)`
- `eventHash = SHA256(eventPayload | anchorSignature)`

## 5. Event Types

- `GENESIS`
- `VERSION_COMMIT`
- `GRANT`
- `REVOKE`
- `ACCESS_LOG`
- `PROVENANCE`
- `POLICY_UPDATE`
- `KEY_EPOCH`

## 6. Reduced AnchorState

- `latestSeq`
- `latestEventHash`
- `latestBrickMapHash`
- `activeGrants`
- `revokedGrants`
- `policy`
- `keyEpoch`

## 7. Public API

### Engine

- `open`
- `createDSU`
- `loadDSU`
- `parseSSI`
- `setCurrentDID`
- `close`

### Mounted DSU

- Filesystem: `readFile`, `writeFile`, `appendToFile`, `createFolder`, `delete`, `rename`, `stat`, `readDir`, `listFiles`, `listFolders`
- Batch: `beginBatch`, `commitBatch`, `cancelBatch`, `hasUncommittedChanges`
- Access: `grantAccess`, `revokeAccess`, `checkAccess`, `listAccess`
- Provenance/history: `appendProvenance`, `getProvenance`, `getHistory`, `validateProvenance`, `listProvenanceProfiles`, `getProvenancePolicy`, `updateProvenancePolicy`
- Runtime utilities: `setCurrentDID`, `verifyAnchor`, `getLatestEventHash`, `runGarbageCollection`

## 8. Operational Rules

- `lkey`: full control (write, commit, grant/revoke, read, verify)
- `rkey`: read-only (decrypt BrickMap, read content if access grants allow it, verify)
- `lza`: anchor verification and structural inspection only
- Concurrent VERSION_COMMIT retries rebuild from the latest committed BrickMap snapshot before retrying
- Garbage collection requires a writable `lkey` mount and ADMIN access
- Invalid scope objects are rejected explicitly; they are never coerced into broader DSU scope

## 9. Standard Errors

- `ERR_INVALID_SSI`
- `ERR_INVALID_SCOPE`
- `ERR_DOMAIN_MISMATCH`
- `ERR_UNSUPPORTED_VERSION`
- `ERR_ANCHOR_NOT_FOUND`
- `ERR_EVENT_PARSE_FAILED`
- `ERR_EVENT_SIGNATURE_INVALID`
- `ERR_EVENT_CHAIN_INVALID`
- `ERR_BRICK_NOT_FOUND`
- `ERR_BRICK_HASH_MISMATCH`
- `ERR_DECRYPTION_FAILED`
- `ERR_ACCESS_DENIED`
- `ERR_READ_ONLY_DSU`
- `ERR_BATCH_ALREADY_STARTED`
- `ERR_NO_BATCH_IN_PROGRESS`
- `ERR_CONCURRENT_COMMIT`
- `ERR_INVALID_PATH`
- `ERR_INVALID_PERMISSION`
- `ERR_INVALID_PROVENANCE_PROFILE`
- `ERR_PROVENANCE_VALIDATION_FAILED`
- `ERR_UNSUPPORTED_PROFILE`

## 10. Security and Integrity Decisions

- `ADMIN` remains scope-bound; it does not bypass grant scope globally.
- `grantId` is the GRANT event hash, and revoke-by-grantId authorizes against the target grant scope.
- Filesystem operations validate paths and entry types strictly.
- Anchor verification includes actor signatures, anchor signatures, sequence continuity, and previous-event hash continuity.
- Provenance payloads are validated before persistence and decoded strictly on read.
- Retention-window GC preserves the file bricks referenced by retained historical BrickMaps.

---

## Provenance Profiles Extension

### ProvenancePayloadV1

Each provenance event stores an encrypted `ProvenancePayloadV1` brick with:

| Field | Type | Description |
|-------|------|-------------|
| `profileId` | u16 | One of the defined profile IDs |
| `profileVersion` | u16 | Supported profile version |
| `payloadFormat` | u8 | 0x01 CBOR / 0x02 JSON / 0x03 JSON-LD / 0x04 RDF/Turtle / 0x05 FHIR JSON / 0x06 binary |
| `createdAt` | u48 ms | Timestamp |
| `resourceHash` | bytes32? | Optional referenced resource hash |
| `versionSeq` | uvarint? | Optional DSU version sequence |
| `canonicalPayloadHash` | bytes32 | SHA-256 of canonical payload bytes |
| `canonicalPayload` | bytes | Profile-specific data |
| `externalReferences` | list? | `{ type, ref, hash }` entries |

Double-hash invariant:

- `canonicalPayloadHash = SHA256(canonicalPayload)`
- Event `payloadHash = SHA256(encryptedBrickEnvelope)`

### Profile IDs

| ID | Name | Standard |
|----|------|---------|
| 0x0001 | LIGHTDSU_MINIMAL | Native LightDSU minimal audit |
| 0x0002 | W3C_PROV | W3C PROV-O |
| 0x0003 | FHIR_PROVENANCE | HL7 FHIR Provenance |
| 0x0004 | FHIR_AUDIT_EVENT | HL7 FHIR AuditEvent |
| 0x0005 | GXP_AUDIT_TRAIL | FDA 21 CFR Part 11 / EU GMP Annex 11 |
| 0x0006 | RO_CRATE | RO-Crate 1.2 |
| 0x0007 | GA4GH_DATA_USE | GA4GH DUO |
| 0x0008 | ISO_8000_PROVENANCE | ISO 8000-120 master data provenance |
| 0x0009 | OECD_GLP_DATA_INTEGRITY | OECD GLP Data Integrity |
| 0x000A | AI_ML_EXPERIMENT | Native LightDSU ML experiment provenance |

### Provenance APIs

```js
dsu.appendProvenance(resource, {
  profileId,
  profileVersion?,
  payloadFormat?,
  canonicalPayload,
  externalReferences?,
  versionSeq?
}) -> { seq, payloadHash, canonicalPayloadHash, profileId, profileName }

dsu.getProvenance({ payloadHash?, resourceHash?, profileId? }) -> ProvenanceRecord[]
dsu.validateProvenance(query?, options?) -> ProvenanceValidationReport
dsu.listProvenanceProfiles() -> ProvenanceProfileDescriptor[]
dsu.getProvenancePolicy() -> ProvenancePolicy
dsu.updateProvenancePolicy(policyUpdate, options?) -> { seq, policy }
```

`appendProvenance()` validates structural and domain rules before persisting a provenance record.

### Manifest `provenancePolicy`

```json
{
  "requiredProfiles": [],
  "operationProfileMap": {},
  "regulatedMode": { "gxp": false, "glp": false, "healthcare": false },
  "minimumPayloadFields": {},
  "auditMode": "no-read-audit"
}
```

In v1, this `auditMode` field is descriptive policy metadata. Runtime read-audit behavior still depends on explicit `readFile({ audit: true })` calls or an anchor `policyWord` set by the implementation.
