---
id: DS011
title: "DS011 — Provenance Extension"
order: 11
---

# DS011 — Provenance Extension

## Introduction

This document specifies the provenance profile system that extends LightDSU with structured, standards-compatible provenance metadata. Provenance payloads are stored as encrypted bricks and referenced compactly in the anchor via PROVENANCE events.

## Core Content

### ProvenancePayloadV1

The provenance payload binary format:

| Offset | Size | Field | Type |
|--------|------|-------|------|
| 0 | 1 | versionTag | u8 (always 0x01) |
| 1 | 1 | flags | u8 |
| 2 | 2 | profileId | u16 (big-endian) |
| 4 | 2 | profileVersion | u16 (big-endian) |
| 6 | 1 | payloadFormat | u8 |
| 7 | 6 | createdAt | u48 (big-endian, ms) |
| 13 | 32 | resourceHash | bytes32 (if flags bit 0) |
| 13+ | N | versionSeq | uvarint (if flags bit 1) |
| — | 32 | canonicalPayloadHash | bytes32 |
| — | N | canonicalPayloadLen | uvarint |
| — | N | canonicalPayload | bytes |
| — | N | externalReferences | list (if flags bit 2) |

#### Flags

| Bit | Meaning |
|-----|---------|
| 0 | hasResourceHash |
| 1 | hasVersionSeq |
| 2 | hasExternalRefs |

#### External Reference Entry

Each entry:
- `typeLen` (uvarint) + `type` (bytes)
- `refLen` (uvarint) + `ref` (bytes)
- `hashLen` (uvarint) + `hash` (bytes, 0 = absent)

### Double-Hash Invariant

1. `canonicalPayloadHash = SHA256(canonicalPayload)` — inner integrity check after decryption.
2. `payloadHash = SHA256(encryptedBrickEnvelope)` — outer integrity check for the stored brick.

### Payload Formats

| Value | Name | Description |
|-------|------|-------------|
| 0x01 | CBOR | Canonical CBOR |
| 0x02 | CANONICAL_JSON | Canonical JSON |
| 0x03 | JSON_LD | JSON-LD |
| 0x04 | RDF_TURTLE | RDF/Turtle |
| 0x05 | FHIR_JSON | FHIR JSON |
| 0x06 | BINARY | Binary profile-specific |

### Profile Registry

| ID | Name | Standard Reference |
|----|------|-------------------|
| 0x0001 | LIGHTDSU_MINIMAL | Native LightDSU |
| 0x0002 | W3C_PROV | W3C PROV-O |
| 0x0003 | FHIR_PROVENANCE | HL7 FHIR Provenance |
| 0x0004 | FHIR_AUDIT_EVENT | HL7 FHIR AuditEvent |
| 0x0005 | GXP_AUDIT_TRAIL | FDA 21 CFR Part 11 / EU GMP Annex 11 |
| 0x0006 | RO_CRATE | RO-Crate 1.2 |
| 0x0007 | GA4GH_DATA_USE | GA4GH DUO |
| 0x0008 | ISO_8000_PROVENANCE | ISO 8000-120 |
| 0x0009 | OECD_GLP_DATA_INTEGRITY | OECD GLP Data Integrity |
| 0x000A | AI_ML_EXPERIMENT | Native LightDSU |

### Profile: LIGHTDSU_MINIMAL (0x0001)

**Required fields in canonicalPayload:**
- `eventKind` — one of: CREATE, UPDATE, DELETE, IMPORT, EXPORT, TRANSFORM, ANALYZE, DERIVE, SHARE, REVIEW, APPROVE, REJECT
- `operation` — semantic operation description
- `actorHash` — DID reference
- `timestampMs` — timestamp
- `method` — method or pipeline name
- `softwareAgent` — software identifier
- `softwareVersion` — version string

**Optional fields:**
- `resourceHash`, `versionSeq`, `inputHashes`, `outputHashes`, `reason`, `previousVersion`, `newVersion`, `relatedPayloads`

### Profile: W3C_PROV (0x0002)

**Required fields:** `entity`, `activity`, `agent`
**Optional fields:** `wasGeneratedBy`, `used`, `wasAssociatedWith`, `wasRevisionOf`, `startedAtTime`, `endedAtTime`
**Payload formats:** JSON-LD, RDF/Turtle, CANONICAL_JSON

### Profile: FHIR_PROVENANCE (0x0003)

**Required fields:** `resourceType` (must be "Provenance"), `target`, `recorded`, `agent`
**Optional fields:** `activity`, `entity`, `reason`, `signature`
**Payload formats:** FHIR_JSON

### Profile: FHIR_AUDIT_EVENT (0x0004)

**Required fields:** `resourceType` (must be "AuditEvent"), `type`, `recorded`, `agent`, `source`
**Optional fields:** `action`, `outcome`, `outcomeDesc`, `purposeOfEvent`, `entity`
**Payload formats:** FHIR_JSON

### Profile: GXP_AUDIT_TRAIL (0x0005)

**Required fields:** `regulatedRecordType`, `operation`, `actorHash`, `timestampMs`, `resourceHash`, `changeReason`, `systemId`, `systemVersion`, `reviewStatus`, `retentionClass`
**Optional fields:** `validationContext`, `previousValueHash`, `newValueHash`, `electronicSignatureMeaning`, `reviewedBy`, `reviewTimestamp`
**Special rule:** `changeReason` is required for UPDATE and DELETE operations.

### Profile: RO_CRATE (0x0006)

**Required fields:** `roCrateVersion`, `rootDatasetId`, `metadataJsonLd`
**Special rule:** `metadataJsonLd` must contain `@context` and `@graph`.
**Payload formats:** JSON-LD, CANONICAL_JSON

### Profile: GA4GH_DATA_USE (0x0007)

**Required fields:** `datasetId`, `duoTerms`, `permittedUses`, `prohibitedUses`, `policyVersion`
**Special rule:** `duoTerms`, `permittedUses`, `prohibitedUses` must be arrays.

### Profile: ISO_8000_PROVENANCE (0x0008)

**Required fields:** `masterDataObjectId`, `characteristicId`, `characteristicValueHash`, `source`, `acquisitionMethod`, `responsibleParty`, `timestampMs`, `qualityStatus`, `validationStatus`

### Profile: OECD_GLP_DATA_INTEGRITY (0x0009)

**Required fields:** `studyId`, `studyPhase`, `rawDataReference`, `metadataCompleteness`, `acquisitionSystem`, `processingStep`, `operator`, `timestampMs`, `dataCriticality`, `dataLifecycleStage`, `integrityAssessment`

### Profile: AI_ML_EXPERIMENT (0x000A)

**Required fields:** `experimentId`, `runId`, `task`, `datasetHashes`, `parametersHash`, `softwareEnvironment`, `outputHashes`
**Optional fields:** `featureSetHash`, `modelId`, `modelVersion`, `promptHash`, `codeHash`, `containerHash`, `metrics`, `evaluator`, `randomSeed`, `hardwareContext`
**Special rule:** `datasetHashes` and `outputHashes` must be arrays.

### Validation Levels

| Level | Checks |
|-------|--------|
| 1 — Cryptographic | payloadHash matches brick, brick decrypts, canonicalPayloadHash matches decrypted payload, EventSSI signature valid, chain valid |
| 2 — Structural | profileId recognized, profileVersion supported, payloadFormat accepted, required fields present, field types valid |
| 3 — Domain | Profile-specific rules (e.g., GxP changeReason for UPDATE/DELETE, FHIR resourceType, RO-Crate @context/@graph) |

`appendProvenance()` runs the profile validation pipeline before persisting a provenance brick. Invalid payloads are rejected with `ERR_INVALID_PROVENANCE_PROFILE` instead of being stored for later cleanup.

### Provenance Policy

Stored in the BrickMap manifest:

```
manifest.provenancePolicy
  requiredProfiles: number[]
  operationProfileMap: { operationName: number[] }
  regulatedMode: { gxp, glp, healthcare }
  minimumPayloadFields: { profileId: string[] }
  auditMode: string
```

For v1, `manifest.provenancePolicy.auditMode` is descriptive policy data. Runtime read-audit behavior is still driven by explicit `readFile({ audit: true })` calls and by the anchor `policyWord` when one is present.

### Implementation

- `src/provenancePayloadCodec.js` — `encodeProvenancePayload`, `decodeProvenancePayload`, `buildProvenancePayloadV1`
- `src/provenanceProfiles.js` — Profile registry, validators, `validateStructural`
- `src/dsu.js` — `appendProvenance`, `getProvenance`, `validateProvenance`, `listProvenanceProfiles`, `getProvenancePolicy`, `updateProvenancePolicy`

## Decisions & Questions

### Question #1: Why store provenance in encrypted bricks instead of inline in the anchor?

**Response:** Keeping the anchor compact is essential for performance and inspectability. Provenance payloads can be large (especially FHIR, RO-Crate, or AI/ML profiles). Storing them as encrypted bricks maintains the anchor's line-oriented simplicity while supporting arbitrarily large provenance metadata.

### Question #2: Why two levels of hashing (canonicalPayloadHash + payloadHash)?

**Response:** `payloadHash` verifies the integrity of the stored encrypted brick (storage layer). `canonicalPayloadHash` verifies the integrity of the decrypted semantic content (application layer). This separation allows detection of corruption at either layer.

### Question #3: Why reject malformed provenance during append instead of only during validation?

**Response:** Provenance is an audit surface, so storing known-invalid payloads weakens the contract and creates avoidable cleanup work. v1 now validates structural and domain rules before writing the provenance brick, while `validateProvenance()` remains useful for re-checking already stored records and detecting post-write corruption.

## Conclusion

The provenance extension provides a flexible, standards-compatible system for attaching verifiable provenance metadata to DSU versions and resources. The profile-based architecture supports domain-specific requirements while maintaining a common binary encoding and validation framework.
