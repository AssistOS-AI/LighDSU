# LightDSU v1 — specificație tehnică (self-contained)

## 1. Scop

LightDSU este o librărie locală pentru stocare/versionare/audit/access-control pentru DSU-uri criptate, inspirată din OpenDSU:
- DSU = unitate de date segmentată în bricks criptate.
- BrickMap = snapshot criptat al sistemului virtual de fișiere + referințe chunks/keys.
- Anchor = lanț append-only de `ssi:event` semnate, stocat local.

v1 implementează strict local:
- storage local (`anchors`, `bricks`, `tmp`, `locks`)
- SSI compacte (`lkey`, `rkey`, `lza`, `event`)
- EventSSI semnate cu Ed25519
- BrickMap criptat AES-256-GCM
- API filesystem + batch + access + provenance

## 2. Convenție SSI

- `ssi:lkey:<domain>:<base58(lkeySecret)>:v1`
- `ssi:rkey:<domain>:<base58(rkeySecret|anchorPublic)>:v1`
- `ssi:lza:<domain>:<base58(anchorPublic)>:v1`
- `ssi:event:<domain>:<base58(eventPayload)>:<base58(anchorSignature)>:v1`

Engine:

```js
LightDSUEngine.open({
  storageRoot,
  domain,
  didStrategy,
  currentDID
});
```

## 3. Derivări criptografice

- `anchorSigningSeed = HKDF(lkeySecret, empty, "anchor-signing", 32)`
- `rkeySecret = HKDF(lkeySecret, empty, "read-key", 32)`
- `anchorPrivate, anchorPublic = Ed25519.fromSeed(anchorSigningSeed)`
- `anchorId = SHA256(anchorPublic)`
- `brickMapKey = HKDF(rkeySecret, anchorId, "brickmap", 32)`
- `accessIndexKey = HKDF(rkeySecret, anchorId, "access-index", 32)`

Suite v1:
- SHA-256
- HKDF-SHA256
- HMAC-SHA256
- Ed25519
- AES-256-GCM
- Base58 pentru payload-uri SSI

## 4. EventSSI payload

Header:
- `u8 eventType`
- `u16 flags`
- `uvarint seq`
- `u48 timestampMs`
- `bytes32 prevEventHash`

Câmpuri opționale (ordonate fix prin flags):
- `brickMapHash`, `payloadHash`, `subjectHash`, `resourceHash`, `permissions`, `policyWord`,
  `keyEpoch`, `grantId`, `actorHash`, `actorSignature`, `anchorPublic`, `extension`

Semnături:
- `anchorSignature = Ed25519.sign(anchorPrivate, eventPayload)`
- `eventHash = SHA256(eventPayload | anchorSignature)`

## 5. Tipuri de eveniment

- `GENESIS`
- `VERSION_COMMIT`
- `GRANT`
- `REVOKE`
- `ACCESS_LOG`
- `PROVENANCE`
- `POLICY_UPDATE`
- `KEY_EPOCH`

## 6. AnchorState redus

- `latestSeq`
- `latestEventHash`
- `latestBrickMapHash`
- `activeGrants`
- `revokedGrants`
- `policy`
- `keyEpoch`

## 7. API public

### Engine
- `open`
- `createDSU`
- `loadDSU`
- `parseSSI`
- `setCurrentDID`
- `close`

### Mounted DSU
- filesystem: `readFile`, `writeFile`, `appendToFile`, `createFolder`, `delete`, `rename`, `stat`, `readDir`, `listFiles`, `listFolders`
- batch: `beginBatch`, `commitBatch`, `cancelBatch`, `hasUncommittedChanges`
- access: `grantAccess`, `revokeAccess`, `checkAccess`, `listAccess`
- provenance/history: `appendProvenance`, `getProvenance`, `getHistory`
- actor context: `setCurrentDID`, `verifyAnchor`, `getLatestEventHash`

## 8. Reguli operaționale

- `lkey`: control complet (scriere, commit, grant/revoke, citire, verificare)
- `rkey`: read-only (decriptare BrickMap + citire, fără evenimente de scriere)
- `lza`: verificare ancoră și inspecție structurală, fără acces la conținut

## 9. Erori standard

- `ERR_INVALID_SSI`
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

## 10. Decizii de securitate operațională (implementate)

- `ADMIN` respectă scope-ul grantului (nu este global implicit).
- `grantId` este unic per grant (`eventHash`), iar `REVOKE` fără `grantId` operează pe tuple active.
- `REVOKE` cu `grantId` validează dreptul de revocare pe scope-ul grantului țintit.
- Operațiile FS validează strict existența/tipul path-urilor.
- Verificarea ancorei include semnături actor + anchor și consistența lanțului (`seq`, `prevEventHash`).

---

## Provenance Profiles Extension

### ProvenancePayloadV1

Every provenance event stores an encrypted `ProvenancePayloadV1` brick. The outer struct carries:

| Field | Type | Description |
|-------|------|-------------|
| `profileId` | u16 | One of the 10 defined profile IDs |
| `profileVersion` | u16 | Profile version supported by this payload |
| `payloadFormat` | u8 | 0x01 CBOR / 0x02 JSON / 0x03 JSON-LD / 0x04 RDF/Turtle / 0x05 FHIR JSON / 0x06 binary |
| `createdAt` | u48 ms | Timestamp |
| `resourceHash` | bytes32? | Optional — HMAC of the referenced resource |
| `versionSeq` | uvarint? | Optional DSU version number |
| `canonicalPayloadHash` | bytes32 | SHA-256 of the raw `canonicalPayload` (inner integrity check) |
| `canonicalPayload` | bytes | Profile-specific data |
| `externalReferences` | list? | `{ type, ref, hash }` entries for external artefacts |

Double-hash invariant: `canonicalPayloadHash = SHA256(canonicalPayload)` and the EventSSI `payloadHash = SHA256(encryptedBrickEnvelope)`.

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

### New DSU APIs

```js
// Append provenance (profile-aware)
dsu.appendProvenance(resource, {
  profileId,           // PROVENANCE_PROFILES constant
  profileVersion?,     // defaults to profile.version
  payloadFormat?,      // defaults to profile.payloadFormats[0]
  canonicalPayload,    // Buffer or JSON-serialisable object
  externalReferences?, // [{ type, ref, hash }]
  versionSeq?
}) -> { seq, payloadHash, canonicalPayloadHash, profileId, profileName }

// Retrieve and decode provenance records
dsu.getProvenance({ payloadHash?, resourceHash?, profileId? }) -> ProvenanceRecord[]

// 3-level validation: cryptographic → structural → domain
dsu.validateProvenance(query?, options?) -> ProvenanceValidationReport

// Enumerate supported profiles
dsu.listProvenanceProfiles() -> ProvenanceProfileDescriptor[]

// Policy management
dsu.getProvenancePolicy() -> ProvenancePolicy
dsu.updateProvenancePolicy(policyUpdate, options?) -> { seq, policy }
```

### Manifest provenancePolicy

```json
{
  "requiredProfiles": [],
  "operationProfileMap": {},
  "regulatedMode": { "gxp": false, "glp": false, "healthcare": false },
  "minimumPayloadFields": {},
  "auditMode": "no-read-audit"
}
```
