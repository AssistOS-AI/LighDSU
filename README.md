# LightDSU v1

LightDSU is a local library for encrypted DSUs (Data Security Units) with:

- **KeySSI family**: `lkey`, `rkey`, `lza`
- **Local append-only anchors**: line-oriented `ssi:event` chains
- **Encrypted BrickMap snapshots**: complete virtual filesystem state per version
- **Encrypted bricks**: content-addressed AES-256-GCM envelopes
- **Access, audit, and provenance**: recorded through EventSSI

The DS specifications in `docs/specs/` are the authoritative contract set. The consolidated summary is available at [`docs/lightdsu-v1-spec.md`](docs/lightdsu-v1-spec.md), and the hardening review is available at [`docs/security-review.md`](docs/security-review.md).

## Install

```bash
npm install
```

## Run tests

```bash
npm test
```

## Local storage layout

```text
<storageRoot>/
  anchors/
    <anchorId>.la
  bricks/
    <prefix>/
      <brickHash>.ldb
  tmp/
  locks/
```

## SSI convention

- `ssi:lkey:<domain>:<payloadB58>:v1`
- `ssi:rkey:<domain>:<payloadB58>:v1`
- `ssi:lza:<domain>:<payloadB58>:v1`
- `ssi:event:<domain>:<payloadB58>:<signatureB58>:v1`

## Public API

```js
const { LightDSUEngine, DefaultDidStrategy } = require("lighdsu");

const engine = await LightDSUEngine.open({
  storageRoot: "/tmp/lightdsu-demo",
  domain: "local",
  currentDID: "did:example:alice",
  didStrategy: new DefaultDidStrategy("did:example:alice")
});

const { dsu, lkeySSI, rkeySSI, lzaSSI, anchorId } = await engine.createDSU();
await dsu.writeFile("/docs/a.txt", Buffer.from("hello"));
const data = await dsu.readFile("/docs/a.txt");
```

### Engine

- `LightDSUEngine.open(config) -> engine`
- `engine.createDSU() -> { dsu, lkeySSI, rkeySSI, lzaSSI, anchorId }`
- `engine.loadDSU(keySSI) -> MountedLightDSU`
- `engine.parseSSI(serializedSSI) -> ParsedSSI`
- `engine.setCurrentDID(did) -> void`
- `engine.close()`

### Mounted DSU

- Filesystem: `readFile`, `writeFile`, `appendToFile`, `createFolder`, `delete`, `rename`, `stat`, `readDir`, `listFiles`, `listFolders`
- Batch: `beginBatch`, `commitBatch`, `cancelBatch`, `hasUncommittedChanges`
- Access: `grantAccess`, `revokeAccess`, `checkAccess`, `listAccess`
- Provenance: `appendProvenance`, `getProvenance`, `getHistory`, `validateProvenance`, `listProvenanceProfiles`, `getProvenancePolicy`, `updateProvenancePolicy`
- Utility: `verifyAnchor`, `getLatestEventHash`, `runGarbageCollection`, `setCurrentDID`

## v1 implementation highlights

- HKDF-SHA256 key derivation from `lkeySecret`
- Ed25519 anchor signing
- AES-256-GCM encryption for BrickMap, provenance bricks, and file bricks
- SHA-256 and HMAC-SHA256 integrity/indexing primitives
- Complete BrickMap snapshots per version with concurrent commit rebasing
- Strict scope validation and explicit error codes
- Provenance profile validation before persistence
- Retention-window garbage collection that preserves retained historical file bricks

## Standard error codes

`ERR_INVALID_SSI`, `ERR_INVALID_SCOPE`, `ERR_DOMAIN_MISMATCH`, `ERR_UNSUPPORTED_VERSION`, `ERR_ANCHOR_NOT_FOUND`, `ERR_EVENT_PARSE_FAILED`, `ERR_EVENT_SIGNATURE_INVALID`, `ERR_EVENT_CHAIN_INVALID`, `ERR_BRICK_NOT_FOUND`, `ERR_BRICK_HASH_MISMATCH`, `ERR_DECRYPTION_FAILED`, `ERR_ACCESS_DENIED`, `ERR_READ_ONLY_DSU`, `ERR_BATCH_ALREADY_STARTED`, `ERR_NO_BATCH_IN_PROGRESS`, `ERR_CONCURRENT_COMMIT`, `ERR_INVALID_PATH`, `ERR_INVALID_PERMISSION`, `ERR_INVALID_PROVENANCE_PROFILE`, `ERR_PROVENANCE_VALIDATION_FAILED`, `ERR_UNSUPPORTED_PROFILE`.
