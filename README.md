# LightDSU v1

LightDSU este o librărie locală pentru DSU-uri criptate, cu:
- **KeySSI family**: `lkey`, `rkey`, `lza`
- **anchor local append-only**: fișier line-oriented cu `ssi:event`
- **BrickMap criptat**: snapshot complet al sistemului virtual de fișiere
- **bricks criptate**: content-addressed, AES-256-GCM
- **access + audit + provenance**: pe bază de EventSSI

Specificația tehnică self-contained: [`docs/lightdsu-v1-spec.md`](docs/lightdsu-v1-spec.md)

## Instalare

```bash
npm install
```

## Rulare teste

```bash
npm test
```

## Structură locală storage

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

## Convenție SSI

- `ssi:lkey:<domain>:<payloadB58>:v1`
- `ssi:rkey:<domain>:<payloadB58>:v1`
- `ssi:lza:<domain>:<payloadB58>:v1`
- `ssi:event:<domain>:<payloadB58>:<signatureB58>:v1`

## API public

```js
const { LightDSUEngine, DefaultDidStrategy, PERMISSIONS } = require("lighdsu");

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
- `engine.close()`

### Filesystem API

- `readFile`, `writeFile`, `appendToFile`
- `createFolder`, `delete`, `rename`
- `stat`, `readDir`, `listFiles`, `listFolders`

### Batch API

- `beginBatch()`
- `commitBatch()`
- `cancelBatch()`
- `hasUncommittedChanges()`

### Access API

- `grantAccess(subjectDID, scope, permissions, options?)`
- `revokeAccess(subjectDID, scope, permissions, options?)`
- `checkAccess(subjectDID, scope, permissions)`
- `listAccess()`

### Provenance API

- `appendProvenance(resource, payload, options?)`
- `getProvenance()`
- `getHistory(query?)`

## Implementare v1 (esențial)

- Derivări chei prin HKDF-SHA256 din `lkeySecret`:
  - `anchorSigningSeed`
  - `rkeySecret`
  - `brickMapKey`
  - `accessIndexKey`
- Semnare ancoră: Ed25519
- Criptare bricks / brickmap: AES-256-GCM
- Hashing: SHA-256, HMAC-SHA256
- Reducere AnchorState: seq, latest hash, latest BrickMap, grants/revokes, policy, keyEpoch

## Erori standard expuse

`ERR_INVALID_SSI`, `ERR_DOMAIN_MISMATCH`, `ERR_UNSUPPORTED_VERSION`, `ERR_ANCHOR_NOT_FOUND`, `ERR_EVENT_PARSE_FAILED`, `ERR_EVENT_SIGNATURE_INVALID`, `ERR_EVENT_CHAIN_INVALID`, `ERR_BRICK_NOT_FOUND`, `ERR_BRICK_HASH_MISMATCH`, `ERR_DECRYPTION_FAILED`, `ERR_ACCESS_DENIED`, `ERR_READ_ONLY_DSU`, `ERR_BATCH_ALREADY_STARTED`, `ERR_NO_BATCH_IN_PROGRESS`, `ERR_CONCURRENT_COMMIT`, `ERR_INVALID_PATH`, `ERR_INVALID_PERMISSION`.
