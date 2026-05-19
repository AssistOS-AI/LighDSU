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
- `close`

### Mounted DSU
- filesystem: `readFile`, `writeFile`, `appendToFile`, `createFolder`, `delete`, `rename`, `stat`, `readDir`, `listFiles`, `listFolders`
- batch: `beginBatch`, `commitBatch`, `cancelBatch`, `hasUncommittedChanges`
- access: `grantAccess`, `revokeAccess`, `checkAccess`, `listAccess`
- provenance/history: `appendProvenance`, `getProvenance`, `getHistory`

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
