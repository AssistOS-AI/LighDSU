---
id: DS009
title: "DS009 — DID Strategy"
order: 9
---

# DS009 — DID Strategy

## Introduction

LightDSU accepts a pluggable DID strategy at engine initialization. The strategy handles DID normalization, signing, and verification for actor signatures on DSU events.

## Core Content

### DIDStrategy Interface

```
DIDStrategy
  normalize(did) -> normalizedDID (string)
  sign(bytes) -> signatureEnvelope (Buffer)
  verify(did, bytes, signatureEnvelope) -> boolean
```

### Engine Configuration

```js
LightDSUEngine.open({
  storageRoot,
  domain,
  didStrategy,
  currentDID
})
```

The engine has a `currentDID` that represents the operational actor. Filesystem and access APIs use `currentDID` implicitly — they do not accept a DID parameter.

### Actor Message Encoding

The actor message is built from event fields and signed by the DID strategy:

```js
actorMessage = canonicalJSONStringify({
  eventType,
  seq,
  timestampMs,
  brickMapHash?,   // hex string if present
  payloadHash?,    // hex string if present
  subjectHash?,    // hex string if present
  resourceHash?,   // hex string if present
  permissions?,    // number if present
  policyWord?,     // number if present
  keyEpoch?,       // number if present
  grantId?         // hex string if present
})
```

Buffers are converted to hex strings for canonical JSON encoding.

### Actor Hash

```
actorHash = HMAC-SHA256(accessIndexKey, normalize(currentDID))
```

The actor hash is computed during event recording and included in the event payload when the `actorHash` flag is set.

### Actor Signature

```
actorSignature = didStrategy.sign(actorMessage)
```

The signature envelope format is implementation-specific. The default strategy uses:

```json
{
  "did": "did:example:alice",
  "signature": "<base58(Ed25519 signature)>"
}
```

### Actor Verification

During anchor verification:
1. Parse the DID from the signature envelope.
2. Reconstruct the actor message from the event fields.
3. Call `didStrategy.verify(did, actorMessage, signatureEnvelope)`.
4. Optionally verify `actorHash` matches `HMAC-SHA256(accessIndexKey, normalize(did))`.

### Default DID Strategy

`DefaultDidStrategy` provides a local Ed25519-based implementation:

- **Key derivation**: `seed = SHA256(normalize(did))` per DID.
- **Signing**: Ed25519 sign with the derived key.
- **Verification**: Ed25519 verify with the derived public key.
- **Envelope**: JSON `{ did, signature: base58(sig) }`.
- **Caching**: Key pairs are cached per normalized DID.

**Warning**: `DefaultDidStrategy` is for development and testing only. Production deployments should use an external DID strategy (HSM, KMS, or wallet).

### DID Context Switching

```js
engine.setCurrentDID(did)
dsu.setCurrentDID(did)
```

Both methods update the `currentDID` and synchronize with the DID strategy if it supports `setCurrentDID` or has a `currentDID` property.

### Implementation

- `src/defaultDidStrategy.js` — `DefaultDidStrategy` class
- `src/actorMessage.js` — `encodeActorMessage`
- `src/access.js` — `hashDid`, `parseDidFromSignatureEnvelope`
- `src/anchor.js` — `verifyActor`
- `src/engine.js` — `setCurrentDID`
- `src/dsu.js` — `setCurrentDID`, `#currentActorHash`

## Decisions & Questions

### Question #1: Why does the actor message use canonical JSON instead of binary concatenation?

**Response:** The original specification describes actorMessage as binary concatenation. The implementation uses canonical JSON for determinism, debuggability, and cross-language interoperability. Canonical JSON with sorted keys produces a unique byte sequence for any given set of fields. This is a deliberate deviation from the spec wording, documented in DS000.

### Question #2: Why is currentDID implicit in filesystem APIs?

**Response:** The engine model assumes a single operational context. The `currentDID` is set at engine initialization and can be switched via `setCurrentDID`. This simplifies the API surface and matches the typical usage pattern where one actor operates on a DSU at a time.

## Conclusion

The DID strategy interface provides a clean separation between LightDSU's core logic and identity management. The default implementation enables local development, while the interface supports production-grade identity providers.
