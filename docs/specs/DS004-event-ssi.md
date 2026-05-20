---
id: DS004
title: "DS004 — EventSSI Encoding"
order: 4
---

# DS004 — EventSSI Encoding

## Introduction

EventSSI is the binary-encoded payload format for anchor events. Each event in the anchor file is an EventSSI: a binary payload signed with the anchor's Ed25519 private key, serialized as an SSI string.

## Core Content

### Binary Layout

The event payload is encoded as a binary structure with a fixed header followed by optional fields controlled by a flags bitmask.

#### Header (fixed)

| Offset | Size | Field | Type |
|--------|------|-------|------|
| 0 | 1 | eventType | u8 |
| 1 | 2 | flags | u16 (big-endian) |
| 3 | N | seq | uvarint |
| 3+N | 6 | timestampMs | u48 (big-endian) |
| 3+N+6 | 32 | prevEventHash | bytes32 |

The header is serialized as: `[eventType(1)][flags(2)][seq(varint)][timestampMs(6)][prevEventHash(32)]`

#### Optional Fields (ordered by flag position)

Fields appear in the exact order below, only if their flag bit is set:

| Flag | Field | Type |
|------|-------|------|
| 0x0001 | brickMapHash | bytes32 |
| 0x0002 | payloadHash | bytes32 |
| 0x0004 | subjectHash | bytes32 |
| 0x0008 | resourceHash | bytes32 |
| 0x0010 | permissions | u16 (big-endian) |
| 0x0020 | policyWord | u32 (big-endian) |
| 0x0040 | keyEpoch | u32 (big-endian) |
| 0x0080 | grantId | bytes32 |
| 0x0100 | actorHash | bytes32 |
| 0x0200 | actorSignature | varbytes (uvarint length + data) |
| 0x0400 | anchorPublic | bytes32 |
| 0x0800 | extension | varbytes (uvarint length + data) |

### Encoding Rules

- All integers are big-endian.
- `uvarint` uses standard variable-length encoding (7 bits per byte, MSB = continuation).
- `bytes32` fields are exactly 32 bytes.
- `varbytes` fields are prefixed with a uvarint length.
- The `extension` field contains JSON-encoded data for future extensibility.

### Event Hash

```
eventHash = SHA256(eventPayload || anchorSignature)
```

The event hash is computed over the concatenation of the binary event payload and the Ed25519 anchor signature.

### Anchor Signature

```
anchorSignature = Ed25519.sign(anchorPrivate, eventPayload)
```

Verification:
```
Ed25519.verify(anchorPublic, eventPayload, anchorSignature)
```

### Chain Integrity

- `prevEventHash` in each event must equal the `eventHash` of the previous event.
- For GENESIS (seq=0), `prevEventHash` is 32 zero bytes.
- `seq` must be strictly sequential starting from 0.

### SSI Serialization

```
ssi:event:<domain>:<base58(eventPayload)>:<base58(anchorSignature)>:v1
```

Each line in the anchor file is one EventSSI string.

### Implementation

- `src/eventCodec.js` — `encodeEventPayload`, `decodeEventPayload`, `encodeUVarint`, `decodeUVarint`
- `src/ssi.js` — `makeEventSSI`, `parseSSI` (event type)
- `src/anchor.js` — `eventHash`, `readAndVerifyAnchor`

## Decisions & Questions

### Question #1: Why is seq encoded as uvarint in the header but other integers are fixed-width?

**Response:** Sequence numbers can grow arbitrarily large over the lifetime of a DSU. Using uvarint provides efficient encoding for small values while supporting arbitrarily large values. Fixed-width fields (eventType, flags, timestampMs, prevEventHash) have known maximum sizes.

### Question #2: Why are optional fields in a fixed order rather than key-value pairs?

**Response:** Fixed-order encoding produces a deterministic binary representation, which is essential for signature verification. Key-value encoding would require canonicalization rules and would be less efficient.

## Conclusion

EventSSI provides a compact, deterministic binary format for anchor events. The flags-based optional field system allows different event types to carry only the data they need while maintaining a verifiable chain structure.
