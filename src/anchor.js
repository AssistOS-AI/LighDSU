"use strict";

const { parseSSI, ensureVersion } = require("./ssi");
const { readAnchorLines, appendAnchorLine, withAnchorLock } = require("./storage");
const { decodeEventPayload } = require("./eventCodec");
const { ed25519Verify, sha256 } = require("./crypto/primitives");
const { ERROR_CODES, throwError } = require("./errors");
const { EVENT_TYPES } = require("./constants");
const {
  buildGrantId,
  hashDid,
  parseDidFromSignatureEnvelope,
  scopeFromEventExtension
} = require("./access");
const { encodeActorMessage } = require("./actorMessage");

function eventHash(payload, signature) {
  return sha256(payload, signature);
}

function readAnchorLinesOrEmpty(storageRoot, anchorIdHex) {
  return readAnchorLines(storageRoot, anchorIdHex).catch((error) => {
    if (error.code === ERROR_CODES.ERR_ANCHOR_NOT_FOUND) return [];
    throw error;
  });
}

function verifyEventShape(events) {
  for (let i = 0; i < events.length; i += 1) {
    const event = events[i];
    if (event.seq !== i) {
      throwError(ERROR_CODES.ERR_EVENT_CHAIN_INVALID, `Invalid seq at ${i + 1}`);
    }
    if (i === 0) {
      if (event.eventType !== EVENT_TYPES.GENESIS) {
        throwError(ERROR_CODES.ERR_EVENT_CHAIN_INVALID, "First event must be GENESIS");
      }
      if (!event.prevEventHash.equals(Buffer.alloc(32))) {
        throwError(ERROR_CODES.ERR_EVENT_CHAIN_INVALID, "GENESIS prev hash must be zero");
      }
    }
  }
}

function verifyActor(event, didStrategy, accessIndexKey) {
  if (!event.actorSignature) return;
  if (!didStrategy) {
    throwError(ERROR_CODES.ERR_EVENT_SIGNATURE_INVALID, "Actor verification context missing");
  }
  const did = parseDidFromSignatureEnvelope(event.actorSignature);
  if (!did) throwError(ERROR_CODES.ERR_EVENT_SIGNATURE_INVALID, "Actor DID missing from signature envelope");
  const actorMessage = encodeActorMessage(event);
  const valid = didStrategy.verify(did, actorMessage, event.actorSignature);
  if (!valid) throwError(ERROR_CODES.ERR_EVENT_SIGNATURE_INVALID, "Actor signature invalid");
  if (event.actorHash && accessIndexKey) {
    const expectedHash = hashDid(accessIndexKey, didStrategy, did);
    if (!expectedHash.equals(event.actorHash)) {
      throwError(ERROR_CODES.ERR_EVENT_SIGNATURE_INVALID, "Actor hash mismatch");
    }
  }
}

async function readAndVerifyAnchor(storageRoot, domain, anchorIdHex, anchorPublic, didStrategy, accessIndexKey) {
  const lines = await readAnchorLines(storageRoot, anchorIdHex);
  const events = [];
  let prev = Buffer.alloc(32);
  for (let i = 0; i < lines.length; i += 1) {
    const parsed = parseSSI(lines[i]);
    ensureVersion(parsed);
    if (parsed.domain !== domain || parsed.type !== "event") {
      throwError(ERROR_CODES.ERR_EVENT_PARSE_FAILED, `Invalid event SSI at line ${i + 1}`);
    }
    const ok = ed25519Verify(anchorPublic, parsed.payload, parsed.signature);
    if (!ok) {
      throwError(ERROR_CODES.ERR_EVENT_SIGNATURE_INVALID, `Invalid signature at line ${i + 1}`);
    }
    const decoded = decodeEventPayload(parsed.payload);
    if (!decoded.prevEventHash.equals(prev)) {
      throwError(ERROR_CODES.ERR_EVENT_CHAIN_INVALID, `Invalid chain at line ${i + 1}`);
    }
    verifyActor(decoded, didStrategy, accessIndexKey);
    const hash = eventHash(parsed.payload, parsed.signature);
    prev = hash;
    events.push({
      ...decoded,
      anchorSignature: parsed.signature,
      eventPayload: parsed.payload,
      eventHash: hash,
      scope: scopeFromEventExtension(decoded.extension),
      serialized: lines[i]
    });
  }
  verifyEventShape(events);
  return events;
}

function reduceAnchorState(events) {
  const state = {
    latestSeq: -1,
    latestEventHash: Buffer.alloc(32),
    latestBrickMapHash: null,
    activeGrants: new Map(),
    revokedGrants: new Set(),
    policy: 0,
    keyEpoch: 0
  };
  for (const event of events) {
    state.latestSeq = event.seq;
    state.latestEventHash = event.eventHash;
    if (event.eventType === EVENT_TYPES.VERSION_COMMIT && event.brickMapHash) {
      state.latestBrickMapHash = event.brickMapHash.toString("hex");
    }
    if (event.eventType === EVENT_TYPES.GRANT) {
      const id = event.eventHash.toString("hex");
      state.activeGrants.set(id, {
        id,
        subjectHash: event.subjectHash,
        resourceHash: event.resourceHash,
        permissions: event.permissions,
        scope: event.scope,
        tupleId: buildGrantId(event).toString("hex"),
        event
      });
      state.revokedGrants.delete(id);
    } else if (event.eventType === EVENT_TYPES.REVOKE) {
      if (event.grantId) {
        const id = event.grantId.toString("hex");
        state.activeGrants.delete(id);
        state.revokedGrants.add(id);
      } else {
        const tupleId = buildGrantId(event).toString("hex");
        for (const [id, grant] of state.activeGrants.entries()) {
          if (grant.tupleId === tupleId) {
            state.activeGrants.delete(id);
            state.revokedGrants.add(id);
          }
        }
      }
    } else if (event.eventType === EVENT_TYPES.POLICY_UPDATE || event.eventType === EVENT_TYPES.GENESIS) {
      if (typeof event.policyWord === "number") state.policy = event.policyWord >>> 0;
    } else if (event.eventType === EVENT_TYPES.KEY_EPOCH) {
      state.keyEpoch = event.keyEpoch >>> 0;
    }
  }
  return state;
}

async function appendEvent(storageRoot, anchorIdHex, serializedEvent, expectedPrevHashHex) {
  await withAnchorLock(storageRoot, anchorIdHex, async () => {
    if (expectedPrevHashHex) {
      const lines = await readAnchorLinesOrEmpty(storageRoot, anchorIdHex);
      let latest = Buffer.alloc(32).toString("hex");
      if (lines.length > 0) {
        const parsed = parseSSI(lines[lines.length - 1]);
        latest = eventHash(parsed.payload, parsed.signature).toString("hex");
      }
      if (latest !== expectedPrevHashHex) {
        throwError(ERROR_CODES.ERR_CONCURRENT_COMMIT, "Anchor changed during commit");
      }
    }
    await appendAnchorLine(storageRoot, anchorIdHex, serializedEvent);
  });
}

module.exports = { eventHash, readAndVerifyAnchor, reduceAnchorState, appendEvent };
