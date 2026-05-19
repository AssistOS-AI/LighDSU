"use strict";

const { EVENT_FLAGS } = require("./constants");
const { ERROR_CODES, throwError } = require("./errors");

const OPTIONAL_FIELDS = [
  ["brickMapHash", EVENT_FLAGS.brickMapHash, "bytes32"],
  ["payloadHash", EVENT_FLAGS.payloadHash, "bytes32"],
  ["subjectHash", EVENT_FLAGS.subjectHash, "bytes32"],
  ["resourceHash", EVENT_FLAGS.resourceHash, "bytes32"],
  ["permissions", EVENT_FLAGS.permissions, "u16"],
  ["policyWord", EVENT_FLAGS.policyWord, "u32"],
  ["keyEpoch", EVENT_FLAGS.keyEpoch, "u32"],
  ["grantId", EVENT_FLAGS.grantId, "bytes32"],
  ["actorHash", EVENT_FLAGS.actorHash, "bytes32"],
  ["actorSignature", EVENT_FLAGS.actorSignature, "varbytes"],
  ["anchorPublic", EVENT_FLAGS.anchorPublic, "bytes32"],
  ["extension", EVENT_FLAGS.extension, "varbytes"]
];

function encodeUVarint(value) {
  let n = Number(value);
  const bytes = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return Buffer.from(bytes);
}

function decodeUVarint(buffer, start = 0) {
  let n = 0;
  let shift = 0;
  let offset = start;
  while (offset < buffer.length) {
    const b = buffer[offset];
    n |= (b & 0x7f) << shift;
    offset += 1;
    if ((b & 0x80) === 0) return { value: n >>> 0, offset };
    shift += 7;
    if (shift > 35) break;
  }
  throwError(ERROR_CODES.ERR_EVENT_PARSE_FAILED, "Invalid uvarint");
}

function encodeEventPayload(event) {
  const flags = event.flags >>> 0;
  const header = Buffer.alloc(1 + 2 + 6 + 32);
  header.writeUInt8(event.eventType, 0);
  header.writeUInt16BE(flags, 1);
  const seqBytes = encodeUVarint(event.seq >>> 0);
  header.writeUIntBE(Number(event.timestampMs), 3, 6);
  Buffer.from(event.prevEventHash).copy(header, 9);
  const chunks = [header.subarray(0, 3), seqBytes, header.subarray(3)];

  for (const [name, flag, kind] of OPTIONAL_FIELDS) {
    if ((flags & flag) === 0) continue;
    const value = event[name];
    if (kind === "bytes32") {
      if (!Buffer.isBuffer(value) || value.length !== 32) {
        throwError(ERROR_CODES.ERR_EVENT_PARSE_FAILED, `${name} must be bytes32`);
      }
      chunks.push(value);
    } else if (kind === "u16") {
      const b = Buffer.alloc(2);
      b.writeUInt16BE(value >>> 0, 0);
      chunks.push(b);
    } else if (kind === "u32") {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(value >>> 0, 0);
      chunks.push(b);
    } else if (kind === "varbytes") {
      const buf = Buffer.from(value || Buffer.alloc(0));
      chunks.push(encodeUVarint(buf.length), buf);
    }
  }
  return Buffer.concat(chunks);
}

function decodeEventPayload(payload) {
  try {
    const buffer = Buffer.from(payload);
    let offset = 0;
    const eventType = buffer.readUInt8(offset);
    offset += 1;
    const flags = buffer.readUInt16BE(offset);
    offset += 2;
    const seqDecoded = decodeUVarint(buffer, offset);
    const seq = seqDecoded.value;
    offset = seqDecoded.offset;
    const timestampMs = buffer.readUIntBE(offset, 6);
    offset += 6;
    const prevEventHash = buffer.subarray(offset, offset + 32);
    offset += 32;
    const out = { eventType, flags, seq, timestampMs, prevEventHash };
    for (const [name, flag, kind] of OPTIONAL_FIELDS) {
      if ((flags & flag) === 0) continue;
      if (kind === "bytes32") {
        out[name] = buffer.subarray(offset, offset + 32);
        offset += 32;
      } else if (kind === "u16") {
        out[name] = buffer.readUInt16BE(offset);
        offset += 2;
      } else if (kind === "u32") {
        out[name] = buffer.readUInt32BE(offset);
        offset += 4;
      } else if (kind === "varbytes") {
        const decoded = decodeUVarint(buffer, offset);
        offset = decoded.offset;
        out[name] = buffer.subarray(offset, offset + decoded.value);
        offset += decoded.value;
      }
    }
    if (offset !== buffer.length) {
      throw new Error("Trailing bytes");
    }
    return out;
  } catch (error) {
    throwError(ERROR_CODES.ERR_EVENT_PARSE_FAILED, error.message);
  }
}

module.exports = { encodeEventPayload, decodeEventPayload, encodeUVarint, decodeUVarint };
