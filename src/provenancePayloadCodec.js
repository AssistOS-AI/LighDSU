"use strict";

/**
 * ProvenancePayloadV1 binary codec.
 *
 * Binary layout (big-endian integers):
 *   [1]  flags
 *          bit 0: hasResourceHash
 *          bit 1: hasVersionSeq
 *          bit 2: hasExternalRefs
 *   [2]  profileId (u16)
 *   [2]  profileVersion (u16)
 *   [1]  payloadFormat
 *   [6]  createdAt (u48, ms)
 *   [32] resourceHash (if flags bit 0)
 *   [N]  versionSeq (uvarint, if flags bit 1)
 *   [32] canonicalPayloadHash
 *   [N]  canonicalPayloadLen (uvarint)
 *   [N]  canonicalPayload bytes
 *   [N]  externalRefsCount (uvarint, if flags bit 2)
 *        each ref:
 *          typeLen (uvarint) + type bytes
 *          refLen  (uvarint) + ref bytes
 *          hashLen (uvarint) + hash bytes (0 = absent)
 */

const { sha256 } = require("./crypto/primitives");
const { encodeUVarint, decodeUVarint } = require("./eventCodec");
const { throwError, ERROR_CODES } = require("./errors");
const { canonicalJSONStringify } = require("./utils");

const PROV_VERSION_TAG = 0x01; // v1

function encodeVarBytes(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data || "");
  return Buffer.concat([encodeUVarint(buf.length), buf]);
}

function encodeProvenancePayload(v1) {
  const {
    profileId,
    profileVersion,
    payloadFormat,
    createdAt,
    resourceHash,
    versionSeq,
    canonicalPayloadHash,
    canonicalPayload,
    externalReferences
  } = v1;

  let flags = 0;
  if (resourceHash) flags |= 0x01;
  if (versionSeq != null) flags |= 0x02;
  if (externalReferences && externalReferences.length > 0) flags |= 0x04;

  const header = Buffer.alloc(1 + 1 + 2 + 2 + 1 + 6);
  let pos = 0;
  header.writeUInt8(PROV_VERSION_TAG, pos++);
  header.writeUInt8(flags, pos++);
  header.writeUInt16BE(profileId >>> 0, pos);
  pos += 2;
  header.writeUInt16BE(profileVersion >>> 0, pos);
  pos += 2;
  header.writeUInt8(payloadFormat >>> 0, pos++);
  header.writeUIntBE(Number(createdAt), pos, 6);

  const parts = [header];

  if (flags & 0x01) {
    const rh = Buffer.isBuffer(resourceHash) ? resourceHash : Buffer.from(resourceHash, "hex");
    if (rh.length !== 32) throwError(ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE, "resourceHash must be 32 bytes");
    parts.push(rh);
  }

  if (flags & 0x02) {
    parts.push(encodeUVarint(versionSeq >>> 0));
  }

  const cph = Buffer.isBuffer(canonicalPayloadHash) ? canonicalPayloadHash : Buffer.from(canonicalPayloadHash, "hex");
  if (cph.length !== 32) throwError(ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE, "canonicalPayloadHash must be 32 bytes");
  parts.push(cph);

  const cpBuf = Buffer.isBuffer(canonicalPayload) ? canonicalPayload : Buffer.from(canonicalPayload);
  parts.push(encodeUVarint(cpBuf.length));
  parts.push(cpBuf);

  if (flags & 0x04) {
    parts.push(encodeUVarint(externalReferences.length));
    for (const ref of externalReferences) {
      parts.push(encodeVarBytes(Buffer.from(ref.type || "")));
      parts.push(encodeVarBytes(Buffer.from(ref.ref || "")));
      const hashBuf = ref.hash ? Buffer.from(ref.hash, "hex") : Buffer.alloc(0);
      parts.push(encodeVarBytes(hashBuf));
    }
  }

  return Buffer.concat(parts);
}

function decodeProvenancePayload(data) {
  try {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    let offset = 0;

    const versionTag = buffer.readUInt8(offset++);
    if (versionTag !== PROV_VERSION_TAG) {
      throwError(ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE, `Unsupported provenance payload version: ${versionTag}`);
    }

    const flags = buffer.readUInt8(offset++);
    const profileId = buffer.readUInt16BE(offset);
    offset += 2;
    const profileVersion = buffer.readUInt16BE(offset);
    offset += 2;
    const payloadFormat = buffer.readUInt8(offset++);
    const createdAt = buffer.readUIntBE(offset, 6);
    offset += 6;

    let resourceHash;
    if (flags & 0x01) {
      resourceHash = buffer.subarray(offset, offset + 32);
      offset += 32;
    }

    let versionSeq;
    if (flags & 0x02) {
      const dec = decodeUVarint(buffer, offset);
      versionSeq = dec.value;
      offset = dec.offset;
    }

    const canonicalPayloadHash = buffer.subarray(offset, offset + 32);
    offset += 32;

    const cpLenDec = decodeUVarint(buffer, offset);
    offset = cpLenDec.offset;
    const canonicalPayload = buffer.subarray(offset, offset + cpLenDec.value);
    offset += cpLenDec.value;

    const externalReferences = [];
    if (flags & 0x04) {
      const countDec = decodeUVarint(buffer, offset);
      offset = countDec.offset;
      for (let i = 0; i < countDec.value; i++) {
        const typeDec = decodeUVarint(buffer, offset);
        offset = typeDec.offset;
        const type = buffer.subarray(offset, offset + typeDec.value).toString("utf8");
        offset += typeDec.value;

        const refDec = decodeUVarint(buffer, offset);
        offset = refDec.offset;
        const ref = buffer.subarray(offset, offset + refDec.value).toString("utf8");
        offset += refDec.value;

        const hashDec = decodeUVarint(buffer, offset);
        offset = hashDec.offset;
        const hashBuf = buffer.subarray(offset, offset + hashDec.value);
        offset += hashDec.value;

        externalReferences.push({
          type,
          ref,
          hash: hashBuf.length > 0 ? hashBuf.toString("hex") : null
        });
      }
    }

    return {
      profileId,
      profileVersion,
      payloadFormat,
      createdAt,
      resourceHash: resourceHash ? resourceHash.toString("hex") : null,
      versionSeq: versionSeq != null ? versionSeq : null,
      canonicalPayloadHash: canonicalPayloadHash.toString("hex"),
      canonicalPayload,
      externalReferences: externalReferences.length > 0 ? externalReferences : undefined
    };
  } catch (error) {
    if (error.code === ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE) throw error;
    throwError(ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE, `Failed to decode ProvenancePayloadV1: ${error.message}`);
  }
}

function buildProvenancePayloadV1(input) {
  const cpBuf = Buffer.isBuffer(input.canonicalPayload)
    ? input.canonicalPayload
    : Buffer.from(typeof input.canonicalPayload === "object"
        ? canonicalJSONStringify(input.canonicalPayload)
        : String(input.canonicalPayload));

  const canonicalPayloadHash = sha256(cpBuf);

  return {
    profileId:            input.profileId,
    profileVersion:       input.profileVersion || 1,
    payloadFormat:        input.payloadFormat || 0x02,
    createdAt:            input.createdAt || Date.now(),
    resourceHash:         input.resourceHash || null,
    versionSeq:           input.versionSeq != null ? input.versionSeq : null,
    canonicalPayloadHash,
    canonicalPayload:     cpBuf,
    externalReferences:   input.externalReferences || null
  };
}

module.exports = { encodeProvenancePayload, decodeProvenancePayload, buildProvenancePayloadV1 };
