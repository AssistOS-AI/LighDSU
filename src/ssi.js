"use strict";

const { decode, encode } = require("./crypto/base58");
const { SSI_TYPES } = require("./constants");
const { ERROR_CODES, throwError } = require("./errors");

function decodeSSIComponent(value, componentName) {
  try {
    return decode(value);
  } catch {
    throwError(ERROR_CODES.ERR_INVALID_SSI, `Invalid Base58 in SSI ${componentName}`);
  }
}

function parseSSI(ssi) {
  if (typeof ssi !== "string") {
    throwError(ERROR_CODES.ERR_INVALID_SSI, "SSI must be string");
  }
  const parts = ssi.split(":");
  if (parts[0] !== "ssi") {
    throwError(ERROR_CODES.ERR_INVALID_SSI, "Missing ssi prefix");
  }
  const type = parts[1];
  if (!Object.values(SSI_TYPES).includes(type)) {
    throwError(ERROR_CODES.ERR_INVALID_SSI, "Unknown SSI type");
  }

  if (type === SSI_TYPES.EVENT) {
    if (parts.length !== 6) {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "Invalid event SSI");
    }
    return {
      type,
      domain: parts[2],
      payload: decodeSSIComponent(parts[3], "payload"),
      signature: decodeSSIComponent(parts[4], "signature"),
      version: parts[5]
    };
  }

  if (parts.length !== 5) {
    throwError(ERROR_CODES.ERR_INVALID_SSI, "Invalid key SSI");
  }
  return {
    type,
    domain: parts[2],
    payload: decodeSSIComponent(parts[3], "payload"),
    version: parts[4]
  };
}

function ensureVersion(parsed) {
  if (parsed.version !== "v1") {
    throwError(ERROR_CODES.ERR_UNSUPPORTED_VERSION, `Unsupported version: ${parsed.version}`);
  }
}

function ensureDomain(expected, parsedDomain) {
  if (expected !== parsedDomain) {
    throwError(ERROR_CODES.ERR_DOMAIN_MISMATCH, `Expected ${expected}, got ${parsedDomain}`);
  }
}

function makeLKeySSI(domain, lkeySecret) {
  return `ssi:${SSI_TYPES.LKEY}:${domain}:${encode(lkeySecret)}:v1`;
}

function makeRKeySSI(domain, rkeySecret, anchorPublic) {
  return `ssi:${SSI_TYPES.RKEY}:${domain}:${encode(Buffer.concat([rkeySecret, anchorPublic]))}:v1`;
}

function makeLzaSSI(domain, anchorPublic) {
  return `ssi:${SSI_TYPES.LZA}:${domain}:${encode(anchorPublic)}:v1`;
}

function makeEventSSI(domain, eventPayload, anchorSignature) {
  return `ssi:${SSI_TYPES.EVENT}:${domain}:${encode(eventPayload)}:${encode(anchorSignature)}:v1`;
}

module.exports = {
  parseSSI,
  ensureVersion,
  ensureDomain,
  makeLKeySSI,
  makeRKeySSI,
  makeLzaSSI,
  makeEventSSI
};
