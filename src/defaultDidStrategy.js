"use strict";

const { encode, decode } = require("./crypto/base58");
const { ed25519KeyPairFromSeed, ed25519Sign, ed25519Verify, sha256 } = require("./crypto/primitives");

class DefaultDidStrategy {
  constructor(currentDID) {
    this.currentDID = currentDID;
    this.cache = new Map();
  }

  setCurrentDID(did) {
    this.currentDID = did;
  }

  normalize(did) {
    return String(did).trim().toLowerCase();
  }

  #keyForDid(did) {
    const normalized = this.normalize(did);
    if (this.cache.has(normalized)) return this.cache.get(normalized);
    const seed = sha256(Buffer.from(normalized));
    const keyPair = ed25519KeyPairFromSeed(seed);
    this.cache.set(normalized, keyPair);
    return keyPair;
  }

  sign(data) {
    const { privateKey } = this.#keyForDid(this.currentDID);
    const signature = ed25519Sign(privateKey, data);
    const envelope = { did: this.currentDID, signature: encode(signature) };
    return Buffer.from(JSON.stringify(envelope));
  }

  verify(did, data, envelopeBytes) {
    try {
      const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
      const expected = this.normalize(did);
      if (!envelope.did || this.normalize(envelope.did) !== expected) return false;
      const sig = decode(envelope.signature);
      const { publicKey } = this.#keyForDid(did);
      return ed25519Verify(publicKey, data, sig);
    } catch {
      return false;
    }
  }
}

module.exports = { DefaultDidStrategy };
