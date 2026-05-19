"use strict";

const crypto = require("node:crypto");
const { throwError, ERROR_CODES } = require("../errors");

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function randomBytes(length) {
  return crypto.randomBytes(length);
}

function sha256(...parts) {
  const hasher = crypto.createHash("sha256");
  for (const part of parts) {
    hasher.update(part);
  }
  return hasher.digest();
}

function hkdf(ikm, salt, info, len) {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(ikm),
      Buffer.from(salt || Buffer.alloc(0)),
      Buffer.from(info),
      len
    )
  );
}

function hmacSha256(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

function aes256gcmEncrypt(key, plaintext, aad) {
  const nonce = randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

function aes256gcmDecrypt(key, nonce, ciphertext, tag, aad) {
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    if (aad) decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    throwError(ERROR_CODES.ERR_DECRYPTION_FAILED, error.message);
  }
}

function ed25519KeyPairFromSeed(seed32) {
  if (!Buffer.isBuffer(seed32) || seed32.length !== 32) {
    throw new TypeError("Ed25519 seed must be 32 bytes");
  }
  const privateKeyDer = Buffer.concat([ED25519_PKCS8_PREFIX, seed32]);
  const privateKey = crypto.createPrivateKey({ key: privateKeyDer, format: "der", type: "pkcs8" });
  const publicKeyObj = crypto.createPublicKey(privateKey);
  const publicKeyDer = publicKeyObj.export({ format: "der", type: "spki" });
  const publicKey = Buffer.from(publicKeyDer).subarray(ED25519_SPKI_PREFIX.length);
  return { privateKey, publicKey };
}

function ed25519Sign(privateKey, data) {
  return crypto.sign(null, Buffer.from(data), privateKey);
}

function ed25519Verify(publicKey, data, signature) {
  const keyObject = Buffer.isBuffer(publicKey)
    ? crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]), format: "der", type: "spki" })
    : publicKey;
  return crypto.verify(null, Buffer.from(data), keyObject, Buffer.from(signature));
}

module.exports = {
  randomBytes,
  sha256,
  hkdf,
  hmacSha256,
  aes256gcmEncrypt,
  aes256gcmDecrypt,
  ed25519KeyPairFromSeed,
  ed25519Sign,
  ed25519Verify
};
