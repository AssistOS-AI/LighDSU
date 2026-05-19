"use strict";

const { ensureLayout, writeBrick } = require("./storage");
const { parseSSI, ensureDomain, ensureVersion, makeLKeySSI, makeRKeySSI, makeLzaSSI, makeEventSSI } = require("./ssi");
const {
  hkdf,
  randomBytes,
  sha256,
  aes256gcmEncrypt,
  ed25519KeyPairFromSeed,
  ed25519Sign
} = require("./crypto/primitives");
const { createEmptyBrickMap, serializeBrickMap } = require("./brickmap");
const { EVENT_TYPES, EVENT_FLAGS, PERMISSIONS } = require("./constants");
const { encodeEventPayload } = require("./eventCodec");
const { appendEvent, readAndVerifyAnchor, reduceAnchorState } = require("./anchor");
const { MountedLightDSU } = require("./dsu");
const { hashDid, hashResource, makeExtensionPayload, scopeToJSON } = require("./access");
const { ERROR_CODES, throwError } = require("./errors");
const { DefaultDidStrategy } = require("./defaultDidStrategy");
const { encodeActorMessage } = require("./actorMessage");

class LightDSUEngine {
  static async open(config) {
    const engine = new LightDSUEngine(config);
    await ensureLayout(engine.storageRoot);
    return engine;
  }

  constructor(config) {
    if (!config || typeof config !== "object") {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "Engine config is required");
    }
    if (!config.storageRoot || typeof config.storageRoot !== "string") {
      throwError(ERROR_CODES.ERR_INVALID_PATH, "storageRoot is required");
    }
    if (!config.domain || typeof config.domain !== "string" || config.domain.includes(":")) {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "domain is required and cannot contain ':'");
    }
    if (config.currentDID !== undefined && typeof config.currentDID !== "string") {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "currentDID must be string");
    }
    this.storageRoot = config.storageRoot;
    this.domain = config.domain;
    this.currentDID = config.currentDID || "did:lightdsu:default";
    this.didStrategy = config.didStrategy || new DefaultDidStrategy(this.currentDID);
    if (
      !this.didStrategy ||
      typeof this.didStrategy.normalize !== "function" ||
      typeof this.didStrategy.sign !== "function" ||
      typeof this.didStrategy.verify !== "function"
    ) {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "didStrategy must implement normalize/sign/verify");
    }
  }

  parseSSI(serializedSSI) {
    const parsed = parseSSI(serializedSSI);
    ensureVersion(parsed);
    ensureDomain(this.domain, parsed.domain);
    return parsed;
  }

  #deriveFromLkeySecret(lkeySecret) {
    const anchorSigningSeed = hkdf(lkeySecret, Buffer.alloc(0), Buffer.from("anchor-signing"), 32);
    const rkeySecret = hkdf(lkeySecret, Buffer.alloc(0), Buffer.from("read-key"), 32);
    const { privateKey: anchorPrivate, publicKey: anchorPublic } = ed25519KeyPairFromSeed(anchorSigningSeed);
    const anchorId = sha256(anchorPublic);
    const brickMapKey = hkdf(rkeySecret, anchorId, Buffer.from("brickmap"), 32);
    const accessIndexKey = hkdf(rkeySecret, anchorId, Buffer.from("access-index"), 32);
    return {
      lkeySecret,
      rkeySecret,
      anchorPrivate,
      anchorPublic,
      anchorId,
      brickMapKey,
      accessIndexKey
    };
  }

  #deriveFromRkeyPayload(payload) {
    if (payload.length !== 64) throwError(ERROR_CODES.ERR_INVALID_SSI, "rkey payload must be 64 bytes");
    const rkeySecret = payload.subarray(0, 32);
    const anchorPublic = payload.subarray(32, 64);
    const anchorId = sha256(anchorPublic);
    const brickMapKey = hkdf(rkeySecret, anchorId, Buffer.from("brickmap"), 32);
    const accessIndexKey = hkdf(rkeySecret, anchorId, Buffer.from("access-index"), 32);
    return { rkeySecret, anchorPublic, anchorId, brickMapKey, accessIndexKey };
  }

  #deriveFromLzaPayload(payload) {
    if (payload.length !== 32) throwError(ERROR_CODES.ERR_INVALID_SSI, "lza payload must be 32 bytes");
    const anchorPublic = payload;
    const anchorId = sha256(anchorPublic);
    return { anchorPublic, anchorId };
  }

  async createDSU() {
    const lkeySecret = randomBytes(32);
    const keys = this.#deriveFromLkeySecret(lkeySecret);
    const anchorIdHex = keys.anchorId.toString("hex");
    const lkeySSI = makeLKeySSI(this.domain, keys.lkeySecret);
    const rkeySSI = makeRKeySSI(this.domain, keys.rkeySecret, keys.anchorPublic);
    const lzaSSI = makeLzaSSI(this.domain, keys.anchorPublic);

    const brickMap = createEmptyBrickMap();
    const encrypted = aes256gcmEncrypt(keys.brickMapKey, serializeBrickMap(brickMap), Buffer.from("brickmap"));
    const brickMapEnvelope = Buffer.concat([encrypted.nonce, encrypted.ciphertext, encrypted.tag]);
    const brickMapHashHex = await writeBrick(this.storageRoot, brickMapEnvelope);

    let prev = Buffer.alloc(32);
    let seq = 0;
    const now = Date.now();

    const genesisFields = {
      eventType: EVENT_TYPES.GENESIS,
      flags: EVENT_FLAGS.anchorPublic,
      seq,
      timestampMs: now,
      prevEventHash: prev,
      anchorPublic: keys.anchorPublic
    };
    const genesisPayload = encodeEventPayload(genesisFields);
    const genesisSignature = ed25519Sign(keys.anchorPrivate, genesisPayload);
    await appendEvent(this.storageRoot, anchorIdHex, makeEventSSI(this.domain, genesisPayload, genesisSignature));
    prev = sha256(genesisPayload, genesisSignature);
    seq += 1;

    const versionFields = {
      eventType: EVENT_TYPES.VERSION_COMMIT,
      flags: EVENT_FLAGS.brickMapHash | EVENT_FLAGS.actorHash | EVENT_FLAGS.actorSignature,
      seq,
      timestampMs: now + 1,
      prevEventHash: prev,
      brickMapHash: Buffer.from(brickMapHashHex, "hex")
    };
    const versionActorMsg = encodeActorMessage(versionFields);
    versionFields.actorHash = hashDid(keys.accessIndexKey, this.didStrategy, this.currentDID);
    versionFields.actorSignature = Buffer.from(this.didStrategy.sign(versionActorMsg));
    const versionPayload = encodeEventPayload(versionFields);
    const versionSignature = ed25519Sign(keys.anchorPrivate, versionPayload);
    await appendEvent(this.storageRoot, anchorIdHex, makeEventSSI(this.domain, versionPayload, versionSignature));
    prev = sha256(versionPayload, versionSignature);
    seq += 1;

    const adminResourceHash = hashResource(keys.accessIndexKey, { kind: "DSU", path: "/", recursive: true });
    const grantFields = {
      eventType: EVENT_TYPES.GRANT,
      flags:
        EVENT_FLAGS.subjectHash |
        EVENT_FLAGS.resourceHash |
        EVENT_FLAGS.permissions |
        EVENT_FLAGS.actorHash |
        EVENT_FLAGS.actorSignature,
      seq,
      timestampMs: now + 2,
      prevEventHash: prev,
      subjectHash: hashDid(keys.accessIndexKey, this.didStrategy, this.currentDID),
      resourceHash: adminResourceHash,
      permissions:
        PERMISSIONS.ADMIN |
        PERMISSIONS.READ |
        PERMISSIONS.WRITE |
        PERMISSIONS.DELETE |
        PERMISSIONS.LIST |
        PERMISSIONS.EXPORT |
        PERMISSIONS.GRANT |
        PERMISSIONS.REVOKE |
        PERMISSIONS.AUDIT |
        PERMISSIONS.PROVENANCE_APPEND
    };
    grantFields.flags |= EVENT_FLAGS.extension;
    grantFields.extension = makeExtensionPayload({ scope: scopeToJSON({ kind: "DSU", path: "/", recursive: true }) });
    const grantActorMsg = encodeActorMessage(grantFields);
    grantFields.actorHash = hashDid(keys.accessIndexKey, this.didStrategy, this.currentDID);
    grantFields.actorSignature = Buffer.from(this.didStrategy.sign(grantActorMsg));
    const grantPayload = encodeEventPayload(grantFields);
    const grantSignature = ed25519Sign(keys.anchorPrivate, grantPayload);
    await appendEvent(this.storageRoot, anchorIdHex, makeEventSSI(this.domain, grantPayload, grantSignature));

    const dsu = await this.loadDSU(lkeySSI);
    return { dsu, lkeySSI, rkeySSI, lzaSSI, anchorId: anchorIdHex };
  }

  async loadDSU(keySSI) {
    const parsed = this.parseSSI(keySSI);
    let derived;
    let mountType = parsed.type;
    if (parsed.type === "lkey") {
      if (parsed.payload.length !== 32) throwError(ERROR_CODES.ERR_INVALID_SSI, "lkey payload must be 32 bytes");
      derived = this.#deriveFromLkeySecret(parsed.payload);
    } else if (parsed.type === "rkey") {
      derived = this.#deriveFromRkeyPayload(parsed.payload);
    } else if (parsed.type === "lza") {
      derived = this.#deriveFromLzaPayload(parsed.payload);
    } else {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "Unsupported SSI type for load");
    }

    const anchorIdHex = derived.anchorId.toString("hex");
    const events = await readAndVerifyAnchor(
      this.storageRoot,
      this.domain,
      anchorIdHex,
      derived.anchorPublic,
      this.didStrategy,
      derived.accessIndexKey
    );
    const anchorState = reduceAnchorState(events);
    anchorState.accessIndexKey = derived.accessIndexKey;
    let brickMap = null;
    if (mountType !== "lza") {
      const latestHash = anchorState.latestBrickMapHash;
      brickMap = await MountedLightDSU.decryptBrickMap(this.storageRoot, latestHash, derived.brickMapKey);
    }

    return new MountedLightDSU({
      storageRoot: this.storageRoot,
      domain: this.domain,
      mountType,
      currentDID: this.currentDID,
      didStrategy: this.didStrategy,
      anchorIdHex,
      events,
      anchorState,
      brickMap,
      anchorPrivate: derived.anchorPrivate,
      anchorPublic: derived.anchorPublic,
      brickMapKey: derived.brickMapKey,
      accessIndexKey: derived.accessIndexKey
    });
  }

  close() {}

  setCurrentDID(did) {
    if (typeof did !== "string" || !did.length) {
      throwError(ERROR_CODES.ERR_INVALID_SSI, "DID must be non-empty string");
    }
    this.currentDID = did;
    if (this.didStrategy && typeof this.didStrategy.setCurrentDID === "function") {
      this.didStrategy.setCurrentDID(did);
    } else if (this.didStrategy && typeof this.didStrategy === "object" && "currentDID" in this.didStrategy) {
      this.didStrategy.currentDID = did;
    }
  }
}

module.exports = { LightDSUEngine };
