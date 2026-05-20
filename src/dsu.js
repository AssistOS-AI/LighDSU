"use strict";

const { ERROR_CODES, throwError } = require("./errors");
const { EVENT_TYPES, EVENT_FLAGS, PERMISSIONS, policyAuditMode, AUDIT_MODE, DEFAULT_CHUNK_SIZE } = require("./constants");
const { normalizePath, canonicalJSONStringify } = require("./utils");
const { encodeEventPayload } = require("./eventCodec");
const { makeEventSSI } = require("./ssi");
const { aes256gcmEncrypt, aes256gcmDecrypt, sha256, randomBytes, ed25519Sign } = require("./crypto/primitives");
const { writeBrick, readBrick, listBrickHashes, removeBrick } = require("./storage");
const {
  serializeBrickMap,
  deserializeBrickMap,
  ensureFolder,
  setFileEntry,
  getFileEntry,
  statEntry,
  deleteEntry,
  renameEntry,
  listEntries,
  listByType,
  decodeFileKey
} = require("./brickmap");
const {
  hashDid,
  hashResource,
  normalizeScope,
  checkPermission,
  buildGrantId,
  makeExtensionPayload,
  scopeToJSON,
  buildAccessDecision,
  verifyPermissionMask
} = require("./access");
const { appendEvent, readAndVerifyAnchor, reduceAnchorState } = require("./anchor");
const { encodeActorMessage } = require("./actorMessage");
const { encodeProvenancePayload, decodeProvenancePayload, buildProvenancePayloadV1 } = require("./provenancePayloadCodec");
const { getProfile, listProfiles, validateStructural } = require("./provenanceProfiles");

function cloneJSON(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function valuesEqual(left, right) {
  if (left === undefined && right === undefined) return true;
  return canonicalJSONStringify(left) === canonicalJSONStringify(right);
}

function replayLocalChanges(baseValue, workingValue, latestValue) {
  if (valuesEqual(baseValue, workingValue)) {
    return cloneJSON(latestValue);
  }
  if (!isPlainObject(baseValue) || !isPlainObject(workingValue) || !isPlainObject(latestValue)) {
    return cloneJSON(workingValue);
  }

  const result = cloneJSON(latestValue) || {};
  const keys = new Set([
    ...Object.keys(baseValue || {}),
    ...Object.keys(workingValue || {})
  ]);

  for (const key of keys) {
    if (!(key in workingValue)) {
      delete result[key];
      continue;
    }
    result[key] = replayLocalChanges(baseValue?.[key], workingValue[key], latestValue?.[key]);
  }

  return result;
}

class MountedLightDSU {
  constructor(options) {
    Object.assign(this, options);
    this.isBatchMode = false;
    this.dirty = false;
    this.baseBrickMap = this.brickMap ? cloneJSON(this.brickMap) : null;
  }

  #assertWritable() {
    if (this.mountType !== "lkey") {
      throwError(ERROR_CODES.ERR_READ_ONLY_DSU, "DSU is read-only");
    }
  }

  #assertContentCapable() {
    if (this.mountType === "lza") {
      throwError(ERROR_CODES.ERR_READ_ONLY_DSU, "LZA cannot access encrypted content");
    }
  }

  #currentActorHash() {
    return hashDid(this.accessIndexKey, this.didStrategy, this.currentDID);
  }

  #resourceHashForScope(scope) {
    return hashResource(this.accessIndexKey, normalizeScope(scope));
  }

  #checkCurrentAccess(scope, permission) {
    if (this.mountType === "lza") {
      throwError(ERROR_CODES.ERR_READ_ONLY_DSU, "LZA cannot evaluate access");
    }
    const actorHash = this.#currentActorHash();
    const normalizedScope = normalizeScope(scope);
    const allowed = checkPermission(this.anchorState, actorHash, normalizedScope, permission);
    if (!allowed) throwError(ERROR_CODES.ERR_ACCESS_DENIED, "Access denied");
  }

  async #refreshAnchorState() {
    const events = await readAndVerifyAnchor(
      this.storageRoot,
      this.domain,
      this.anchorIdHex,
      this.anchorPublic,
      this.didStrategy,
      this.accessIndexKey
    );
    this.events = events;
    this.anchorState = reduceAnchorState(events);
    this.anchorState.accessIndexKey = this.accessIndexKey;
    return events;
  }

  #prepareBrickMapForCommit() {
    const nextBrickMap = cloneJSON(this.brickMap);
    nextBrickMap.seq = (Number.isInteger(nextBrickMap.seq) ? nextBrickMap.seq : 0) + 1;
    nextBrickMap.manifest = nextBrickMap.manifest || {};
    nextBrickMap.manifest.updatedAt = Date.now();
    return nextBrickMap;
  }

  async #rebaseBrickMapOntoLatest() {
    await this.#refreshAnchorState();
    const latestBrickMap = await MountedLightDSU.decryptBrickMap(
      this.storageRoot,
      this.anchorState.latestBrickMapHash,
      this.brickMapKey
    );
    const rebased = replayLocalChanges(this.baseBrickMap || latestBrickMap, this.brickMap, latestBrickMap);
    this.brickMap = rebased;
  }

  async #appendEventOnce(eventPayloadFields) {
    this.#assertWritable();
    const baseSeq = this.anchorState.latestSeq;
    const basePrevHash = this.anchorState.latestEventHash;
    const timestampMs = Date.now();
    const seq = baseSeq + 1;
    const event = {
      seq,
      timestampMs,
      prevEventHash: basePrevHash,
      ...eventPayloadFields
    };
    const actorMessage = encodeActorMessage(event);
    if (event.flags & EVENT_FLAGS.actorSignature) {
      event.actorSignature = Buffer.from(this.didStrategy.sign(actorMessage));
    }
    if (event.flags & EVENT_FLAGS.actorHash) {
      event.actorHash = this.#currentActorHash();
    }
    const eventPayload = encodeEventPayload(event);
    const anchorSignature = ed25519Sign(this.anchorPrivate, eventPayload);
    const serialized = makeEventSSI(this.domain, eventPayload, anchorSignature);
    const expectedEventHash = sha256(eventPayload, anchorSignature).toString("hex");

    await appendEvent(this.storageRoot, this.anchorIdHex, serialized, basePrevHash.toString("hex"));
    const events = await this.#refreshAnchorState();
    const appendedEvent = events.find((item) => item.eventHash.toString("hex") === expectedEventHash);
    if (!appendedEvent) {
      throwError(ERROR_CODES.ERR_CONCURRENT_COMMIT, "Appended event could not be located after refresh");
    }
    return appendedEvent;
  }

  async #recordEvent(eventPayloadFields) {
    this.#assertWritable();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.#appendEventOnce(eventPayloadFields);
      } catch (error) {
        if (error.code !== ERROR_CODES.ERR_CONCURRENT_COMMIT || attempt === 2) throw error;
        await this.#refreshAnchorState();
      }
    }
    throwError(ERROR_CODES.ERR_CONCURRENT_COMMIT, "Failed to append event after retries");
  }

  async #commitVersion(payloadHash) {
    this.#assertWritable();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const nextBrickMap = this.#prepareBrickMapForCommit();
      const plain = serializeBrickMap(nextBrickMap);
      const encrypted = aes256gcmEncrypt(this.brickMapKey, plain, Buffer.from("brickmap"));
      const envelope = Buffer.concat([encrypted.nonce, encrypted.ciphertext, encrypted.tag]);
      const brickMapHashHex = await writeBrick(this.storageRoot, envelope);
      const fields = {
        eventType: EVENT_TYPES.VERSION_COMMIT,
        flags: EVENT_FLAGS.brickMapHash | EVENT_FLAGS.actorHash | EVENT_FLAGS.actorSignature,
        brickMapHash: Buffer.from(brickMapHashHex, "hex")
      };
      if (payloadHash) {
        fields.flags |= EVENT_FLAGS.payloadHash;
        fields.payloadHash = payloadHash;
      }

      try {
        const event = await this.#appendEventOnce(fields);
        this.brickMap = nextBrickMap;
        this.baseBrickMap = cloneJSON(nextBrickMap);
        this.dirty = false;
        return { seq: event.seq, brickMapHash: brickMapHashHex, eventHash: event.eventHash.toString("hex") };
      } catch (error) {
        if (error.code !== ERROR_CODES.ERR_CONCURRENT_COMMIT || attempt === 2) {
          throw error;
        }
        await this.#rebaseBrickMapOntoLatest();
      }
    }
    throwError(ERROR_CODES.ERR_CONCURRENT_COMMIT, "Failed to commit version after retries");
  }

  async #maybeAutoCommit() {
    if (!this.isBatchMode && this.dirty) {
      await this.#commitVersion();
    }
  }

  hasUncommittedChanges() {
    return this.dirty;
  }

  beginBatch() {
    if (this.isBatchMode) throwError(ERROR_CODES.ERR_BATCH_ALREADY_STARTED, "Batch already started");
    this.isBatchMode = true;
    this.batchSnapshot = cloneJSON(this.brickMap);
  }

  async commitBatch() {
    if (!this.isBatchMode) throwError(ERROR_CODES.ERR_NO_BATCH_IN_PROGRESS, "No batch in progress");
    this.isBatchMode = false;
    this.batchSnapshot = null;
    if (!this.dirty) {
      return {
        seq: this.anchorState.latestSeq,
        brickMapHash: this.anchorState.latestBrickMapHash,
        eventHash: this.anchorState.latestEventHash.toString("hex")
      };
    }
    return this.#commitVersion();
  }

  cancelBatch() {
    if (!this.isBatchMode) throwError(ERROR_CODES.ERR_NO_BATCH_IN_PROGRESS, "No batch in progress");
    this.isBatchMode = false;
    this.brickMap = this.batchSnapshot || this.brickMap;
    this.batchSnapshot = null;
    this.dirty = false;
  }

  async createFolder(folderPath) {
    this.#assertContentCapable();
    this.#assertWritable();
    this.#checkCurrentAccess({ kind: "folder", path: folderPath, recursive: true }, PERMISSIONS.WRITE);
    ensureFolder(this.brickMap, folderPath);
    this.dirty = true;
    await this.#maybeAutoCommit();
  }

  async writeFile(filePath, data, options = {}) {
    this.#assertContentCapable();
    this.#assertWritable();
    this.#checkCurrentAccess({ kind: "file", path: filePath, recursive: false }, PERMISSIONS.WRITE);
    const normalized = normalizePath(filePath);
    ensureFolder(this.brickMap, normalized.split("/").slice(0, -1).join("/") || "/");
    const content = Buffer.from(data);
    const fileKey = randomBytes(32);
    const chunkSize = options.chunkSize || DEFAULT_CHUNK_SIZE;
    const chunks = [];
    for (let offset = 0; offset < content.length || (content.length === 0 && offset === 0); offset += chunkSize) {
      const plainChunk = content.subarray(offset, offset + chunkSize);
      const encrypted = aes256gcmEncrypt(fileKey, plainChunk, Buffer.from(`${normalized}:${offset}`));
      const envelope = Buffer.concat([encrypted.nonce, encrypted.ciphertext, encrypted.tag]);
      const brickHash = await writeBrick(this.storageRoot, envelope);
      chunks.push({
        brickHash,
        offset,
        plainSize: plainChunk.length,
        cipherSize: envelope.length,
        nonce: encrypted.nonce.toString("hex")
      });
      if (content.length === 0) break;
    }
    setFileEntry(this.brickMap, normalized, {
      size: content.length,
      mediaType: options.mediaType,
      metadata: options.metadata,
      fileKey,
      chunks
    });
    this.dirty = true;
    await this.#maybeAutoCommit();
  }

  async appendToFile(filePath, data, options = {}) {
    let current = Buffer.alloc(0);
    try {
      current = await this.readFile(filePath);
    } catch (error) {
      if (error.code !== ERROR_CODES.ERR_INVALID_PATH) throw error;
    }
    const next = Buffer.concat([current, Buffer.from(data)]);
    await this.writeFile(filePath, next, options);
  }

  async readFile(filePath, options = {}) {
    this.#assertContentCapable();
    this.#checkCurrentAccess({ kind: "file", path: filePath, recursive: false }, PERMISSIONS.READ);
    const normalized = normalizePath(filePath);
    const entry = getFileEntry(this.brickMap, normalized);
    const fileKey = decodeFileKey(entry);
    const chunks = [];
    for (const chunk of entry.chunks) {
      const envelope = await readBrick(this.storageRoot, chunk.brickHash);
      const nonce = envelope.subarray(0, 12);
      const tag = envelope.subarray(envelope.length - 16);
      const ciphertext = envelope.subarray(12, envelope.length - 16);
      const plain = aes256gcmDecrypt(fileKey, nonce, ciphertext, tag, Buffer.from(`${normalized}:${chunk.offset}`));
      chunks.push(plain);
    }
    const content = Buffer.concat(chunks);
    const auditMode = options.audit || policyAuditMode(this.anchorState.policy);
    if (auditMode === true || auditMode === AUDIT_MODE["semantic-read-audit"] || auditMode === AUDIT_MODE["full-operation-audit"]) {
      await this.#appendAccessLog({ kind: "file", path: normalized, recursive: false }, PERMISSIONS.READ);
    }
    return content;
  }

  async #appendAccessLog(scope, permissions, payloadHash) {
    if (this.mountType !== "lkey") return;
    const normalizedScope = normalizeScope(scope);
    const fields = {
      eventType: EVENT_TYPES.ACCESS_LOG,
      flags:
        EVENT_FLAGS.subjectHash |
        EVENT_FLAGS.resourceHash |
        EVENT_FLAGS.permissions |
        EVENT_FLAGS.actorHash |
        EVENT_FLAGS.actorSignature |
        EVENT_FLAGS.extension,
      subjectHash: this.#currentActorHash(),
      resourceHash: hashResource(this.accessIndexKey, normalizedScope),
      permissions,
      extension: makeExtensionPayload({ scope: scopeToJSON(normalizedScope) })
    };
    if (payloadHash) {
      fields.flags |= EVENT_FLAGS.payloadHash;
      fields.payloadHash = payloadHash;
    }
    await this.#recordEvent(fields);
  }

  async delete(targetPath) {
    this.#assertContentCapable();
    this.#assertWritable();
    this.#checkCurrentAccess({ kind: "file", path: targetPath, recursive: true }, PERMISSIONS.DELETE);
    deleteEntry(this.brickMap, targetPath);
    this.dirty = true;
    await this.#maybeAutoCommit();
  }

  async rename(sourcePath, targetPath) {
    this.#assertContentCapable();
    this.#assertWritable();
    this.#checkCurrentAccess({ kind: "file", path: sourcePath, recursive: true }, PERMISSIONS.WRITE);
    renameEntry(this.brickMap, sourcePath, targetPath);
    this.dirty = true;
    await this.#maybeAutoCommit();
  }

  stat(pathname) {
    this.#assertContentCapable();
    return statEntry(this.brickMap, pathname);
  }

  readDir(pathname) {
    this.#assertContentCapable();
    this.#checkCurrentAccess({ kind: "folder", path: pathname, recursive: false }, PERMISSIONS.LIST);
    return listEntries(this.brickMap, pathname).map((entryPath) => {
      const e = this.brickMap.entries[entryPath];
      return { name: entryPath.split("/").pop(), path: entryPath, type: e.type };
    });
  }

  listFiles(pathname) {
    this.#assertContentCapable();
    this.#checkCurrentAccess({ kind: "folder", path: pathname, recursive: false }, PERMISSIONS.LIST);
    return listByType(this.brickMap, pathname, "file");
  }

  listFolders(pathname) {
    this.#assertContentCapable();
    this.#checkCurrentAccess({ kind: "folder", path: pathname, recursive: false }, PERMISSIONS.LIST);
    return listByType(this.brickMap, pathname, "folder");
  }

  async grantAccess(subjectDID, scope, permissions, options = {}) {
    this.#assertWritable();
    if (!verifyPermissionMask(permissions)) throwError(ERROR_CODES.ERR_INVALID_PERMISSION, "Invalid permission bitmap");
    this.#checkCurrentAccess(scope, PERMISSIONS.GRANT);
    const normalizedScope = normalizeScope(scope);
    const subjectHash = hashDid(this.accessIndexKey, this.didStrategy, subjectDID);
    const resourceHash = hashResource(this.accessIndexKey, normalizedScope);
    const fields = {
      eventType: EVENT_TYPES.GRANT,
      flags:
        EVENT_FLAGS.subjectHash |
        EVENT_FLAGS.resourceHash |
        EVENT_FLAGS.permissions |
        EVENT_FLAGS.actorHash |
        EVENT_FLAGS.actorSignature,
      subjectHash,
      resourceHash,
      permissions
    };
    fields.flags |= EVENT_FLAGS.extension;
    fields.extension = makeExtensionPayload({ scope: scopeToJSON(normalizedScope) });
    if (options.payloadHash) {
      fields.flags |= EVENT_FLAGS.payloadHash;
      fields.payloadHash = Buffer.from(options.payloadHash, "hex");
    }
    const event = await this.#recordEvent(fields);
    const grantId = event.eventHash.toString("hex");
    return { seq: event.seq, grantId };
  }

  async revokeAccess(subjectDID, scope, permissions, options = {}) {
    this.#assertWritable();
    if (!verifyPermissionMask(permissions)) throwError(ERROR_CODES.ERR_INVALID_PERMISSION, "Invalid permission bitmap");
    let effectivePermissions = permissions;
    let effectiveSubjectHash;
    let normalizedScope = normalizeScope(scope);
    if (options.grantId) {
      const target = this.anchorState.activeGrants.get(options.grantId);
      if (!target) throwError(ERROR_CODES.ERR_ACCESS_DENIED, "Grant not found");
      if (target.scope) {
        normalizedScope = normalizeScope(target.scope);
      }
      effectivePermissions = target.permissions;
      effectiveSubjectHash = target.subjectHash;
    }
    this.#checkCurrentAccess(normalizedScope, PERMISSIONS.REVOKE);
    const subjectHash = effectiveSubjectHash || hashDid(this.accessIndexKey, this.didStrategy, subjectDID);
    const resourceHash = hashResource(this.accessIndexKey, normalizedScope);
    const fields = {
      eventType: EVENT_TYPES.REVOKE,
      flags:
        EVENT_FLAGS.subjectHash |
        EVENT_FLAGS.resourceHash |
        EVENT_FLAGS.permissions |
        EVENT_FLAGS.actorHash |
        EVENT_FLAGS.actorSignature,
      subjectHash,
      resourceHash,
      permissions: effectivePermissions
    };
    fields.flags |= EVENT_FLAGS.extension;
    fields.extension = makeExtensionPayload({ scope: scopeToJSON(normalizedScope) });
    if (options.grantId) {
      fields.flags |= EVENT_FLAGS.grantId;
      fields.grantId = Buffer.from(options.grantId, "hex");
    }
    const event = await this.#recordEvent(fields);
    return { seq: event.seq };
  }

  checkAccess(subjectDID, scope, permissions) {
    if (this.mountType === "lza") {
      throwError(ERROR_CODES.ERR_READ_ONLY_DSU, "LZA cannot evaluate access");
    }
    const normalizedScope = normalizeScope(scope);
    const subjectHash = hashDid(this.accessIndexKey, this.didStrategy, subjectDID);
    return buildAccessDecision(this.anchorState, subjectHash, normalizedScope, permissions);
  }

  listAccess() {
    return Array.from(this.anchorState.activeGrants.values()).map((grant) => ({
      grantId: grant.id,
      subjectHash: grant.subjectHash.toString("hex"),
      resourceHash: grant.resourceHash.toString("hex"),
      permissions: grant.permissions,
      scope: grant.scope || null
    }));
  }

  async appendProvenance(resource, provenanceInput, options = {}) {
    this.#assertWritable();
    this.#checkCurrentAccess(resource, PERMISSIONS.PROVENANCE_APPEND);

    const { profileId, profileVersion, payloadFormat, canonicalPayload, externalReferences, versionSeq } = provenanceInput;
    if (!profileId) throwError(ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE, "profileId is required");

    const profile = getProfile(profileId);
    if (!profile) throwError(ERROR_CODES.ERR_UNSUPPORTED_PROFILE, `Unknown profileId: 0x${profileId.toString(16)}`);

    const resourceHashHex = resource?.path || resource?.kind
      ? hashResource(this.accessIndexKey, normalizeScope(resource)).toString("hex")
      : null;

    const v1 = buildProvenancePayloadV1({
      profileId,
      profileVersion: profileVersion || profile.version,
      payloadFormat:  payloadFormat || profile.payloadFormats[0],
      canonicalPayload,
      resourceHash: resourceHashHex ? Buffer.from(resourceHashHex, "hex") : null,
      versionSeq:   versionSeq != null ? versionSeq : null,
      externalReferences: externalReferences || null
    });

    const validationErrors = validateStructural(v1);
    if (validationErrors.length > 0) {
      throwError(ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE, validationErrors.join("; "));
    }

    const plain = encodeProvenancePayload(v1);
    const encrypted = aes256gcmEncrypt(this.brickMapKey, plain, Buffer.from("provenance"));
    const envelope = Buffer.concat([encrypted.nonce, encrypted.ciphertext, encrypted.tag]);
    const payloadHashHex = await writeBrick(this.storageRoot, envelope);

    const fields = {
      eventType: EVENT_TYPES.PROVENANCE,
      flags: EVENT_FLAGS.payloadHash | EVENT_FLAGS.actorHash | EVENT_FLAGS.actorSignature
    };
    fields.payloadHash = Buffer.from(payloadHashHex, "hex");

    const extensionData = {};
    if (resource?.path || resource?.kind) {
      const normalizedResource = normalizeScope(resource);
      fields.flags |= EVENT_FLAGS.resourceHash;
      fields.resourceHash = hashResource(this.accessIndexKey, normalizedResource);
      extensionData.scope = scopeToJSON(normalizedResource);
    }
    if (Object.keys(extensionData).length > 0) {
      fields.flags |= EVENT_FLAGS.extension;
      fields.extension = makeExtensionPayload(extensionData);
    }

    const event = await this.#recordEvent(fields);
    if (options.attachToCommit) {
      await this.#commitVersion(Buffer.from(payloadHashHex, "hex"));
    }
    return {
      seq:                    event.seq,
      payloadHash:            payloadHashHex,
      canonicalPayloadHash:   v1.canonicalPayloadHash.toString("hex"),
      profileId,
      profileName:            profile.name
    };
  }

  getHistory(query = {}) {
    let out = this.events.slice();
    if (query.eventType) out = out.filter((event) => event.eventType === query.eventType);
    return out.map((event) => ({
      seq: event.seq,
      timestampMs: event.timestampMs,
      eventType: event.eventType,
      eventHash: event.eventHash.toString("hex"),
      actorHash: event.actorHash?.toString("hex"),
      resourceHash: event.resourceHash?.toString("hex"),
      payloadHash: event.payloadHash?.toString("hex")
    }));
  }

  async getProvenance(query = {}) {
    const records = [];
    for (const event of this.events) {
      if (event.eventType !== EVENT_TYPES.PROVENANCE || !event.payloadHash) continue;
      const payloadHashHex = event.payloadHash.toString("hex");
      const envelope = await readBrick(this.storageRoot, payloadHashHex);
      const nonce = envelope.subarray(0, 12);
      const tag = envelope.subarray(envelope.length - 16);
      const ciphertext = envelope.subarray(12, envelope.length - 16);
      const plain = aes256gcmDecrypt(this.brickMapKey, nonce, ciphertext, tag, Buffer.from("provenance"));
      const v1 = decodeProvenancePayload(plain);

      const profile = getProfile(v1.profileId);
      records.push({
        seq:                  event.seq,
        payloadHash:          payloadHashHex,
        profileId:            v1.profileId,
        profileName:          profile?.name || "UNKNOWN",
        profileVersion:       v1.profileVersion,
        payloadFormat:        v1.payloadFormat,
        createdAt:            v1.createdAt,
        canonicalPayloadHash: v1.canonicalPayloadHash,
        resourceHash:         v1.resourceHash,
        versionSeq:           v1.versionSeq,
        canonicalPayload:     v1.canonicalPayload,
        externalReferences:   v1.externalReferences
      });
    }

    let out = records;
    if (query.payloadHash)  out = out.filter((r) => r.payloadHash === query.payloadHash);
    if (query.resourceHash) out = out.filter((r) => r.resourceHash === query.resourceHash);
    if (query.profileId)    out = out.filter((r) => r.profileId === query.profileId);
    return out;
  }

  async validateProvenance(resourceOrVersion, options = {}) {
    const records = await this.getProvenance({
      resourceHash: resourceOrVersion?.resourceHash,
      profileId:    resourceOrVersion?.profileId
    });

    const report = {
      valid: true,
      totalRecords: records.length,
      results: []
    };

    for (const rec of records) {
      const result = { seq: rec.seq, payloadHash: rec.payloadHash, valid: true, errors: [], level: null };

      // Level 1: cryptographic – verify canonicalPayloadHash
      const cpBuf = Buffer.isBuffer(rec.canonicalPayload) ? rec.canonicalPayload : Buffer.from(rec.canonicalPayload);
      const recomputed = sha256(cpBuf).toString("hex");
      if (recomputed !== rec.canonicalPayloadHash) {
        result.valid = false;
        result.level = "cryptographic";
        result.errors.push("canonicalPayloadHash mismatch – payload content corrupted");
      }

      // Level 2+3: structural + domain
      if (result.valid || options.continueOnCryptoError) {
        const profile = getProfile(rec.profileId);
        if (!profile) {
          result.valid = false;
          result.level = "structural";
          result.errors.push(`unknown profileId: 0x${rec.profileId?.toString(16).padStart(4, "0")}`);
        } else {
          const v1 = {
            profileId:      rec.profileId,
            profileVersion: rec.profileVersion,
            payloadFormat:  rec.payloadFormat,
            canonicalPayload: cpBuf
          };
          const errs = validateStructural(v1);
          if (errs.length > 0) {
            result.valid = false;
            result.level = result.level || "structural";
            result.errors.push(...errs);
          }
        }
      }

      if (!result.valid) report.valid = false;
      report.results.push(result);
    }

    return report;
  }

  listProvenanceProfiles() {
    return listProfiles();
  }

  getProvenancePolicy() {
    return JSON.parse(JSON.stringify(
      this.brickMap?.manifest?.provenancePolicy || {
        requiredProfiles: [],
        operationProfileMap: {},
        regulatedMode: { gxp: false, glp: false, healthcare: false },
        minimumPayloadFields: {},
        auditMode: "no-read-audit"
      }
    ));
  }

  async updateProvenancePolicy(policyUpdate, options = {}) {
    this.#assertWritable();
    this.#checkCurrentAccess({ kind: "DSU", path: "/" }, PERMISSIONS.ADMIN);

    if (!this.brickMap.manifest) this.brickMap.manifest = {};
    if (!this.brickMap.manifest.provenancePolicy) this.brickMap.manifest.provenancePolicy = {};

    const policy = this.brickMap.manifest.provenancePolicy;
    if (policyUpdate.requiredProfiles !== undefined)    policy.requiredProfiles    = policyUpdate.requiredProfiles;
    if (policyUpdate.operationProfileMap !== undefined) policy.operationProfileMap = policyUpdate.operationProfileMap;
    if (policyUpdate.regulatedMode !== undefined)       Object.assign(policy.regulatedMode || (policy.regulatedMode = {}), policyUpdate.regulatedMode);
    if (policyUpdate.minimumPayloadFields !== undefined) policy.minimumPayloadFields = policyUpdate.minimumPayloadFields;
    if (policyUpdate.auditMode !== undefined)           policy.auditMode = policyUpdate.auditMode;

    this.dirty = true;
    const fields = {
      eventType: EVENT_TYPES.POLICY_UPDATE,
      flags: EVENT_FLAGS.actorHash | EVENT_FLAGS.actorSignature | EVENT_FLAGS.extension,
      extension: makeExtensionPayload({ policyTarget: "provenancePolicy" })
    };
    const event = await this.#recordEvent(fields);
    await this.#commitVersion();

    return { seq: event.seq, policy: this.getProvenancePolicy() };
  }

  async verifyAnchor() {
    const events = await readAndVerifyAnchor(
      this.storageRoot,
      this.domain,
      this.anchorIdHex,
      this.anchorPublic,
      this.didStrategy,
      this.accessIndexKey
    );
    return {
      valid: true,
      latestSeq: events.length ? events[events.length - 1].seq : -1,
      latestEventHash: events.length ? events[events.length - 1].eventHash.toString("hex") : Buffer.alloc(32).toString("hex")
    };
  }

  async runGarbageCollection() {
    this.#assertWritable();
    this.#checkCurrentAccess({ kind: "DSU", path: "/" }, PERMISSIONS.ADMIN);
    const mode = this.brickMap?.manifest?.retentionMode || "keep-all";
    const referenced = new Set();
    const addCurrentBrickMapAndFiles = () => {
      if (this.anchorState.latestBrickMapHash) referenced.add(this.anchorState.latestBrickMapHash);
      for (const entry of Object.values(this.brickMap.entries || {})) {
        if (entry.type !== "file" || !Array.isArray(entry.chunks)) continue;
        for (const chunk of entry.chunks) referenced.add(chunk.brickHash);
      }
    };

    if (mode === "keep-all") {
      for (const event of this.events) {
        if (event.brickMapHash) referenced.add(event.brickMapHash.toString("hex"));
        if (event.payloadHash) referenced.add(event.payloadHash.toString("hex"));
      }
      addCurrentBrickMapAndFiles();
      const all = await listBrickHashes(this.storageRoot);
      return {
        mode,
        removedBricks: 0,
        retainedBricks: all.length,
        referencedBricks: referenced.size
      };
    }

    if (mode === "retention-window") {
      const keepVersions = 10;
      const versionHashes = this.events
        .filter((event) => event.eventType === EVENT_TYPES.VERSION_COMMIT && event.brickMapHash)
        .map((event) => event.brickMapHash.toString("hex"))
        .slice(-keepVersions);
      for (const hash of versionHashes) {
        referenced.add(hash);
        const historicalBrickMap = await MountedLightDSU.decryptBrickMap(this.storageRoot, hash, this.brickMapKey);
        for (const entry of Object.values(historicalBrickMap.entries || {})) {
          if (entry.type !== "file" || !Array.isArray(entry.chunks)) continue;
          for (const chunk of entry.chunks) referenced.add(chunk.brickHash);
        }
      }
      for (const event of this.events) {
        if (event.payloadHash) referenced.add(event.payloadHash.toString("hex"));
      }
      addCurrentBrickMapAndFiles();
    } else {
      addCurrentBrickMapAndFiles();
      for (const event of this.events) {
        if (event.payloadHash) referenced.add(event.payloadHash.toString("hex"));
      }
    }

    const all = await listBrickHashes(this.storageRoot);
    let removed = 0;
    for (const hash of all) {
      if (!referenced.has(hash)) {
        await removeBrick(this.storageRoot, hash);
        removed += 1;
      }
    }
    return {
      mode,
      removedBricks: removed,
      retainedBricks: all.length - removed,
      referencedBricks: referenced.size
    };
  }

  exportState() {
    return {
      anchorId: this.anchorIdHex,
      mode: this.mountType,
      latestSeq: this.anchorState.latestSeq
    };
  }

  getLatestEventHash() {
    return this.anchorState.latestEventHash.toString("hex");
  }

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

  static async decryptBrickMap(storageRoot, brickMapHashHex, brickMapKey) {
    const envelope = await readBrick(storageRoot, brickMapHashHex);
    const nonce = envelope.subarray(0, 12);
    const tag = envelope.subarray(envelope.length - 16);
    const ciphertext = envelope.subarray(12, envelope.length - 16);
    const plain = aes256gcmDecrypt(brickMapKey, nonce, ciphertext, tag, Buffer.from("brickmap"));
    return deserializeBrickMap(plain);
  }
}

module.exports = { MountedLightDSU };
