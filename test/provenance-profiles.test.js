"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const os = require("node:os");
const fs = require("node:fs/promises");

const { LightDSUEngine, DefaultDidStrategy, PROVENANCE_PROFILES, PAYLOAD_FORMAT, PROVENANCE_EVENT_KIND, ERROR_CODES } = require("../src/index");
const { EVENT_TYPES, EVENT_FLAGS } = require("../src/constants");
const { encodeProvenancePayload, decodeProvenancePayload, buildProvenancePayloadV1 } = require("../src/provenancePayloadCodec");
const { listProfiles, getProfile, validateStructural } = require("../src/provenanceProfiles");
const { encodeActorMessage } = require("../src/actorMessage");
const { hashDid } = require("../src/access");
const { appendAnchorLine, writeBrick } = require("../src/storage");
const { encodeEventPayload } = require("../src/eventCodec");
const { makeEventSSI } = require("../src/ssi");
const { sha256, aes256gcmEncrypt, ed25519Sign } = require("../src/crypto/primitives");

async function makeEngine(dir, did) {
  const strategy = new DefaultDidStrategy(did);
  return LightDSUEngine.open({
    storageRoot: dir,
    domain: "test",
    didStrategy: strategy,
    currentDID: did
  });
}

// ---------------------------------------------------------------------------
// Profile registry
// ---------------------------------------------------------------------------

test("listProvenanceProfiles returns all 10 profiles", () => {
  const profiles = listProfiles();
  assert.equal(profiles.length, 10);
  const names = profiles.map((p) => p.name);
  assert.ok(names.includes("LIGHTDSU_MINIMAL"));
  assert.ok(names.includes("W3C_PROV"));
  assert.ok(names.includes("FHIR_PROVENANCE"));
  assert.ok(names.includes("FHIR_AUDIT_EVENT"));
  assert.ok(names.includes("GXP_AUDIT_TRAIL"));
  assert.ok(names.includes("RO_CRATE"));
  assert.ok(names.includes("GA4GH_DATA_USE"));
  assert.ok(names.includes("ISO_8000_PROVENANCE"));
  assert.ok(names.includes("OECD_GLP_DATA_INTEGRITY"));
  assert.ok(names.includes("AI_ML_EXPERIMENT"));
});

test("getProfile returns correct descriptor", () => {
  const p = getProfile(PROVENANCE_PROFILES.LIGHTDSU_MINIMAL);
  assert.equal(p.name, "LIGHTDSU_MINIMAL");
  assert.ok(Array.isArray(p.requiredFields));
  assert.ok(p.requiredFields.includes("eventKind"));
  assert.ok(typeof p.validator === "function");
});

test("getProfile returns null for unknown profileId", () => {
  assert.equal(getProfile(0xffff), null);
});

// ---------------------------------------------------------------------------
// ProvenancePayloadV1 codec
// ---------------------------------------------------------------------------

test("ProvenancePayloadV1 roundtrip without optional fields", () => {
  const cp = Buffer.from(JSON.stringify({ hello: "world" }));
  const v1 = buildProvenancePayloadV1({
    profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: cp
  });
  const encoded = encodeProvenancePayload(v1);
  const decoded = decodeProvenancePayload(encoded);

  assert.equal(decoded.profileId, PROVENANCE_PROFILES.LIGHTDSU_MINIMAL);
  assert.equal(decoded.profileVersion, 1);
  assert.equal(decoded.payloadFormat, PAYLOAD_FORMAT.CANONICAL_JSON);
  assert.equal(decoded.canonicalPayloadHash, sha256(cp).toString("hex"));
  assert.equal(decoded.canonicalPayload.toString(), cp.toString());
  assert.equal(decoded.resourceHash, null);
  assert.equal(decoded.versionSeq, null);
});

test("ProvenancePayloadV1 roundtrip with all optional fields", () => {
  const cp = Buffer.from("test-canonical-data");
  const resourceHash = Buffer.alloc(32, 0xab);
  const refs = [{ type: "doi", ref: "https://doi.org/10.1234/x", hash: "aa".repeat(32) }];

  const v1 = buildProvenancePayloadV1({
    profileId:      PROVENANCE_PROFILES.AI_ML_EXPERIMENT,
    profileVersion: 2,
    payloadFormat:  PAYLOAD_FORMAT.CBOR,
    canonicalPayload: cp,
    resourceHash,
    versionSeq: 7,
    externalReferences: refs
  });
  const decoded = decodeProvenancePayload(encodeProvenancePayload(v1));

  assert.equal(decoded.profileId, PROVENANCE_PROFILES.AI_ML_EXPERIMENT);
  assert.equal(decoded.profileVersion, 2);
  assert.equal(decoded.payloadFormat, PAYLOAD_FORMAT.CBOR);
  assert.equal(decoded.resourceHash, resourceHash.toString("hex"));
  assert.equal(decoded.versionSeq, 7);
  assert.ok(Array.isArray(decoded.externalReferences));
  assert.equal(decoded.externalReferences[0].type, "doi");
  assert.equal(decoded.externalReferences[0].ref, "https://doi.org/10.1234/x");
});

test("decodeProvenancePayload rejects unknown version tag", () => {
  const buf = Buffer.alloc(4);
  buf.writeUInt8(0xff, 0); // bad version tag
  assert.throws(() => decodeProvenancePayload(buf), { code: ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE });
});

test("buildProvenancePayloadV1 canonicalizes object payloads before hashing", () => {
  const left = buildProvenancePayloadV1({
    profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: { b: 2, a: 1 }
  });
  const right = buildProvenancePayloadV1({
    profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: { a: 1, b: 2 }
  });

  assert.equal(left.canonicalPayload.toString("utf8"), "{\"a\":1,\"b\":2}");
  assert.equal(left.canonicalPayloadHash.toString("hex"), right.canonicalPayloadHash.toString("hex"));
});

// ---------------------------------------------------------------------------
// Profile validators
// ---------------------------------------------------------------------------

test("LIGHTDSU_MINIMAL validator: valid payload passes", () => {
  const profile = getProfile(PROVENANCE_PROFILES.LIGHTDSU_MINIMAL);
  const cp = Buffer.from(JSON.stringify({
    eventKind: PROVENANCE_EVENT_KIND.ANALYZE,
    operation: "runAnalysis",
    actorHash: "did:example:alice",
    timestampMs: Date.now(),
    method: "ml-pipeline",
    softwareAgent: "python",
    softwareVersion: "3.11"
  }));
  const errors = profile.validator(cp, null);
  assert.deepEqual(errors, []);
});

test("LIGHTDSU_MINIMAL validator: missing fields produce errors", () => {
  const profile = getProfile(PROVENANCE_PROFILES.LIGHTDSU_MINIMAL);
  const cp = Buffer.from(JSON.stringify({ eventKind: "ANALYZE" }));
  const errors = profile.validator(cp, null);
  assert.ok(errors.length > 0);
  assert.ok(errors.some((e) => e.includes("operation")));
});

test("LIGHTDSU_MINIMAL validator: unknown eventKind produces error", () => {
  const profile = getProfile(PROVENANCE_PROFILES.LIGHTDSU_MINIMAL);
  const cp = Buffer.from(JSON.stringify({
    eventKind: "INVALID_KIND",
    operation: "op",
    actorHash: "hash",
    timestampMs: 1,
    method: "m",
    softwareAgent: "a",
    softwareVersion: "v"
  }));
  const errors = profile.validator(cp, null);
  assert.ok(errors.some((e) => e.includes("eventKind")));
});

test("W3C_PROV validator: entity/activity/agent required", () => {
  const profile = getProfile(PROVENANCE_PROFILES.W3C_PROV);
  const valid = profile.validator(Buffer.from(JSON.stringify({
    entity: { id: "x" },
    activity: { id: "y" },
    agent: { id: "z" }
  })), null);
  assert.deepEqual(valid, []);

  const invalid = profile.validator(Buffer.from(JSON.stringify({ entity: { id: "x" } })), null);
  assert.ok(invalid.some((e) => e.includes("activity")));
  assert.ok(invalid.some((e) => e.includes("agent")));
});

test("FHIR_PROVENANCE validator: requires resourceType=Provenance", () => {
  const profile = getProfile(PROVENANCE_PROFILES.FHIR_PROVENANCE);
  const valid = { resourceType: "Provenance", target: [{}], recorded: "2024-01-01", agent: [{}] };
  assert.deepEqual(profile.validator(Buffer.from(JSON.stringify(valid)), null), []);

  const badType = { ...valid, resourceType: "Patient" };
  const errs = profile.validator(Buffer.from(JSON.stringify(badType)), null);
  assert.ok(errs.some((e) => e.includes("resourceType")));
});

test("FHIR_AUDIT_EVENT validator: requires resourceType=AuditEvent", () => {
  const profile = getProfile(PROVENANCE_PROFILES.FHIR_AUDIT_EVENT);
  const valid = { resourceType: "AuditEvent", type: {}, recorded: "2024-01-01", agent: [{}], source: {} };
  assert.deepEqual(profile.validator(Buffer.from(JSON.stringify(valid)), null), []);
});

test("GXP_AUDIT_TRAIL validator: changeReason required for UPDATE/DELETE", () => {
  const profile = getProfile(PROVENANCE_PROFILES.GXP_AUDIT_TRAIL);
  const base = {
    regulatedRecordType: "batch-record",
    operation: "UPDATE",
    actorHash: "did:example:operator",
    timestampMs: Date.now(),
    resourceHash: "aa".repeat(32),
    changeReason: "Correcting transcription error",
    systemId: "lims-v2",
    systemVersion: "2.1",
    reviewStatus: "pending",
    retentionClass: "GMP-5yr"
  };
  assert.deepEqual(profile.validator(Buffer.from(JSON.stringify(base)), null), []);

  const missingReason = { ...base, changeReason: undefined };
  const errs = profile.validator(Buffer.from(JSON.stringify(missingReason)), null);
  assert.ok(errs.some((e) => e.includes("changeReason")));
});

test("RO_CRATE validator: requires roCrateVersion, rootDatasetId, metadataJsonLd with @context and @graph", () => {
  const profile = getProfile(PROVENANCE_PROFILES.RO_CRATE);
  const valid = {
    roCrateVersion: "1.2",
    rootDatasetId: "./",
    metadataJsonLd: { "@context": "https://w3id.org/ro/crate/1.2/context", "@graph": [] }
  };
  assert.deepEqual(profile.validator(Buffer.from(JSON.stringify(valid)), null), []);

  const missingGraph = { ...valid, metadataJsonLd: { "@context": "ctx" } };
  const errs = profile.validator(Buffer.from(JSON.stringify(missingGraph)), null);
  assert.ok(errs.some((e) => e.includes("@graph")));
});

test("GA4GH_DATA_USE validator: duoTerms must be array", () => {
  const profile = getProfile(PROVENANCE_PROFILES.GA4GH_DATA_USE);
  const valid = {
    datasetId: "ds-001",
    duoTerms: ["DUO:0000007", "DUO:0000042"],
    permittedUses: ["research"],
    prohibitedUses: ["commercial"],
    policyVersion: "v1"
  };
  assert.deepEqual(profile.validator(Buffer.from(JSON.stringify(valid)), null), []);

  const badTerms = { ...valid, duoTerms: "DUO:0000007" };
  const errs = profile.validator(Buffer.from(JSON.stringify(badTerms)), null);
  assert.ok(errs.some((e) => e.includes("duoTerms")));
});

test("AI_ML_EXPERIMENT validator: all required fields", () => {
  const profile = getProfile(PROVENANCE_PROFILES.AI_ML_EXPERIMENT);
  const valid = {
    experimentId: "exp-001",
    runId: "run-abc",
    task: "classification",
    datasetHashes: ["aabb"],
    parametersHash: "ccdd",
    softwareEnvironment: { python: "3.11" },
    outputHashes: ["eeff"]
  };
  assert.deepEqual(profile.validator(Buffer.from(JSON.stringify(valid)), null), []);

  const missing = { ...valid };
  delete missing.outputHashes;
  const errs = profile.validator(Buffer.from(JSON.stringify(missing)), null);
  assert.ok(errs.some((e) => e.includes("outputHashes")));
});

// ---------------------------------------------------------------------------
// DSU appendProvenance / getProvenance / validateProvenance
// ---------------------------------------------------------------------------

test("appendProvenance with LIGHTDSU_MINIMAL stores and retrieves", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  const canonicalPayload = JSON.stringify({
    eventKind: "CREATE",
    operation: "writeFile",
    actorHash: "did:example:alice",
    timestampMs: Date.now(),
    method: "dsu.writeFile",
    softwareAgent: "lightdsu-test",
    softwareVersion: "1.0.0",
    inputHashes: [],
    outputHashes: ["aabb"]
  });

  const result = await dsu.appendProvenance(
    { kind: "DSU", path: "/", recursive: false },
    {
      profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
      payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
      canonicalPayload
    }
  );

  assert.ok(result.payloadHash);
  assert.ok(result.canonicalPayloadHash);
  assert.equal(result.profileName, "LIGHTDSU_MINIMAL");

  const records = await dsu.getProvenance();
  assert.equal(records.length, 1);
  assert.equal(records[0].profileName, "LIGHTDSU_MINIMAL");
  const parsedPayload = JSON.parse(records[0].canonicalPayload.toString());
  assert.equal(parsedPayload.eventKind, "CREATE");
});

test("appendProvenance rejects unknown profileId", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await assert.rejects(
    () => dsu.appendProvenance({ kind: "DSU", path: "/" }, {
      profileId: 0xffff,
      canonicalPayload: "{}"
    }),
    { code: ERROR_CODES.ERR_UNSUPPORTED_PROFILE }
  );
});

test("appendProvenance rejects missing profileId", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await assert.rejects(
    () => dsu.appendProvenance({ kind: "DSU", path: "/" }, { canonicalPayload: "{}" }),
    { code: ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE }
  );
});

test("validateProvenance: three-level validation passes for valid payload", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await dsu.appendProvenance({ kind: "DSU", path: "/" }, {
    profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: JSON.stringify({
      eventKind: "IMPORT",
      operation: "importData",
      actorHash: "did:example:alice",
      timestampMs: Date.now(),
      method: "csv-import",
      softwareAgent: "importer",
      softwareVersion: "2.0"
    })
  });

  const report = await dsu.validateProvenance({});
  assert.ok(report.valid);
  assert.equal(report.totalRecords, 1);
  assert.equal(report.results[0].valid, true);
  assert.deepEqual(report.results[0].errors, []);
});

test("appendProvenance rejects structurally invalid LIGHTDSU_MINIMAL payloads", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await assert.rejects(
    () => dsu.appendProvenance({ kind: "DSU", path: "/" }, {
      profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
      payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
      canonicalPayload: { eventKind: "ANALYZE" }
    }),
    { code: ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE }
  );
});

test("appendProvenance rejects GXP payloads that miss changeReason for DELETE", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await assert.rejects(
    () => dsu.appendProvenance({ kind: "DSU", path: "/" }, {
      profileId: PROVENANCE_PROFILES.GXP_AUDIT_TRAIL,
      payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
      canonicalPayload: {
        regulatedRecordType: "analytical-result",
        operation: "DELETE",
        actorHash: "did:example:operator",
        timestampMs: Date.now(),
        resourceHash: "aa".repeat(32),
        systemId: "lims",
        systemVersion: "1.0",
        reviewStatus: "pending",
        retentionClass: "GMP-5yr"
      }
    }),
    { code: ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE }
  );
});

test("multiple profiles stored in same DSU, filter by profileId", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await dsu.appendProvenance({ kind: "DSU", path: "/" }, {
    profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: JSON.stringify({
      eventKind: "CREATE", operation: "op", actorHash: "a",
      timestampMs: 1, method: "m", softwareAgent: "a", softwareVersion: "v"
    })
  });

  await dsu.appendProvenance({ kind: "DSU", path: "/" }, {
    profileId: PROVENANCE_PROFILES.AI_ML_EXPERIMENT,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: JSON.stringify({
      experimentId: "e1", runId: "r1", task: "classify",
      datasetHashes: ["aa"], parametersHash: "bb",
      softwareEnvironment: { py: "3" }, outputHashes: ["cc"]
    })
  });

  const all = await dsu.getProvenance();
  assert.equal(all.length, 2);

  const minimal = await dsu.getProvenance({ profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL });
  assert.equal(minimal.length, 1);
  assert.equal(minimal[0].profileName, "LIGHTDSU_MINIMAL");

  const mlProf = await dsu.getProvenance({ profileId: PROVENANCE_PROFILES.AI_ML_EXPERIMENT });
  assert.equal(mlProf.length, 1);
  assert.equal(mlProf[0].profileName, "AI_ML_EXPERIMENT");
});

// ---------------------------------------------------------------------------
// Provenance policy management
// ---------------------------------------------------------------------------

test("getProvenancePolicy returns default policy from new DSU", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  const policy = dsu.getProvenancePolicy();
  assert.ok(Array.isArray(policy.requiredProfiles));
  assert.equal(policy.requiredProfiles.length, 0);
  assert.ok(typeof policy.regulatedMode === "object");
  assert.equal(policy.regulatedMode.gxp, false);
});

test("updateProvenancePolicy persists policy changes across reload", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu, lkeySSI } = await engine.createDSU();

  const result = await dsu.updateProvenancePolicy({
    requiredProfiles: [PROVENANCE_PROFILES.LIGHTDSU_MINIMAL],
    regulatedMode: { gxp: true, healthcare: true }
  });
  assert.ok(result.seq > 0);
  assert.deepEqual(result.policy.requiredProfiles, [PROVENANCE_PROFILES.LIGHTDSU_MINIMAL]);
  assert.equal(result.policy.regulatedMode.gxp, true);

  // Reload and verify persistence
  const dsu2 = await engine.loadDSU(lkeySSI);
  const policy2 = dsu2.getProvenancePolicy();
  assert.deepEqual(policy2.requiredProfiles, [PROVENANCE_PROFILES.LIGHTDSU_MINIMAL]);
  assert.equal(policy2.regulatedMode.gxp, true);
  assert.equal(policy2.regulatedMode.healthcare, true);
});

test("listProvenanceProfiles accessible on DSU instance", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  const profiles = dsu.listProvenanceProfiles();
  assert.equal(profiles.length, 10);
});

// ---------------------------------------------------------------------------
// External references roundtrip
// ---------------------------------------------------------------------------

test("appendProvenance with externalReferences roundtrips correctly", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await dsu.appendProvenance({ kind: "DSU", path: "/" }, {
    profileId: PROVENANCE_PROFILES.AI_ML_EXPERIMENT,
    payloadFormat: PAYLOAD_FORMAT.CANONICAL_JSON,
    canonicalPayload: JSON.stringify({
      experimentId: "exp-001", runId: "run-xyz", task: "regression",
      datasetHashes: ["aabb"], parametersHash: "ccdd",
      softwareEnvironment: { python: "3.11", torch: "2.0" },
      outputHashes: ["eeff"]
    }),
    externalReferences: [
      { type: "doi", ref: "https://doi.org/10.1234/experiment", hash: "ff".repeat(32) },
      { type: "mlflow", ref: "mlflow://experiment/42", hash: null }
    ]
  });

  const records = await dsu.getProvenance({ profileId: PROVENANCE_PROFILES.AI_ML_EXPERIMENT });
  assert.equal(records.length, 1);
  assert.ok(Array.isArray(records[0].externalReferences));
  assert.equal(records[0].externalReferences[0].type, "doi");
  assert.equal(records[0].externalReferences[1].type, "mlflow");
  assert.equal(records[0].externalReferences[1].hash, null);
});

test("getProvenance surfaces undecodable payloads instead of treating them as legacy", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu, lkeySSI } = await engine.createDSU();

  const invalidPayload = Buffer.from([0xff, 0x00, 0x00, 0x00]);
  const encrypted = aes256gcmEncrypt(dsu.brickMapKey, invalidPayload, Buffer.from("provenance"));
  const envelope = Buffer.concat([encrypted.nonce, encrypted.ciphertext, encrypted.tag]);
  const payloadHashHex = await writeBrick(dir, envelope);

  const event = {
    eventType: EVENT_TYPES.PROVENANCE,
    flags: EVENT_FLAGS.payloadHash | EVENT_FLAGS.actorHash | EVENT_FLAGS.actorSignature,
    seq: dsu.anchorState.latestSeq + 1,
    timestampMs: Date.now(),
    prevEventHash: dsu.anchorState.latestEventHash,
    payloadHash: Buffer.from(payloadHashHex, "hex")
  };
  event.actorHash = hashDid(dsu.accessIndexKey, dsu.didStrategy, dsu.currentDID);
  event.actorSignature = Buffer.from(dsu.didStrategy.sign(encodeActorMessage(event)));

  const payload = encodeEventPayload(event);
  const anchorSignature = ed25519Sign(dsu.anchorPrivate, payload);
  await appendAnchorLine(dir, dsu.anchorIdHex, makeEventSSI("test", payload, anchorSignature));

  const reloaded = await engine.loadDSU(lkeySSI);
  await assert.rejects(() => reloaded.getProvenance(), { code: ERROR_CODES.ERR_INVALID_PROVENANCE_PROFILE });
});

// ---------------------------------------------------------------------------
// FHIR profiles
// ---------------------------------------------------------------------------

test("FHIR_PROVENANCE: full payload accepted and validated", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ldsu-prov-"));
  const engine = await makeEngine(dir, "did:example:clinician");
  const { dsu } = await engine.createDSU();

  const fhirProv = {
    resourceType: "Provenance",
    target: [{ reference: "Observation/obs-001" }],
    recorded: new Date().toISOString(),
    agent: [{ who: { reference: "Practitioner/pract-001" } }],
    activity: { coding: [{ system: "http://terminology.hl7.org/CodeSystem/v3-DataOperation", code: "CREATE" }] },
    entity: [{ role: "source", what: { reference: "DocumentReference/doc-001" } }]
  };

  const result = await dsu.appendProvenance({ kind: "DSU", path: "/" }, {
    profileId: PROVENANCE_PROFILES.FHIR_PROVENANCE,
    payloadFormat: PAYLOAD_FORMAT.FHIR_JSON,
    canonicalPayload: JSON.stringify(fhirProv)
  });
  assert.ok(result.payloadHash);

  const report = await dsu.validateProvenance({});
  assert.ok(report.valid, `Expected valid; errors: ${JSON.stringify(report.results[0]?.errors)}`);
});

// ---------------------------------------------------------------------------
// validateStructural (unit tests on the structural validator)
// ---------------------------------------------------------------------------

test("validateStructural rejects unsupported payloadFormat", () => {
  const v1 = {
    profileId: PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
    profileVersion: 1,
    payloadFormat: PAYLOAD_FORMAT.FHIR_JSON, // not supported by LIGHTDSU_MINIMAL
    canonicalPayload: Buffer.from("{}")
  };
  const errs = validateStructural(v1);
  assert.ok(errs.some((e) => e.includes("payloadFormat")));
});

test("validateStructural rejects unknown profileId", () => {
  const errs = validateStructural({ profileId: 0x9999, profileVersion: 1, payloadFormat: 0x02, canonicalPayload: Buffer.from("{}") });
  assert.ok(errs.some((e) => e.includes("unknown profileId")));
});

test("validateStructural passes for all known profiles with minimal valid payloads", () => {
  const cases = [
    [PROVENANCE_PROFILES.W3C_PROV, { entity: {}, activity: {}, agent: {} }],
    [PROVENANCE_PROFILES.FHIR_PROVENANCE, { resourceType: "Provenance", target: [{}], recorded: "2024", agent: [{}] }],
    [PROVENANCE_PROFILES.FHIR_AUDIT_EVENT, { resourceType: "AuditEvent", type: {}, recorded: "2024", agent: [{}], source: {} }],
    [PROVENANCE_PROFILES.GA4GH_DATA_USE, { datasetId: "ds-1", duoTerms: ["DUO:1"], permittedUses: [], prohibitedUses: [], policyVersion: "v1" }],
    [PROVENANCE_PROFILES.ISO_8000_PROVENANCE, { masterDataObjectId: "m1", characteristicId: "c1", characteristicValueHash: "h", source: "s", acquisitionMethod: "a", responsibleParty: "p", timestampMs: 1, qualityStatus: "ok", validationStatus: "ok" }],
    [PROVENANCE_PROFILES.OECD_GLP_DATA_INTEGRITY, { studyId: "s1", studyPhase: "p", rawDataReference: "r", metadataCompleteness: "full", acquisitionSystem: "sys", processingStep: "raw", operator: "op", timestampMs: 1, dataCriticality: "high", dataLifecycleStage: "raw", integrityAssessment: "pass" }]
  ];

  for (const [profileId, payload] of cases) {
    const profile = getProfile(profileId);
    const v1 = {
      profileId,
      profileVersion: 1,
      payloadFormat: profile.payloadFormats[0],
      canonicalPayload: Buffer.from(JSON.stringify(payload))
    };
    const errs = validateStructural(v1);
    assert.deepEqual(errs, [], `Profile ${profile.name} should pass with minimal valid payload, got: ${errs}`);
  }
});
