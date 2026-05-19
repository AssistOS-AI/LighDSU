"use strict";

/**
 * LightDSU Provenance Profile Registry.
 *
 * Each profile declares:
 *   profileId              numeric constant
 *   name                   string label
 *   version                u16 (current supported version)
 *   payloadFormats         supported payloadFormat values
 *   requiredFields         fields that MUST be present in canonicalPayload
 *   optionalFields         fields that MAY be present
 *   validator              (canonicalPayload: Buffer, parsed: object|null) => string[] errors
 *   externalStandardRef    citation URL / standard identifier
 */

const { PROVENANCE_PROFILES, PAYLOAD_FORMAT, PROVENANCE_EVENT_KIND } = require("./constants");

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function parseIfJson(canonicalPayload) {
  try {
    return JSON.parse(canonicalPayload.toString("utf8"));
  } catch {
    return null;
  }
}

function missingFields(obj, fields) {
  if (!obj || typeof obj !== "object") return fields.slice();
  return fields.filter((f) => obj[f] == null);
}

function validatorFor(requiredFields) {
  return function defaultValidator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON for this profile"];
    const missing = missingFields(data, requiredFields);
    return missing.map((f) => `required field missing: ${f}`);
  };
}

const VALID_EVENT_KINDS = new Set(Object.values(PROVENANCE_EVENT_KIND));

// ---------------------------------------------------------------------------
// Profile 0x0001 – LIGHTDSU_MINIMAL
// ---------------------------------------------------------------------------
const LIGHTDSU_MINIMAL = {
  profileId:    PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,
  name:         "LIGHTDSU_MINIMAL",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.CANONICAL_JSON, PAYLOAD_FORMAT.CBOR],
  requiredFields: ["eventKind", "operation", "actorHash", "timestampMs", "method", "softwareAgent", "softwareVersion"],
  optionalFields: ["resourceHash", "versionSeq", "inputHashes", "outputHashes", "reason",
                   "previousVersion", "newVersion", "relatedPayloads"],
  externalStandardRef: null,
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON"];
    const errors = [];
    for (const f of LIGHTDSU_MINIMAL.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    if (data.eventKind && !VALID_EVENT_KINDS.has(data.eventKind)) {
      errors.push(`unknown eventKind: ${data.eventKind}`);
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0002 – W3C_PROV
// ---------------------------------------------------------------------------
const W3C_PROV = {
  profileId:    PROVENANCE_PROFILES.W3C_PROV,
  name:         "W3C_PROV",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.JSON_LD, PAYLOAD_FORMAT.RDF_TURTLE, PAYLOAD_FORMAT.CANONICAL_JSON],
  requiredFields: ["entity", "activity", "agent"],
  optionalFields: ["wasGeneratedBy", "used", "wasAssociatedWith", "wasRevisionOf",
                   "startedAtTime", "endedAtTime"],
  externalStandardRef: "https://www.w3.org/TR/prov-o/",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON/JSON-LD"];
    const errors = [];
    for (const f of W3C_PROV.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0003 – FHIR_PROVENANCE
// ---------------------------------------------------------------------------
const FHIR_PROVENANCE = {
  profileId:    PROVENANCE_PROFILES.FHIR_PROVENANCE,
  name:         "FHIR_PROVENANCE",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.FHIR_JSON],
  requiredFields: ["resourceType", "target", "recorded", "agent"],
  optionalFields: ["activity", "entity", "reason", "signature"],
  externalStandardRef: "https://hl7.org/fhir/provenance.html",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not valid FHIR JSON"];
    const errors = [];
    if (data.resourceType !== "Provenance") {
      errors.push("resourceType must be 'Provenance'");
    }
    for (const f of ["target", "recorded", "agent"]) {
      if (data[f] == null) errors.push(`required FHIR field missing: ${f}`);
    }
    if (data.agent && !Array.isArray(data.agent)) errors.push("agent must be an array");
    if (data.target && !Array.isArray(data.target)) errors.push("target must be an array");
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0004 – FHIR_AUDIT_EVENT
// ---------------------------------------------------------------------------
const FHIR_AUDIT_EVENT = {
  profileId:    PROVENANCE_PROFILES.FHIR_AUDIT_EVENT,
  name:         "FHIR_AUDIT_EVENT",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.FHIR_JSON],
  requiredFields: ["resourceType", "type", "recorded", "agent", "source"],
  optionalFields: ["action", "outcome", "outcomeDesc", "purposeOfEvent", "entity"],
  externalStandardRef: "https://hl7.org/fhir/auditevent.html",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not valid FHIR JSON"];
    const errors = [];
    if (data.resourceType !== "AuditEvent") {
      errors.push("resourceType must be 'AuditEvent'");
    }
    for (const f of ["type", "recorded", "agent", "source"]) {
      if (data[f] == null) errors.push(`required FHIR field missing: ${f}`);
    }
    if (data.agent && !Array.isArray(data.agent)) errors.push("agent must be an array");
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0005 – GXP_AUDIT_TRAIL
// ---------------------------------------------------------------------------
const GXP_AUDIT_TRAIL = {
  profileId:    PROVENANCE_PROFILES.GXP_AUDIT_TRAIL,
  name:         "GXP_AUDIT_TRAIL",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.CANONICAL_JSON, PAYLOAD_FORMAT.CBOR],
  requiredFields: ["regulatedRecordType", "operation", "actorHash", "timestampMs",
                   "resourceHash", "changeReason", "systemId", "systemVersion",
                   "reviewStatus", "retentionClass"],
  optionalFields: ["validationContext", "previousValueHash", "newValueHash",
                   "electronicSignatureMeaning", "reviewedBy", "reviewTimestamp"],
  externalStandardRef: "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/part-11-electronic-records-electronic-signatures-scope-and-application",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON"];
    const errors = [];
    for (const f of GXP_AUDIT_TRAIL.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    // changeReason is especially critical for modifications/deletions
    if (data.operation && ["UPDATE", "DELETE"].includes(data.operation.toUpperCase())) {
      if (!data.changeReason) errors.push("changeReason is required for UPDATE and DELETE operations under GxP");
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0006 – RO_CRATE
// ---------------------------------------------------------------------------
const RO_CRATE = {
  profileId:    PROVENANCE_PROFILES.RO_CRATE,
  name:         "RO_CRATE",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.JSON_LD, PAYLOAD_FORMAT.CANONICAL_JSON],
  requiredFields: ["roCrateVersion", "rootDatasetId", "metadataJsonLd"],
  optionalFields: ["describedResources", "authors", "contributors", "license",
                   "accessRights", "relatedPublications", "workflowReferences"],
  externalStandardRef: "https://w3id.org/ro/crate/1.2",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not valid JSON-LD"];
    const errors = [];
    for (const f of RO_CRATE.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    // metadataJsonLd must contain @context and @graph
    if (data.metadataJsonLd && typeof data.metadataJsonLd === "object") {
      if (!data.metadataJsonLd["@context"]) errors.push("metadataJsonLd must contain @context");
      if (!data.metadataJsonLd["@graph"]) errors.push("metadataJsonLd must contain @graph");
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0007 – GA4GH_DATA_USE
// ---------------------------------------------------------------------------
const GA4GH_DATA_USE = {
  profileId:    PROVENANCE_PROFILES.GA4GH_DATA_USE,
  name:         "GA4GH_DATA_USE",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.CANONICAL_JSON],
  requiredFields: ["datasetId", "duoTerms", "permittedUses", "prohibitedUses", "policyVersion"],
  optionalFields: ["cohortId", "sampleScope", "consentGroup", "dataAccessCommittee",
                   "jurisdiction", "consentReference"],
  externalStandardRef: "https://github.com/EBISPOT/DUO",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON"];
    const errors = [];
    for (const f of GA4GH_DATA_USE.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    if (data.duoTerms && !Array.isArray(data.duoTerms)) {
      errors.push("duoTerms must be an array of DUO ontology term identifiers");
    }
    if (data.permittedUses && !Array.isArray(data.permittedUses)) {
      errors.push("permittedUses must be an array");
    }
    if (data.prohibitedUses && !Array.isArray(data.prohibitedUses)) {
      errors.push("prohibitedUses must be an array");
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0008 – ISO_8000_PROVENANCE
// ---------------------------------------------------------------------------
const ISO_8000_PROVENANCE = {
  profileId:    PROVENANCE_PROFILES.ISO_8000_PROVENANCE,
  name:         "ISO_8000_PROVENANCE",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.CANONICAL_JSON, PAYLOAD_FORMAT.CBOR],
  requiredFields: ["masterDataObjectId", "characteristicId", "characteristicValueHash",
                   "source", "acquisitionMethod", "responsibleParty", "timestampMs",
                   "qualityStatus", "validationStatus"],
  optionalFields: ["transformationHistory"],
  externalStandardRef: "https://www.iso.org/standard/61086.html",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON"];
    const errors = [];
    for (const f of ISO_8000_PROVENANCE.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x0009 – OECD_GLP_DATA_INTEGRITY
// ---------------------------------------------------------------------------
const OECD_GLP_DATA_INTEGRITY = {
  profileId:    PROVENANCE_PROFILES.OECD_GLP_DATA_INTEGRITY,
  name:         "OECD_GLP_DATA_INTEGRITY",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.CANONICAL_JSON, PAYLOAD_FORMAT.CBOR],
  requiredFields: ["studyId", "studyPhase", "rawDataReference", "metadataCompleteness",
                   "acquisitionSystem", "processingStep", "operator", "timestampMs",
                   "dataCriticality", "dataLifecycleStage", "integrityAssessment"],
  optionalFields: ["auditTrailReference"],
  externalStandardRef: "https://www.oecd.org/chemicalsafety/testing/good-laboratory-practice-glp.htm",
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON"];
    const errors = [];
    for (const f of OECD_GLP_DATA_INTEGRITY.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Profile 0x000A – AI_ML_EXPERIMENT
// ---------------------------------------------------------------------------
const AI_ML_EXPERIMENT = {
  profileId:    PROVENANCE_PROFILES.AI_ML_EXPERIMENT,
  name:         "AI_ML_EXPERIMENT",
  version:      1,
  payloadFormats: [PAYLOAD_FORMAT.CANONICAL_JSON, PAYLOAD_FORMAT.CBOR],
  requiredFields: ["experimentId", "runId", "task", "datasetHashes", "parametersHash",
                   "softwareEnvironment", "outputHashes"],
  optionalFields: ["featureSetHash", "modelId", "modelVersion", "promptHash", "codeHash",
                   "containerHash", "metrics", "evaluator", "randomSeed", "hardwareContext"],
  externalStandardRef: null,
  validator(canonicalPayload, parsed) {
    const data = parsed || parseIfJson(canonicalPayload);
    if (!data) return ["canonicalPayload is not parseable as JSON"];
    const errors = [];
    for (const f of AI_ML_EXPERIMENT.requiredFields) {
      if (data[f] == null) errors.push(`required field missing: ${f}`);
    }
    if (data.datasetHashes && !Array.isArray(data.datasetHashes)) {
      errors.push("datasetHashes must be an array");
    }
    if (data.outputHashes && !Array.isArray(data.outputHashes)) {
      errors.push("outputHashes must be an array");
    }
    return errors;
  }
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const PROFILE_REGISTRY = new Map([
  [PROVENANCE_PROFILES.LIGHTDSU_MINIMAL,        LIGHTDSU_MINIMAL],
  [PROVENANCE_PROFILES.W3C_PROV,                W3C_PROV],
  [PROVENANCE_PROFILES.FHIR_PROVENANCE,         FHIR_PROVENANCE],
  [PROVENANCE_PROFILES.FHIR_AUDIT_EVENT,        FHIR_AUDIT_EVENT],
  [PROVENANCE_PROFILES.GXP_AUDIT_TRAIL,         GXP_AUDIT_TRAIL],
  [PROVENANCE_PROFILES.RO_CRATE,                RO_CRATE],
  [PROVENANCE_PROFILES.GA4GH_DATA_USE,          GA4GH_DATA_USE],
  [PROVENANCE_PROFILES.ISO_8000_PROVENANCE,     ISO_8000_PROVENANCE],
  [PROVENANCE_PROFILES.OECD_GLP_DATA_INTEGRITY, OECD_GLP_DATA_INTEGRITY],
  [PROVENANCE_PROFILES.AI_ML_EXPERIMENT,        AI_ML_EXPERIMENT]
]);

function getProfile(profileId) {
  return PROFILE_REGISTRY.get(profileId) || null;
}

function listProfiles() {
  return Array.from(PROFILE_REGISTRY.values()).map((p) => ({
    profileId:             p.profileId,
    name:                  p.name,
    version:               p.version,
    payloadFormats:        p.payloadFormats.slice(),
    requiredFields:        p.requiredFields.slice(),
    optionalFields:        p.optionalFields.slice(),
    externalStandardRef:   p.externalStandardRef || null
  }));
}

/**
 * Structural validation of a decoded ProvenancePayloadV1 against its profile.
 * Returns array of error strings (empty = valid).
 */
function validateStructural(provenancePayloadV1) {
  const { profileId, profileVersion, payloadFormat, canonicalPayload } = provenancePayloadV1;

  const profile = PROFILE_REGISTRY.get(profileId);
  if (!profile) return [`unknown profileId: 0x${profileId.toString(16).padStart(4, "0")}`];

  const errors = [];

  if (profileVersion > profile.version) {
    errors.push(`profileVersion ${profileVersion} is newer than supported ${profile.version}`);
  }

  if (!profile.payloadFormats.includes(payloadFormat)) {
    errors.push(`payloadFormat 0x${payloadFormat.toString(16).padStart(2, "0")} not supported by ${profile.name}`);
  }

  // Domain-level validation via profile validator
  const cpBuf = Buffer.isBuffer(canonicalPayload) ? canonicalPayload : Buffer.from(canonicalPayload);
  const parsed = parseIfJson(cpBuf);
  const domainErrors = profile.validator(cpBuf, parsed);
  errors.push(...domainErrors);

  return errors;
}

module.exports = { getProfile, listProfiles, validateStructural, PROFILE_REGISTRY };
