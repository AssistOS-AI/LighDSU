"use strict";

const SSI_TYPES = {
  LKEY: "lkey",
  RKEY: "rkey",
  LZA: "lza",
  EVENT: "event"
};

const EVENT_TYPES = {
  GENESIS: 0x01,
  VERSION_COMMIT: 0x02,
  GRANT: 0x03,
  REVOKE: 0x04,
  ACCESS_LOG: 0x05,
  PROVENANCE: 0x06,
  POLICY_UPDATE: 0x07,
  KEY_EPOCH: 0x08
};

const EVENT_FLAGS = {
  brickMapHash: 0x0001,
  payloadHash: 0x0002,
  subjectHash: 0x0004,
  resourceHash: 0x0008,
  permissions: 0x0010,
  policyWord: 0x0020,
  keyEpoch: 0x0040,
  grantId: 0x0080,
  actorHash: 0x0100,
  actorSignature: 0x0200,
  anchorPublic: 0x0400,
  extension: 0x0800
};

const PERMISSIONS = {
  READ: 1 << 0,
  WRITE: 1 << 1,
  DELETE: 1 << 2,
  LIST: 1 << 3,
  EXPORT: 1 << 4,
  GRANT: 1 << 5,
  REVOKE: 1 << 6,
  ADMIN: 1 << 7,
  AUDIT: 1 << 8,
  PROVENANCE_APPEND: 1 << 9
};

const RESOURCE_KIND = {
  DSU: 0x0,
  file: 0x1,
  folder: 0x2,
  virtualCollection: 0x3
};

const SCOPE_MODE = {
  exact: 0x0,
  recursive: 0x1,
  prefix: 0x2
};

const RETENTION_MODE = {
  "keep-all": 0x0,
  "purge-obsolete": 0x1,
  "retention-window": 0x2,
  "crypto-shred": 0x3
};

const AUDIT_MODE = {
  "no-read-audit": 0x0,
  "semantic-read-audit": 0x1,
  "full-operation-audit": 0x2
};

const DEFAULT_CHUNK_SIZE = 256 * 1024;

function hasPermission(actual, required) {
  return (actual & required) === required;
}

function makePolicyWord({
  resourceKind = RESOURCE_KIND.DSU,
  scopeMode = SCOPE_MODE.exact,
  retentionMode = RETENTION_MODE["keep-all"],
  auditMode = AUDIT_MODE["no-read-audit"],
  accessMode = 0
} = {}) {
  return (
    (resourceKind & 0x0f) |
    ((scopeMode & 0x0f) << 4) |
    ((retentionMode & 0x0f) << 8) |
    ((auditMode & 0x0f) << 12) |
    ((accessMode & 0xff) << 16)
  ) >>> 0;
}

function policyAuditMode(policyWord) {
  return (policyWord >>> 12) & 0x0f;
}

module.exports = {
  SSI_TYPES,
  EVENT_TYPES,
  EVENT_FLAGS,
  PERMISSIONS,
  RESOURCE_KIND,
  SCOPE_MODE,
  RETENTION_MODE,
  AUDIT_MODE,
  DEFAULT_CHUNK_SIZE,
  hasPermission,
  makePolicyWord,
  policyAuditMode
};
