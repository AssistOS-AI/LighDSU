"use strict";

const { hmacSha256, sha256 } = require("./crypto/primitives");
const { hasPermission, PERMISSIONS, RESOURCE_KIND, SCOPE_MODE } = require("./constants");
const { normalizePath } = require("./utils");
const { throwError, ERROR_CODES } = require("./errors");

const VALID_SCOPE_KINDS = new Set(Object.keys(RESOURCE_KIND));
const VALID_SCOPE_MODES = new Set(["exact", "recursive", "prefix"]);
const VALID_SCOPE_MODE_VALUES = new Set(Object.values(SCOPE_MODE));

function normalizeScope(scope = {}) {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    throwError(ERROR_CODES.ERR_INVALID_SCOPE, "Scope must be an object");
  }
  const kind = scope.kind || "DSU";
  if (!VALID_SCOPE_KINDS.has(kind)) {
    throwError(ERROR_CODES.ERR_INVALID_SCOPE, `Unsupported scope kind: ${kind}`);
  }
  if (scope.scopeMode !== undefined) {
    if (typeof scope.scopeMode === "string" && !VALID_SCOPE_MODES.has(scope.scopeMode)) {
      throwError(ERROR_CODES.ERR_INVALID_SCOPE, `Unsupported scope mode: ${scope.scopeMode}`);
    }
    if (typeof scope.scopeMode === "number" && !VALID_SCOPE_MODE_VALUES.has(scope.scopeMode)) {
      throwError(ERROR_CODES.ERR_INVALID_SCOPE, `Unsupported scope mode: ${scope.scopeMode}`);
    }
    if (typeof scope.scopeMode !== "string" && typeof scope.scopeMode !== "number") {
      throwError(ERROR_CODES.ERR_INVALID_SCOPE, `Unsupported scope mode: ${scope.scopeMode}`);
    }
  }
  if (kind !== "DSU" && typeof scope.path !== "string") {
    throwError(ERROR_CODES.ERR_INVALID_SCOPE, `Scope path is required for kind ${kind}`);
  }
  const path = kind === "DSU" && scope.path === undefined ? "/" : normalizePath(scope.path || "/");
  let scopeMode = typeof scope.scopeMode === "number" ? scope.scopeMode : SCOPE_MODE.exact;
  if (scope.scopeMode === "prefix") scopeMode = SCOPE_MODE.prefix;
  else if (scope.recursive || scope.scopeMode === "recursive") scopeMode = SCOPE_MODE.recursive;
  const recursive = scopeMode === SCOPE_MODE.recursive;
  const prefix = scopeMode === SCOPE_MODE.prefix;
  const resourceKind = RESOURCE_KIND[kind] ?? RESOURCE_KIND.DSU;
  return { kind, path, recursive, prefix, scopeMode, resourceKind };
}

function scopeToJSON(scope = {}) {
  const normalized = normalizeScope(scope);
  return {
    kind: normalized.kind,
    path: normalized.path,
    recursive: normalized.recursive,
    scopeMode:
      normalized.scopeMode === SCOPE_MODE.prefix
        ? "prefix"
        : normalized.scopeMode === SCOPE_MODE.recursive
          ? "recursive"
          : "exact"
  };
}

function parseScopeJSON(scopeJson) {
  if (!scopeJson || typeof scopeJson !== "object") return normalizeScope();
  return normalizeScope(scopeJson);
}

function scopeFromEventExtension(extensionBuffer) {
  if (!extensionBuffer || !extensionBuffer.length) return null;
  try {
    const parsed = JSON.parse(Buffer.from(extensionBuffer).toString("utf8"));
    return parsed.scope ? parseScopeJSON(parsed.scope) : null;
  } catch {
    return null;
  }
}

function makeExtensionPayload(extra = {}) {
  return Buffer.from(JSON.stringify(extra));
}

function areKindsCompatible(grantScope, requestScope) {
  if (grantScope.resourceKind === RESOURCE_KIND.DSU) return true;
  if (grantScope.resourceKind === requestScope.resourceKind) return true;
  if (grantScope.resourceKind === RESOURCE_KIND.folder && requestScope.resourceKind === RESOURCE_KIND.file) return true;
  return false;
}

function doesScopeMatch(grantScopeInput, requestScopeInput) {
  const grantScope = normalizeScope(grantScopeInput);
  const requestScope = normalizeScope(requestScopeInput);
  if (!areKindsCompatible(grantScope, requestScope)) return false;

  if (grantScope.scopeMode === SCOPE_MODE.exact) {
    return requestScope.path === grantScope.path;
  }
  if (grantScope.scopeMode === SCOPE_MODE.recursive) {
    if (grantScope.path === "/") return true;
    return requestScope.path === grantScope.path || requestScope.path.startsWith(`${grantScope.path}/`);
  }
  if (grantScope.scopeMode === SCOPE_MODE.prefix) {
    return requestScope.path.startsWith(grantScope.path);
  }
  return false;
}

function scopeHashInput(scope) {
  const normalized = normalizeScope(scope);
  return `${normalized.path}|${normalized.resourceKind}|${normalized.scopeMode}`;
}

function hashDid(accessIndexKey, didStrategy, did) {
  return hmacSha256(accessIndexKey, Buffer.from(didStrategy.normalize(did)));
}

function hashResource(accessIndexKey, scope = {}) {
  return hmacSha256(accessIndexKey, Buffer.from(scopeHashInput(scope)));
}

function buildGrantId(event) {
  return sha256(event.subjectHash, event.resourceHash, Buffer.from([(event.permissions >>> 8) & 0xff, event.permissions & 0xff]));
}

function verifyPermissionMask(requiredPermissions) {
  const ALL_DEFINED_BITS =
    PERMISSIONS.READ |
    PERMISSIONS.WRITE |
    PERMISSIONS.DELETE |
    PERMISSIONS.LIST |
    PERMISSIONS.EXPORT |
    PERMISSIONS.GRANT |
    PERMISSIONS.REVOKE |
    PERMISSIONS.ADMIN |
    PERMISSIONS.AUDIT |
    PERMISSIONS.PROVENANCE_APPEND;
  if (!Number.isInteger(requiredPermissions) || requiredPermissions <= 0 || requiredPermissions > 0xffff) {
    return false;
  }
  return (requiredPermissions & ~ALL_DEFINED_BITS) === 0;
}

function checkPermission(anchorState, actorHash, requestScope, requiredPermissions) {
  if (!anchorState || !anchorState.activeGrants) return false;
  for (const grant of anchorState.activeGrants.values()) {
    if (!grant.subjectHash.equals(actorHash)) continue;
    let scopeMatches = false;
    if (grant.scope) scopeMatches = doesScopeMatch(grant.scope, requestScope);
    else if (grant.resourceHash && anchorState.accessIndexKey) {
      scopeMatches = grant.resourceHash.equals(hashResource(anchorState.accessIndexKey, requestScope));
    }
    if (!scopeMatches) continue;
    if (hasPermission(grant.permissions, PERMISSIONS.ADMIN)) return true;
    if (hasPermission(grant.permissions, requiredPermissions)) return true;
  }
  return false;
}

function buildAccessDecision(anchorState, actorHash, requestScope, requiredPermissions) {
  const allowed = checkPermission(anchorState, actorHash, requestScope, requiredPermissions);
  return { allowed, reason: allowed ? "GRANTED" : "DENIED" };
}

function parseDidFromSignatureEnvelope(envelopeBytes) {
  try {
    const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
    return envelope?.did ? String(envelope.did) : null;
  } catch {
    return null;
  }
}

module.exports = {
  normalizeScope,
  hashDid,
  hashResource,
  buildGrantId,
  checkPermission,
  verifyPermissionMask,
  makeExtensionPayload,
  scopeFromEventExtension,
  parseDidFromSignatureEnvelope,
  scopeToJSON,
  buildAccessDecision
};
