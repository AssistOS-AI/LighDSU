"use strict";

const path = require("node:path");
const { throwError, ERROR_CODES } = require("./errors");

function normalizePath(inputPath) {
  if (typeof inputPath !== "string" || inputPath.length === 0) {
    throwError(ERROR_CODES.ERR_INVALID_PATH, "Path is required");
  }
  const sanitizedInput = inputPath.replace(/\\/g, "/");
  const normalized = path.posix.normalize(
    path.posix.isAbsolute(sanitizedInput) ? sanitizedInput.slice(1) : sanitizedInput
  );
  if (normalized.includes("\0")) {
    throwError(ERROR_CODES.ERR_INVALID_PATH, "NUL byte in path");
  }
  if (normalized.startsWith("../") || normalized === "..") {
    throwError(ERROR_CODES.ERR_INVALID_PATH, "Path escapes DSU root");
  }
  return normalized === "." ? "/" : normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function dirnameSafe(p) {
  const d = path.posix.dirname(p);
  return d === "." ? "/" : d;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    const out = {};
    for (const key of keys) out[key] = canonicalize(value[key]);
    return out;
  }
  return value;
}

function canonicalJSONStringify(value) {
  return JSON.stringify(canonicalize(value));
}

module.exports = { normalizePath, dirnameSafe, canonicalJSONStringify };
