"use strict";

const { canonicalJSONStringify, normalizePath, dirnameSafe } = require("./utils");
const { randomBytes } = require("./crypto/primitives");
const { encode, decode } = require("./crypto/base58");
const { throwError, ERROR_CODES } = require("./errors");

function createEmptyBrickMap() {
  const now = Date.now();
  return {
    seq: 0,
    manifest: {
      retentionMode: "keep-all",
      createdAt: now,
      updatedAt: now
    },
    metadata: {},
    entries: {
      "/": { type: "folder", createdAt: now, updatedAt: now, metadata: {} }
    }
  };
}

function serializeBrickMap(brickMap) {
  return Buffer.from(canonicalJSONStringify(brickMap));
}

function deserializeBrickMap(data) {
  return JSON.parse(Buffer.from(data).toString("utf8"));
}

function ensureParentFolder(brickMap, filePath) {
  const parent = dirnameSafe(filePath);
  if (!brickMap.entries[parent] || brickMap.entries[parent].type !== "folder") {
    throwError(ERROR_CODES.ERR_INVALID_PATH, `Missing parent folder: ${parent}`);
  }
}

function touchEntry(entry) {
  entry.updatedAt = Date.now();
}

function ensureFolder(brickMap, folderPath) {
  const p = normalizePath(folderPath);
  if (p === "/") return;
  const parent = dirnameSafe(p);
  if (!brickMap.entries[parent]) ensureFolder(brickMap, parent);
  if (brickMap.entries[p] && brickMap.entries[p].type !== "folder") {
    throwError(ERROR_CODES.ERR_INVALID_PATH, `${p} exists and is not folder`);
  }
  if (!brickMap.entries[p]) {
    const now = Date.now();
    brickMap.entries[p] = { type: "folder", createdAt: now, updatedAt: now, metadata: {} };
  }
}

function setFileEntry(brickMap, filePath, data) {
  const p = normalizePath(filePath);
  ensureParentFolder(brickMap, p);
  const now = Date.now();
  const existing = brickMap.entries[p];
  const createdAt = existing?.createdAt || now;
  brickMap.entries[p] = {
    type: "file",
    size: data.size,
    mediaType: data.mediaType || "application/octet-stream",
    createdAt,
    updatedAt: now,
    metadata: data.metadata || {},
    fileKey: encode(data.fileKey || randomBytes(32)),
    chunks: data.chunks
  };
}

function getFileEntry(brickMap, filePath) {
  const p = normalizePath(filePath);
  const entry = brickMap.entries[p];
  if (!entry || entry.type !== "file") {
    throwError(ERROR_CODES.ERR_INVALID_PATH, `Not a file: ${p}`);
  }
  return entry;
}

function statEntry(brickMap, p) {
  const norm = normalizePath(p);
  const entry = brickMap.entries[norm];
  if (!entry) throwError(ERROR_CODES.ERR_INVALID_PATH, `Path not found: ${norm}`);
  return { path: norm, ...entry };
}

function deleteEntry(brickMap, p) {
  const norm = normalizePath(p);
  if (norm === "/") throwError(ERROR_CODES.ERR_INVALID_PATH, "Cannot delete root");
  if (!brickMap.entries[norm]) throwError(ERROR_CODES.ERR_INVALID_PATH, `Path not found: ${norm}`);
  const prefix = `${norm}/`;
  const keys = Object.keys(brickMap.entries);
  for (const key of keys) {
    if (key === norm || key.startsWith(prefix)) delete brickMap.entries[key];
  }
}

function renameEntry(brickMap, sourcePath, targetPath) {
  const source = normalizePath(sourcePath);
  const target = normalizePath(targetPath);
  if (!brickMap.entries[source]) throwError(ERROR_CODES.ERR_INVALID_PATH, `Source missing: ${source}`);
  if (brickMap.entries[target]) throwError(ERROR_CODES.ERR_INVALID_PATH, `Target exists: ${target}`);
  if (target === source || target.startsWith(`${source}/`)) {
    throwError(ERROR_CODES.ERR_INVALID_PATH, "Cannot move entry into itself");
  }
  ensureParentFolder(brickMap, target);
  const keys = Object.keys(brickMap.entries).sort();
  const sourcePrefix = `${source}/`;
  for (const key of keys) {
    if (key === source || key.startsWith(sourcePrefix)) {
      const suffix = key.slice(source.length);
      brickMap.entries[`${target}${suffix}`] = brickMap.entries[key];
      delete brickMap.entries[key];
    }
  }
  touchEntry(brickMap.entries[dirnameSafe(target)]);
}

function listEntries(brickMap, folderPath) {
  const folder = normalizePath(folderPath);
  const folderEntry = brickMap.entries[folder];
  if (!folderEntry) throwError(ERROR_CODES.ERR_INVALID_PATH, `Path not found: ${folder}`);
  if (folderEntry.type !== "folder") throwError(ERROR_CODES.ERR_INVALID_PATH, `Not a folder: ${folder}`);
  const folderPrefix = folder === "/" ? "/" : `${folder}/`;
  return Object.keys(brickMap.entries)
    .filter((entryPath) => {
      if (entryPath === folder) return false;
      if (!entryPath.startsWith(folderPrefix)) return false;
      const rest = entryPath.slice(folderPrefix.length);
      return rest.length > 0 && !rest.includes("/");
    })
    .sort();
}

function listByType(brickMap, folderPath, type) {
  return listEntries(brickMap, folderPath).filter((entryPath) => brickMap.entries[entryPath]?.type === type);
}

function decodeFileKey(entry) {
  return decode(entry.fileKey);
}

module.exports = {
  createEmptyBrickMap,
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
};
