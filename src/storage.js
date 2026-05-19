"use strict";

const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const path = require("node:path");
const { sha256 } = require("./crypto/primitives");
const { ERROR_CODES, throwError } = require("./errors");

function layout(storageRoot) {
  return {
    root: storageRoot,
    anchors: path.join(storageRoot, "anchors"),
    bricks: path.join(storageRoot, "bricks"),
    tmp: path.join(storageRoot, "tmp"),
    locks: path.join(storageRoot, "locks")
  };
}

async function ensureLayout(storageRoot) {
  const p = layout(storageRoot);
  await Promise.all([
    fs.mkdir(p.anchors, { recursive: true }),
    fs.mkdir(p.bricks, { recursive: true }),
    fs.mkdir(p.tmp, { recursive: true }),
    fs.mkdir(p.locks, { recursive: true })
  ]);
  return p;
}

function anchorPath(storageRoot, anchorIdHex) {
  return path.join(layout(storageRoot).anchors, `${anchorIdHex}.la`);
}

function lockPath(storageRoot, anchorIdHex) {
  return path.join(layout(storageRoot).locks, `${anchorIdHex}.lock`);
}

function brickPath(storageRoot, brickHashHex) {
  const prefix = brickHashHex.slice(0, 2);
  return path.join(layout(storageRoot).bricks, prefix, `${brickHashHex}.ldb`);
}

async function writeBrick(storageRoot, envelope) {
  const hash = sha256(envelope).toString("hex");
  const dst = brickPath(storageRoot, hash);
  await fs.mkdir(path.dirname(dst), { recursive: true });
  if (!fsSync.existsSync(dst)) {
    const temp = path.join(layout(storageRoot).tmp, `${hash}.${Date.now()}.tmp`);
    await fs.writeFile(temp, envelope);
    await fs.rename(temp, dst);
  }
  return hash;
}

async function readBrick(storageRoot, brickHashHex) {
  const file = brickPath(storageRoot, brickHashHex);
  let data;
  try {
    data = await fs.readFile(file);
  } catch {
    throwError(ERROR_CODES.ERR_BRICK_NOT_FOUND, `Missing brick ${brickHashHex}`);
  }
  const actual = sha256(data).toString("hex");
  if (actual !== brickHashHex) {
    throwError(ERROR_CODES.ERR_BRICK_HASH_MISMATCH, `${brickHashHex} != ${actual}`);
  }
  return data;
}

async function listBrickHashes(storageRoot) {
  const bricksRoot = layout(storageRoot).bricks;
  const hashes = [];
  const prefixes = await fs.readdir(bricksRoot, { withFileTypes: true }).catch(() => []);
  for (const dirent of prefixes) {
    if (!dirent.isDirectory()) continue;
    const folder = path.join(bricksRoot, dirent.name);
    const entries = await fs.readdir(folder, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".ldb")) continue;
      hashes.push(entry.name.slice(0, -4));
    }
  }
  return hashes;
}

async function removeBrick(storageRoot, brickHashHex) {
  const file = brickPath(storageRoot, brickHashHex);
  await fs.rm(file, { force: true });
}

async function readAnchorLines(storageRoot, anchorIdHex) {
  const file = anchorPath(storageRoot, anchorIdHex);
  try {
    const raw = await fs.readFile(file, "utf8");
    return raw.split("\n").filter(Boolean);
  } catch {
    throwError(ERROR_CODES.ERR_ANCHOR_NOT_FOUND, `Anchor ${anchorIdHex} not found`);
  }
}

async function withAnchorLock(storageRoot, anchorIdHex, action) {
  const lockFile = lockPath(storageRoot, anchorIdHex);
  const started = Date.now();
  while (true) {
    let handle;
    try {
      handle = await fs.open(lockFile, "wx");
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      if (Date.now() - started > 10_000) {
        throwError(ERROR_CODES.ERR_CONCURRENT_COMMIT, "Anchor lock timeout");
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
      continue;
    }
    try {
      return await action();
    } finally {
      await handle.close();
      await fs.rm(lockFile, { force: true });
    }
  }
}

async function appendAnchorLine(storageRoot, anchorIdHex, line) {
  const file = anchorPath(storageRoot, anchorIdHex);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.appendFile(file, `${line}\n`, "utf8");
}

module.exports = {
  ensureLayout,
  anchorPath,
  brickPath,
  writeBrick,
  readBrick,
  listBrickHashes,
  removeBrick,
  readAnchorLines,
  withAnchorLock,
  appendAnchorLine
};
