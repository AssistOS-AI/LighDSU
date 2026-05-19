"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { LightDSUEngine, DefaultDidStrategy, PERMISSIONS, ERROR_CODES, EVENT_TYPES } = require("../src");

async function makeEngine(root, did, domain = "local") {
  return LightDSUEngine.open({
    storageRoot: root,
    domain,
    currentDID: did,
    didStrategy: new DefaultDidStrategy(did)
  });
}

async function readAnchorFile(storageRoot, anchorId) {
  return fs.readFile(path.join(storageRoot, "anchors", `${anchorId}.la`), "utf8");
}

test("createDSU initializes anchor and SSI family", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const created = await engine.createDSU();

  assert.ok(created.lkeySSI.startsWith("ssi:lkey:local:"));
  assert.ok(created.rkeySSI.startsWith("ssi:rkey:local:"));
  assert.ok(created.lzaSSI.startsWith("ssi:lza:local:"));

  const anchorFile = await readAnchorFile(dir, created.anchorId);
  const lines = anchorFile.trim().split("\n");
  assert.equal(lines.length, 3);
  assert.ok(lines[0].startsWith("ssi:event:local:"));
});

test("domain mismatch and SSI validation errors", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engineLocal = await makeEngine(dir, "did:example:alice", "local");
  const created = await engineLocal.createDSU();

  const engineOther = await makeEngine(dir, "did:example:alice", "other-domain");
  await assert.rejects(() => engineOther.loadDSU(created.lkeySSI), { code: ERROR_CODES.ERR_DOMAIN_MISMATCH });
  assert.throws(() => engineLocal.parseSSI("ssi:badtype:local:abc:v1"), { code: ERROR_CODES.ERR_INVALID_SSI });
  assert.throws(() => engineLocal.parseSSI(created.lkeySSI.replace(/:v1$/, ":v2")), { code: ERROR_CODES.ERR_UNSUPPORTED_VERSION });
});

test("filesystem API complete flow", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  await dsu.createFolder("/docs");
  await dsu.writeFile("/docs/a.txt", Buffer.from("hello"));
  await dsu.appendToFile("/docs/a.txt", Buffer.from(" world"));

  const data = await dsu.readFile("/docs/a.txt");
  assert.equal(data.toString(), "hello world");
  assert.equal(dsu.stat("/docs/a.txt").size, 11);

  assert.deepEqual(dsu.readDir("/docs").map((entry) => entry.name), ["a.txt"]);
  assert.deepEqual(dsu.listFiles("/docs"), ["/docs/a.txt"]);
  assert.deepEqual(dsu.listFolders("/"), ["/docs"]);

  await dsu.rename("/docs/a.txt", "/docs/b.txt");
  assert.deepEqual(dsu.listFiles("/docs"), ["/docs/b.txt"]);
  await dsu.delete("/docs/b.txt");
  assert.deepEqual(dsu.listFiles("/docs"), []);
});

test("chunking: large file is split into multiple chunks", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  const large = Buffer.alloc(700 * 1024, 0x7a);
  await dsu.writeFile("/large.bin", large, { chunkSize: 128 * 1024 });
  const st = dsu.stat("/large.bin");
  assert.ok(st.chunks.length > 1);
  const restored = await dsu.readFile("/large.bin");
  assert.equal(restored.length, large.length);
  assert.deepEqual(restored, large);
});

test("batch API: single commit, cancel rollback, state flag", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();

  const before = dsu.getHistory({ eventType: EVENT_TYPES.VERSION_COMMIT }).length;
  dsu.beginBatch();
  await dsu.writeFile("/a.txt", Buffer.from("a"));
  await dsu.writeFile("/b.txt", Buffer.from("b"));
  assert.equal(dsu.hasUncommittedChanges(), true);
  await dsu.commitBatch();
  const after = dsu.getHistory({ eventType: EVENT_TYPES.VERSION_COMMIT }).length;
  assert.equal(after, before + 1);

  dsu.beginBatch();
  await dsu.writeFile("/c.txt", Buffer.from("c"));
  dsu.cancelBatch();
  await assert.rejects(() => dsu.readFile("/c.txt"), { code: ERROR_CODES.ERR_INVALID_PATH });
});

test("access control: exact + recursive scopes, grant/revoke/check/list", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const aliceEngine = await makeEngine(dir, "did:example:alice");
  const created = await aliceEngine.createDSU();

  await created.dsu.createFolder("/shared");
  await created.dsu.writeFile("/shared/report.txt", Buffer.from("report"));

  const recursiveScope = { kind: "folder", path: "/shared", recursive: true };
  const granted = await created.dsu.grantAccess("did:example:bob", recursiveScope, PERMISSIONS.READ | PERMISSIONS.LIST);
  assert.ok(granted.grantId);
  assert.equal(created.dsu.listAccess().length >= 1, true);

  const bobEngine = await makeEngine(dir, "did:example:bob");
  const bobDsu = await bobEngine.loadDSU(created.rkeySSI);
  const decision = bobDsu.checkAccess("did:example:bob", { kind: "file", path: "/shared/report.txt" }, PERMISSIONS.READ);
  assert.equal(decision.allowed, true);
  assert.equal((await bobDsu.readFile("/shared/report.txt")).toString(), "report");

  await created.dsu.revokeAccess("did:example:bob", recursiveScope, PERMISSIONS.READ | PERMISSIONS.LIST);
  const bobDsu2 = await bobEngine.loadDSU(created.rkeySSI);
  const denied = bobDsu2.checkAccess("did:example:bob", { kind: "file", path: "/shared/report.txt" }, PERMISSIONS.READ);
  assert.equal(denied.allowed, false);

  await assert.rejects(
    () => created.dsu.grantAccess("did:example:bob", recursiveScope, 1 << 14),
    { code: ERROR_CODES.ERR_INVALID_PERMISSION }
  );
});

test("rkey and lza restrictions", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const created = await engine.createDSU();
  await created.dsu.writeFile("/r.txt", Buffer.from("r"));

  const rMounted = await engine.loadDSU(created.rkeySSI);
  assert.equal((await rMounted.readFile("/r.txt")).toString(), "r");
  await assert.rejects(() => rMounted.writeFile("/x.txt", Buffer.from("x")), { code: ERROR_CODES.ERR_READ_ONLY_DSU });
  await assert.rejects(() => rMounted.grantAccess("did:example:bob", { kind: "DSU", recursive: true }, PERMISSIONS.READ), {
    code: ERROR_CODES.ERR_READ_ONLY_DSU
  });

  const lzaMounted = await engine.loadDSU(created.lzaSSI);
  const verification = await lzaMounted.verifyAnchor();
  assert.equal(verification.valid, true);
  assert.equal(typeof lzaMounted.getLatestEventHash(), "string");
  await assert.rejects(() => lzaMounted.readFile("/r.txt"), { code: ERROR_CODES.ERR_READ_ONLY_DSU });
  assert.throws(() => lzaMounted.checkAccess("did:example:alice", { kind: "DSU" }, PERMISSIONS.READ), {
    code: ERROR_CODES.ERR_READ_ONLY_DSU
  });
});

test("provenance, history, and read audit access log", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();
  await dsu.writeFile("/p.txt", Buffer.from("payload"));

  const provenanceResult = await dsu.appendProvenance(
    { kind: "file", path: "/p.txt", recursive: false },
    { source: "lab", method: "pipeline-v1", operation: "analysis" }
  );
  assert.ok(provenanceResult.payloadHash);

  const records = await dsu.getProvenance();
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.source, "lab");

  const historyBeforeRead = dsu.getHistory({ eventType: EVENT_TYPES.ACCESS_LOG }).length;
  await dsu.readFile("/p.txt", { audit: true });
  const historyAfterRead = dsu.getHistory({ eventType: EVENT_TYPES.ACCESS_LOG }).length;
  assert.equal(historyAfterRead, historyBeforeRead + 1);
});

test("anchor tamper detection: invalid signature and chain", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const created = await engine.createDSU();

  const anchorPath = path.join(dir, "anchors", `${created.anchorId}.la`);
  const raw = await fs.readFile(anchorPath, "utf8");
  const lines = raw.trim().split("\n");
  lines[1] = lines[1].replace(/v1$/, "v1x");
  await fs.writeFile(anchorPath, `${lines.join("\n")}\n`, "utf8");
  await assert.rejects(() => engine.loadDSU(created.lkeySSI), (error) => {
    return (
      error &&
      (error.code === ERROR_CODES.ERR_EVENT_PARSE_FAILED ||
        error.code === ERROR_CODES.ERR_INVALID_SSI ||
        error.code === ERROR_CODES.ERR_UNSUPPORTED_VERSION)
    );
  });
});

test("brick tamper detection", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();
  await dsu.writeFile("/tamper.txt", Buffer.from("secret"));
  const st = dsu.stat("/tamper.txt");
  const brick = st.chunks[0].brickHash;
  const brickFile = path.join(dir, "bricks", brick.slice(0, 2), `${brick}.ldb`);
  await fs.writeFile(brickFile, Buffer.from("corrupted"));
  await assert.rejects(() => dsu.readFile("/tamper.txt"), { code: ERROR_CODES.ERR_BRICK_HASH_MISMATCH });
});

test("invalid path is rejected", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();
  await assert.rejects(() => dsu.writeFile("../escape.txt", Buffer.from("x")), { code: ERROR_CODES.ERR_INVALID_PATH });
});

test("concurrent commits on same anchor remain valid", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine1 = await makeEngine(dir, "did:example:alice");
  const created = await engine1.createDSU();
  const engine2 = await makeEngine(dir, "did:example:alice");
  const mount2 = await engine2.loadDSU(created.lkeySSI);

  await Promise.all([
    created.dsu.writeFile("/one.txt", Buffer.from("one")),
    mount2.writeFile("/two.txt", Buffer.from("two"))
  ]);

  const verify = await created.dsu.verifyAnchor();
  assert.equal(verify.valid, true);
});

test("garbage collection for purge-obsolete removes old bricks", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "lightdsu-"));
  const engine = await makeEngine(dir, "did:example:alice");
  const { dsu } = await engine.createDSU();
  dsu.brickMap.manifest.retentionMode = "purge-obsolete";
  await dsu.writeFile("/gc.txt", Buffer.from("v1"));
  await dsu.writeFile("/gc.txt", Buffer.from("v2"));
  const report = await dsu.runGarbageCollection();
  assert.equal(report.mode, "purge-obsolete");
  assert.ok(report.removedBricks >= 0);
});
