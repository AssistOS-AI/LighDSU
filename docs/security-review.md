# LightDSU Security Review (v1 hardening)

## Scope

This review covered:

- anchor integrity (`ssi:event`, chain continuity, signatures)
- access control (`grant`, `revoke`, `checkAccess`)
- filesystem consistency
- concurrent commit resilience
- runtime actor identity switching (`currentDID`)
- provenance validation and strict decoding
- garbage-collection authorization and retention safety

## Applied Decisions

1. **Scope-bound ADMIN**
   - `ADMIN` does not bypass grant scope globally.
   - Evaluation remains: *scope match* -> *permission bits*.

2. **Correct grant identity**
   - `grantId` is unique per GRANT (`eventHash` of the GRANT event).
   - `REVOKE` with `grantId` targets the exact grant.
   - `REVOKE` without `grantId` revokes all active grants matching `(subjectHash, resourceHash, permissions)`.

3. **Revoke-by-grantId authorization hardening**
   - When `grantId` is present, authorization is evaluated against the target grant scope, not the caller-supplied scope.

4. **Strict scope validation**
   - Unsupported scope kinds fail with `ERR_INVALID_SCOPE`.
   - Non-DSU scopes require a path.
   - Permission masks must be explicit non-zero integers with defined bits only.

5. **Filesystem validation**
   - `readDir`, `listFiles`, and `listFolders` fail on missing or non-folder paths.
   - `delete` fails on missing paths.
   - `rename` blocks overwrite and self-nesting.

6. **`appendToFile` without silent fallback**
   - Only `ERR_INVALID_PATH` is treated as create-on-missing.
   - Integrity and decryption errors propagate.

7. **Concurrent BrickMap commit rebasing**
   - VERSION_COMMIT retries reload the latest committed BrickMap snapshot.
   - Local BrickMap changes are replayed onto that snapshot before retrying, preserving independent path updates.

8. **Provenance validation before persistence**
   - Canonical JSON payloads are normalized deterministically.
   - Invalid profile payloads are rejected before the provenance brick is written.
   - Undecodable provenance records surface explicit errors during retrieval.

9. **Garbage collection authorization and retention safety**
   - GC requires a writable `lkey` mount and ADMIN access.
   - `retention-window` preserves both retained historical BrickMaps and the file bricks referenced by those retained versions.

10. **Explicit DID actor switching**
    - `engine.setCurrentDID(did)` and `mountedDsu.setCurrentDID(did)` synchronize `didStrategy` when supported.

## Remaining Known Limits

1. **DefaultDidStrategy is local-only**
   - It is useful for tests, development, and embedded local scenarios.
   - Production deployments should prefer an external DID strategy (HSM, KMS, wallet, or equivalent).

2. **Append semantics**
   - `appendToFile` remains read-and-rewrite, which is functionally correct but not optimized for very large files.
   - Incremental chunk append can be added later without changing the public API.

3. **Policy-word coverage**
   - The repository exposes policy-word infrastructure, but most operational policy changes still live in the BrickMap manifest.
   - Provenance policy `auditMode` is descriptive in v1; runtime read-audit behavior is not fully driven by manifest policy updates yet.
