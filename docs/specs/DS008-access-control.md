---
id: DS008
title: "DS008 — Access Control"
order: 8
---

# DS008 — Access Control

## Introduction

LightDSU uses a grant-based access control model where permissions are assigned to DIDs over resource scopes. Access decisions are evaluated by reducing the anchor event chain to an AnchorState and checking active grants against the requested operation.

## Core Content

### Permission Bitmap

```
u16 permissions

bit 0   READ              (0x0001)
bit 1   WRITE             (0x0002)
bit 2   DELETE            (0x0004)
bit 3   LIST              (0x0008)
bit 4   EXPORT            (0x0010)
bit 5   GRANT             (0x0020)
bit 6   REVOKE            (0x0040)
bit 7   ADMIN             (0x0080)
bit 8   AUDIT             (0x0100)
bit 9   PROVENANCE_APPEND (0x0200)
bits 10-15 reserved
```

### Common Permission Combinations

| Combination | Value | Description |
|-------------|-------|-------------|
| READ \| LIST | 0x0009 | Read-only with listing |
| READ \| WRITE \| LIST | 0x000B | Read-write with listing |
| ADMIN | 0x0080 | Full administrative rights |

Permission bitmaps must be non-zero integers whose set bits are defined by the v1 permission table. Invalid values are rejected with `ERR_INVALID_PERMISSION`.

### Scope Model

A scope defines the resource boundary for a grant:

```
{
  kind: "DSU" | "file" | "folder" | "virtualCollection",
  path: string,          // virtual path
  recursive: boolean,    // or scopeMode: "exact" | "recursive" | "prefix"
}
```

- `kind` must be one of the supported values above.
- Non-DSU scopes must provide `path`.
- Invalid scope objects are rejected with `ERR_INVALID_SCOPE`; they are not coerced to DSU scope.

#### Scope Modes

| Mode | Behavior |
|------|----------|
| `exact` | Matches only the exact path |
| `recursive` | Matches the path and all descendants |
| `prefix` | Matches any path starting with the scope path |

#### Kind Compatibility

| Grant Kind | Request Kind | Match? |
|------------|-------------|--------|
| DSU | Any | Yes |
| folder | file | Yes |
| folder | folder | Yes |
| file | file | Yes |
| file | folder | No |

### Hashing

DIDs and resources are hashed using HMAC-SHA256 with `accessIndexKey`:

```
actorHash   = HMAC-SHA256(accessIndexKey, normalize(currentDID))
subjectHash = HMAC-SHA256(accessIndexKey, normalize(subjectDID))
resourceHash = HMAC-SHA256(accessIndexKey, "<path>|<resourceKind>|<scopeMode>")
```

The `accessIndexKey` is derived from `rkeySecret` and `anchorId`, so hashes are DSU-specific.

### Grant Evaluation

Access is evaluated by iterating over active grants in the AnchorState:

1. Find grants where `grant.subjectHash === actorHash`.
2. Check if the grant's scope matches the requested scope.
3. If the grant has `ADMIN` permission, access is granted.
4. If the grant's permission bitmap includes all required permissions, access is granted.
5. If no matching grant is found, access is denied.

### Grant ID

Each GRANT event produces a unique grant ID:

```
grantId = eventHash of the GRANT event
```

A tuple-based grant ID is also computed for revoke-by-tuple operations:

```
tupleId = SHA256(subjectHash || resourceHash || permissions[2 bytes])
```

### Revocation

REVOKE can target:
1. **Specific grant**: by `grantId`. Removes the grant from `activeGrants`.
2. **Tuple match**: by `subjectHash + resourceHash + permissions`. Removes all matching grants.

When revoking by `grantId`, the authorization check uses the **target grant's scope**, not the caller-provided scope. This prevents privilege escalation through scope manipulation.

### Access Decision

```
{
  allowed: boolean,
  reason: "GRANTED" | "DENIED"
}
```

### Mount Type Restrictions

| Mount Type | Can Write | Can Grant/Revoke | Can Read* | Can Verify |
|------------|-----------|------------------|-----------|------------|
| lkey | Yes | Yes | Yes | Yes |
| rkey | No | No | Yes* | Yes |
| lza | No | No | No | Yes |

\* Read access for rkey is subject to access control evaluation.

### Implementation

- `src/access.js` — `normalizeScope`, `hashDid`, `hashResource`, `buildGrantId`, `checkPermission`, `verifyPermissionMask`, `doesScopeMatch`, `buildAccessDecision`
- `src/constants.js` — `PERMISSIONS`, `RESOURCE_KIND`, `SCOPE_MODE`
- `src/dsu.js` — `grantAccess`, `revokeAccess`, `checkAccess`, `listAccess`, `#checkCurrentAccess`

## Decisions & Questions

### Question #1: Why does ADMIN respect scope?

**Response:** ADMIN permission grants all operations **within the scope of the grant**, not globally. This prevents a scoped admin from escalating privileges outside their granted boundary. For example, an admin granted over `/shared` cannot access `/private`.

### Question #2: Why use HMAC for DID hashing instead of plain SHA-256?

**Response:** HMAC with `accessIndexKey` ensures that DID hashes are DSU-specific. The same DID will hash differently in different DSUs, preventing cross-DSU correlation. The `accessIndexKey` is derived from the DSU's rkeySecret and anchorId.

### Question #3: Why reject malformed scopes instead of defaulting them?

**Response:** Silent coercion creates security ambiguity. A typo such as `kind: "bogus"` must fail fast instead of degrading to DSU scope, because callers should never receive broader authorization semantics than they requested.

## Conclusion

The access control model provides fine-grained, scope-based permissions with cryptographic identity binding. Grants and revocations are recorded in the anchor, making the access history fully auditable.
