# Specification Matrix

Generated from DS frontmatter. Edit the DS files and rerun the generator instead of editing this file manually.

| Specification | Title | Status | Owner | Summary |
| --- | --- | --- | --- | --- |
| [DS000](specsLoader.html?spec=DS000-vision.md) | Vision | [[status:implemented]] | repository | LightDSU is a local library for storing, versioning, auditing, and controlling access to encrypted DSUs. |
| [DS001](specsLoader.html?spec=DS001-coding-style.md) | Coding Style | [[status:implemented]] | repository | Coding conventions, module structure, and test organization rules for LightDSU v1. |
| [DS002](specsLoader.html?spec=DS002-ssi-convention.md) | SSI Convention | [[status:implemented]] | repository | Compact SSI format for key material and event data: lkey, rkey, lza, event. |
| [DS003](specsLoader.html?spec=DS003-crypto-derivations.md) | Cryptographic Derivations | [[status:implemented]] | repository | Key derivation chain from lkeySecret using HKDF-SHA256. |
| [DS004](specsLoader.html?spec=DS004-event-ssi.md) | EventSSI Encoding | [[status:implemented]] | repository | Binary encoding format for anchor events with flags-based optional fields. |
| [DS005](specsLoader.html?spec=DS005-event-types.md) | Event Types | [[status:implemented]] | repository | Eight event types: GENESIS, VERSION_COMMIT, GRANT, REVOKE, ACCESS_LOG, PROVENANCE, POLICY_UPDATE, KEY_EPOCH. |
| [DS006](specsLoader.html?spec=DS006-brickmap.md) | BrickMap | [[status:implemented]] | repository | Encrypted virtual filesystem structure with chunk references and file keys. |
| [DS007](specsLoader.html?spec=DS007-bricks.md) | Bricks | [[status:implemented]] | repository | AES-256-GCM encrypted, content-addressed storage units. |
| [DS008](specsLoader.html?spec=DS008-access-control.md) | Access Control | [[status:implemented]] | repository | Grant-based permission model with scope matching and HMAC identity binding. |
| [DS009](specsLoader.html?spec=DS009-did-strategy.md) | DID Strategy | [[status:implemented]] | repository | Pluggable DID strategy interface for actor signatures. |
| [DS010](specsLoader.html?spec=DS010-api-public.md) | Public API | [[status:implemented]] | repository | Complete API specification: Engine, DSU, Filesystem, Batch, Access, Provenance. |
| [DS011](specsLoader.html?spec=DS011-provenance-extension.md) | Provenance Extension | [[status:implemented]] | repository | Profile-based provenance metadata with 10 standards-compatible profiles. |
| [DS012](specsLoader.html?spec=DS012-storage-layout.md) | Storage Layout | [[status:implemented]] | repository | Local filesystem layout: anchors, bricks, tmp, locks. |
| [DS013](specsLoader.html?spec=DS013-errors.md) | Error Codes | [[status:implemented]] | repository | Standardized error codes and LightDSUError class. |
| [DS014](specsLoader.html?spec=DS014-retention-gc.md) | Retention and Garbage Collection | [[status:implemented]] | repository | Retention modes and explicit garbage collection. |
