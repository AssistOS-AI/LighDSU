---
id: DS012
title: "DS012 — Storage Layout"
order: 12
---

# DS012 — Storage Layout

## Introduction

LightDSU uses a local filesystem layout for storing anchors, bricks, temporary files, and lock files. This document specifies the directory structure, file naming conventions, and I/O patterns.

## Core Content

### Directory Structure

```
<storageRoot>/
  anchors/
    <anchorId>.la
  bricks/
    <prefix>/
      <brickHash>.ldb
  tmp/
  locks/
    <anchorId>.lock
```

### Anchors

- **Location**: `anchors/<anchorId>.la`
- **Format**: Line-oriented text file, one EventSSI per line.
- **anchorId**: Hex-encoded SHA-256 of anchorPublic (64 hex characters).
- **Operations**:
  - `readAnchorLines(storageRoot, anchorIdHex)` — reads all lines
  - `appendAnchorLine(storageRoot, anchorIdHex, line)` — appends one line with newline

### Bricks

- **Location**: `bricks/<prefix>/<brickHash>.ldb`
- **prefix**: First 2 characters of hex brick hash.
- **brickHash**: Hex-encoded SHA-256 of the envelope (64 hex characters).
- **Extension**: `.ldb`
- **Operations**:
  - `writeBrick(storageRoot, envelope)` — writes atomically via tmp/, returns hash
  - `readBrick(storageRoot, brickHashHex)` — reads and verifies hash
  - `listBrickHashes(storageRoot)` — scans all prefix directories
  - `removeBrick(storageRoot, brickHashHex)` — deletes file

### Atomic Brick Writes

Brick writes use a write-rename pattern:
1. Write to `tmp/<hash>.<timestamp>.tmp`.
2. Rename to final location.
3. If the file already exists, skip (idempotent).

This ensures that partial writes are never visible to readers.

### Locking

- **Location**: `locks/<anchorId>.lock`
- **Mechanism**: Exclusive file creation (`wx` mode).
- **Timeout**: 10 seconds with 20ms retry interval.
- **Error handling**: Only `EEXIST` triggers retry; other errors propagate.
- **Cleanup**: Lock file is removed after the action completes (in `finally` block).

### Layout Initialization

`ensureLayout(storageRoot)` creates all four directories (`anchors`, `bricks`, `tmp`, `locks`) recursively.

### Implementation

- `src/storage.js` — All storage operations
- `src/engine.js` — `ensureLayout` call in `open()`

## Decisions & Questions

### Question #1: Why use file-based locking instead of in-memory locks?

**Response:** File-based locking works across processes and handles the case where multiple engine instances access the same storage root. In-memory locks would only protect within a single process.

### Question #2: Why prefix brick directories by the first 2 hex characters?

**Response:** This distributes bricks across 256 subdirectories, preventing filesystem performance degradation from too many files in a single directory. It is a common pattern in content-addressed storage systems.

## Conclusion

The storage layout provides a simple, robust foundation for local DSU storage. Atomic writes, file-based locking, and content-addressed brick storage ensure data integrity and concurrent access safety.
