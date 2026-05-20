# AGENTS.md

## Scope

LightDSU is a local library for storing, versioning, auditing, and controlling access to encrypted DSUs (Data Security Units). It implements local storage, compact SSIs, signed EventSSIs, encrypted BrickMap, virtual filesystem APIs, access control, and profile-based provenance.

## Mandatory Reading Order

1. `docs/specs/DS001-coding-style.md` — Coding style, module structure, and test organization rules.
2. `docs/specs/DS000-vision.md` — Project vision, scope, and design principles.
3. `docs/specs/matrix.md` — Full specification index.
4. Relevant DS files for the area you are working on.
5. `docs/index.html` — HTML documentation entry point.

## Current Skill Catalog

This project does not import external skills. The following skills are available in `.agents/skills/`:

- `gamp_specs` — Project structure and DS specification generation.
- `review_specs` — DS file review against implementation.
- `achilles_specs` — AchillesAgentLib integration.
- `antropic_skill_build` — Anthropic-style skill conventions.
- `cskill_build` — C-Skill conventions.
- `dgskill_build` — Dynamic Code Generation skill conventions.
- `oskill_build` — Orchestration skill conventions.
- `article_build` — Research article generation.

## Repository Rules

- **DS specifications are the source of truth.** When wording diverges between code and specs, the specs define the intended behavior.
- **When source code changes, update both HTML documentation and DS specifications** to reflect the change.
- **All documentation, specifications, and comments must be written in English.**
- **DS numbering must remain gap-free.** If DS000 through DS014 exist, the next new DS must be DS015.
- **Read `DS001-coding-style.md`** for coding style, module structure, and test-organization rules before writing code.
- **Run `npm test`** before committing any code changes. All 49 tests must pass.
- **Do not create `AGENT.md`** or any other duplicate of this file.
- **Downstream consumer projects** must not put imported-skill DS files or skill pages inside the host project's `docs/` tree.

## Runtime Defaults

- **Language**: JavaScript (CommonJS), Node.js 18+
- **Test runner**: `node --test`
- **Test command**: `npm test`
- **No transpilation**: Plain Node.js

## Key Paths

| Path | Description |
|------|-------------|
| `src/` | Source code |
| `src/index.js` | Public API exports |
| `test/` | Test files |
| `docs/` | HTML documentation and specs |
| `docs/specs/` | DS specification files |
| `docs/specs/matrix.md` | Specification matrix |
| `docs/specsLoader.html` | Specification viewer |
| `docs/index.html` | HTML documentation entry point |
| `docs/lightdsu-v1-spec.md` | Legacy consolidated spec (superseded by DS files) |
| `docs/security-review.md` | Security review and hardening decisions |
