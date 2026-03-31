# Scripts

## Commands

- **`npm run aeneas-install`** — Clone and build aeneas + charon from source. Skips rebuild if the installed version matches the pinned commit.
- **`npm run aeneas-extract`** — Run the extraction pipeline: charon (Rust → LLBC) → aeneas (LLBC → Lean) → post-extraction tweaks.
- **`npm run src-diff`** — Generate `src-modifications.diff` comparing local `src/` against the pinned upstream commit.

## Configuration

All extraction options live in `aeneas-config.yml` at the project root.

## Updating the aeneas version

The aeneas commit is pinned in two places that must be kept in sync:

1. `aeneas-config.yml` — `aeneas.commit` (used by the install/extract scripts)
2. `lakefile.toml` — `rev` in the aeneas `[[require]]` block (used by Lake for the Lean backend dependency)
