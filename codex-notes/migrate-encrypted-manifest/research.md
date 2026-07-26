# Research: migrate encrypted file key ids into manifests

## Request

The migration need is a command that takes an already-encrypted file and adds an entry to the nearest `git-zcrypt-keys.json` whenever the corresponding local key is found.

This is related to the Issue #8 manifest work already in the `codex/fix-clone-smudge` branch: smudge now requires a committed manifest, but existing repositories may already contain encrypted blobs without matching manifest entries.

## Relevant files and modules

- `src/cli.rs`
  - Defines the handwritten CLI parser and the `Command` enum.
  - Current manifest-related command is `init-manifest [--path <dir>]`.
  - Filter commands are `clean --key <name> --path <path>` and `smudge --path <path>`.
  - `parse_key_and_path` supports commands that require both `--key` and a path option.
  - `parse_required_path` supports commands that require only a path option.
  - Usage text must be updated for any new command.

- `src/main.rs`
  - Dispatches parsed commands.
  - `clean()` reads stdin, encrypts with a named local key, calls `key_manifest::add_key_for_path(path, key_id, key_name)`, and writes encrypted bytes.
  - `smudge()` reads stdin, decodes the blob, checks the nearest manifest with `key_manifest::key_allowed_for_path`, then decrypts if local key material exists.
  - There is currently no command that reads an encrypted file from disk, extracts its embedded key id, finds the matching local key alias, and updates a manifest without changing the file bytes.

- `src/blob.rs`
  - `decode(input: &[u8]) -> Result<Blob>` validates the encrypted blob envelope and extracts `Blob { key_id, nonce, ciphertext }`.
  - The key id is embedded in the blob header. No decryption is needed to learn it.
  - Decode validates magic, version, nonce length, reserved byte, UTF-8 key id, and non-empty key id.

- `src/key_store.rs`
  - Local keys live under `.git/git-zcrypt/keys/*.key`.
  - `key_names()` returns sorted local key aliases.
  - `read_key(name)` reads one key file.
  - `read_key_with_id(name)` returns the key material plus computed `sha256:` key id.
  - `try_read_key_by_id(key_id)` only returns key material, not the matching alias name.
  - `indexed_keys()` returns `Vec<KeyStatus> { name, key_id }` and warnings for unreadable key files; this is the existing API that exposes alias names with computed key ids.

- `src/key_manifest.rs`
  - `add_key_for_path(path, key_id, key_name)` validates the key id and key name, locates the nearest existing `git-zcrypt-keys.json` for `path`, or falls back to the repository root manifest if none exists, then inserts the mapping.
  - Existing conflict behavior: if the manifest already maps that key id to the same key name, it is a no-op; if it maps the key id to a different key name, it errors.
  - Existing nearest-manifest behavior is based on `target_dir(root, path)`, where `path` must be repository-relative and must not contain `..`, root, or platform prefix components.
  - `init_manifest(path)` creates a manifest directory and empty manifest.

- `tests/filter_roundtrip.rs`
  - Existing integration helpers can run the compiled `git-zcrypt` binary against temp Git repositories.
  - Existing tests cover clean writing a committed manifest, smudge behavior with/without local keys, and nearest-manifest semantics indirectly through path handling.
  - A migration command test can reuse `filter()` for stdin-based commands, but a command that reads a file path should probably use `Command::new(git_zcrypt())` directly.

- `README.md` and `docs/data-formats.md`
  - README explains setup, manifest behavior, clone-without-key behavior, and re-smudge after importing/deriving a key.
  - Data format docs describe encrypted blob headers and manifest lookup rules.
  - A migration command would need user-facing documentation because it exists specifically for repositories migrating to committed manifests.

## Current execution flow

### New encrypted content

1. Git invokes the clean filter configured by `install-filter`.
2. `clean --key <alias> --path <repo-relative-path>` reads plaintext from stdin.
3. `KeyStore::discover()` finds `.git/git-zcrypt`.
4. `read_key_with_id(alias)` reads local key material and computes its `sha256:` key id.
5. Content is compressed and encrypted.
6. `key_manifest::add_key_for_path(path, encrypted.key_id, alias)` updates the nearest manifest or creates a root manifest.
7. The encrypted blob is written to stdout.

### Checkout / clone smudge

1. Git invokes `smudge --path <repo-relative-path>` with encrypted bytes on stdin.
2. `blob::decode()` extracts the embedded key id.
3. `key_manifest::key_allowed_for_path(path, key_id)` requires the nearest manifest to contain that key id.
4. If local key material is missing, smudge writes the original encrypted bytes and succeeds with a warning.
5. If local key material exists, smudge decrypts and decompresses.

### Existing encrypted content without manifest entry

Observed gap:

1. The encrypted file already contains its key id in the blob header.
2. The local clone may have a key whose computed id matches the blob key id.
3. The repository may lack a manifest entry for the file path.
4. Existing `clean` can add a manifest entry only by re-cleaning plaintext with an explicitly named key, which changes ciphertext because nonces are random and requires plaintext recovery.
5. Existing `smudge` cannot be used to add a manifest entry; it validates the manifest before decrypting.

## Data structures and invariants

- Encrypted blob key ids are embedded as UTF-8 strings and should validate as current key ids (`sha256:` plus 64 lowercase hex chars) before being written to a manifest.
- Manifest entries map key id to local alias name, not to raw key material.
- Manifest files are committed and contain no raw key material.
- Local key aliases are clone-local names and must pass `validate_key_name`.
- The nearest manifest rule matters for subdirectory boundaries: updating the root manifest when a closer manifest exists would make smudge still reject files below that closer boundary.
- If no manifest exists for a path, existing `add_key_for_path` falls back to `root/git-zcrypt-keys.json`.
- Filter paths are expected to be repository-relative and cannot escape the worktree.

## Existing architectural patterns

- CLI parsing is manual, option names are long-form, and errors include command-specific prefixes.
- Command implementations live in `main.rs` as small functions that compose module APIs.
- File/path validation is centralized in the module that owns the behavior (`key_manifest` for manifest paths; `key_store` for key names and key ids).
- Errors use the local `Result`, `ensure!`, `bail!`, and context helpers.
- Tests are a mix of unit tests for pure parsing/format behavior and integration tests that run the compiled binary against temp Git repositories.

## Naming conventions

- Commands use hyphenated names: `init-manifest`, `generate-key`, `install-filter`.
- Options use explicit long names such as `--key`, `--path`, `--input`, `--output`.
- Existing path-bearing filter commands use `--path` for repository-relative filtered paths.
- Existing file-input commands use `--input` for key import; encrypted-file migration could reasonably need either a repository path option or a file input option, but the nearest-manifest requirement means the repository-relative target path is semantically required.

## Error handling patterns

- Missing required options return `<command>: missing --option`.
- Unexpected options return `<command>: unexpected option ...`.
- Invalid paths fail before filesystem mutation.
- Manifest conflicts preserve existing entries and return an error instead of overwriting.
- Local unreadable keys can be warnings in `status`, but command-specific behavior must decide whether unreadable keys should be fatal or simply ignored while searching for a matching key.

## Potential pitfalls

- A command that reads encrypted bytes from stdin without a path cannot know which nearest manifest to update unless it also takes `--path`.
- A command that takes a filesystem path must distinguish between the repository-relative path used for manifest lookup and the disk path used to read bytes. For normal migration these are probably the same path.
- If the worktree file is currently smudged plaintext rather than the encrypted Git blob, `blob::decode()` will fail. Migration may need users to operate on encrypted bytes from the index/HEAD or on a checked-out encrypted file left by missing-key smudge.
- If multiple local aliases somehow map to the same key material, `indexed_keys()` would return multiple names with the same key id. Existing key creation rejects duplicate key material, but legacy/manual file copies could still create this state.
- If no matching local key exists, the command should not add a manifest entry because it cannot know the local alias name to record.
- If a closer subdirectory manifest exists, updating only the root manifest is insufficient for smudge.
- Existing `add_key_for_path` can create a root manifest automatically when no manifest exists. That may or may not be desirable for a migration command, depending on whether the command should require users to initialize boundaries first.

## Constraints

- Keep this in the existing Issue #8 PR only if treated as part of the same clone-smudge manifest migration feature; otherwise it should be split by workflow guardrails.
- Avoid introducing new dependencies for this CLI addition.
- Preserve committed encrypted file bytes; the migration command should only update manifest JSON.
- Preserve current manifest conflict checks.
- Use existing JSON formatting/parsing so manifest output remains stable.

## Unknowns

- Command name is not yet chosen. Candidates should be evaluated in the plan, but no code should be written before approval.
- Exact CLI shape is open: one path option may be enough if the encrypted file path is repo-relative, but separate `--input` and `--path` may be useful for reading encrypted bytes from elsewhere while updating the manifest for a repository path.
- Behavior when no matching local key is found needs confirmation: likely a clear error and no manifest mutation.
- Behavior when multiple local aliases match the embedded key id needs confirmation: likely an ambiguity error unless existing invariants make it impossible enough to choose the first sorted alias.
- Behavior when no manifest exists needs confirmation: reuse current root fallback or require an existing manifest boundary.
