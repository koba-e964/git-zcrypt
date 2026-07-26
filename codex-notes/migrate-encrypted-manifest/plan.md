# Plan: migrate encrypted file key ids into manifests

## Overview

Add a migration CLI command named `register`:
```sh
git-zcrypt register [--manifest-dir <dir>] <file>...
```

Each `<file>` is a current-directory-relative worktree file path, matching shell completion. The selected manifest directory is chosen in this order: explicit `--manifest-dir <dir>`, then the current directory. `--manifest-dir <dir>` is current-directory-relative for interactive shell-completion workflows. The command resolves each file and selected manifest directory, verifies all paths stay inside the worktree, converts files to repository-relative filter paths for manifest entries, and reads encrypted bytes from the resolved worktree files. The selected manifest directory must be an ancestor of every registered file so smudge can find the manifest later. When a matching local key alias exists, it writes that mapping to the selected `git-zcrypt-keys.json`; when no matching local key exists, it warns and creates the selected manifest file without adding an entry. It will not decrypt, re-encrypt, or rewrite encrypted files.

Example: if the current directory is `repo/a/b`, the encrypted file is `repo/a/b/c.secret`, and the desired manifest is `repo/a/git-zcrypt-keys.json`, run:

```sh
cd ..
git-zcrypt init-manifest
git-zcrypt register b/c.secret
```

The command uses the shell-completed path from `repo/a`, creates/updates `repo/a/git-zcrypt-keys.json`, and records the repository-relative file path `a/b/c.secret`.

To run from `repo/a/b` while still creating `repo/a/git-zcrypt-keys.json`, use the manifest override:

```sh
git-zcrypt register --manifest-dir .. c.secret
```

Multiple files can be registered in one invocation:

```sh
git-zcrypt register b/c.secret b/d.secret other/e.secret
```

The command processes files in argument order and writes all entries to the selected manifest. Missing local keys are warnings per file; malformed blobs, paths outside the worktree, a manifest directory that is not an ancestor of every file, manifest conflicts, and unreadable files are errors.

This directly supports migrating existing encrypted repositories to the new committed manifest model introduced by the clone-smudge fix.

## Files to change

- `src/cli.rs`
  - Add `Command::Register { manifest_dir: Option<PathBuf>, paths: Vec<PathBuf> }`.
  - Parse `register [--manifest-dir <dir>] <file>...` as an optional manifest directory plus one or more positional paths.
  - Add the command to usage text and parser tests.


- `src/key_store.rs`
  - Add an API that returns the matching local alias for a key id, likely `key_name_for_id(&self, key_id: &str) -> Result<Option<String>>`.
  - Validate the requested key id.
  - Search sorted local key names for deterministic behavior.
  - Error if more than one alias maps to the same key id, because the manifest stores exactly one alias per key id and silent choice would hide a broken local key store.

- `src/key_manifest.rs`
  - Add helper to resolve cwd-relative worktree file paths to repository-relative filter paths and absolute worktree file paths.
  - Add helper to resolve the selected cwd-relative manifest directory, validate that it is an ancestor of each registered file, and create/read that manifest without inserting a key entry.

- `src/main.rs`
  - Dispatch `Command::Register`.
  - Implement `register(manifest_dir: Option<&Path>, paths: &[PathBuf])`:
    - Discover the local key store.
    - Select the manifest directory from explicit `--manifest-dir` or current directory.
    - For each cwd-relative input path, resolve the absolute worktree file path and repository-relative filter path.
    - Ensure the selected manifest directory is an ancestor of each resolved file path.
    - Read file bytes from the resolved worktree file path and decode the encrypted blob with `blob::decode`.
    - Find the matching local key alias through the new key-store API.
    - If a matching key exists, add the key id/name entry to the selected manifest for `repo_relative_path`.
    - If no matching key exists, emit a warning, ensure the selected manifest file exists, and do not add an entry.

- `tests/filter_roundtrip.rs`
  - Add an integration test proving the migration command updates the selected manifest for an existing encrypted file without rewriting the file.
  - Add a missing-key warning test verifying manifest creation without a key entry.

- `README.md`
  - Document the migration command in the setup/key section.
  - Explain that it works on encrypted worktree files and updates only the manifest.

- `docs/data-formats.md`
  - Mention that manifest entries for legacy encrypted blobs can be populated from the embedded blob key id when the local matching key is available.

## Detailed implementation steps

1. Update CLI parsing in `src/cli.rs`.

   Add the enum variant:

   ```rust
   Register { manifest_dir: Option<PathBuf>, paths: Vec<PathBuf> },
   ```

   Add parser branch:

   ```rust
   "register" => {
       let (manifest_dir, paths) = parse_register("register", &mut args)?;
       Command::Register { manifest_dir, paths }
   },
   ```

   Add usage line:

   ```text
   git-zcrypt register [--manifest-dir <dir>] <file>...
   ```

   Extend `parses_planned_subcommands` with `register`.

2. Add local key alias lookup in `src/key_store.rs`.

   Proposed behavior:

   ```rust
   pub fn key_name_for_id(&self, key_id: &str) -> Result<Option<String>> {
       validate_key_id(key_id)?;
       let mut found = None;
       for name in self.key_names()? {
           let key = self.read_key(&name)?;
           if key_id_for_key_bytes(&key)? == key_id {
               ensure!(found.is_none(), "multiple local keys match {key_id}");
               found = Some(name);
           }
       }
       Ok(found)
   }
   ```

   Keep unreadable key files fatal for this command path. That matches `try_read_key_by_id`, avoids silently missing a matching key, and prevents writing incomplete migration state from a partially broken local key store.

3. Implement command dispatch in `src/main.rs`.

   Proposed flow:

   ```rust
   Command::Register { manifest_dir, paths } => register(manifest_dir.as_deref(), &paths),
   ```

   Proposed function behavior:

   ```rust
   fn register(manifest_dir: Option<&Path>, paths: &[PathBuf]) -> Result<()> {
       let store = key_store::KeyStore::discover()?;
       let manifest = key_manifest::resolve_selected_manifest_dir(manifest_dir)?;
       for path in paths {
           let resolved = key_manifest::resolve_worktree_file(path)?;
           key_manifest::ensure_manifest_covers_path(&manifest, &resolved.repo_path)?;
           let input = std::fs::read(&resolved.worktree_path).with_context(|| {
               format!("failed to read encrypted file {}", resolved.worktree_path.display())
           })?;
           let encrypted = blob::decode(&input).with_context(|| {
               format!("failed to decode encrypted file {}", resolved.input_path.display())
           })?;
           if let Some(key_name) = store.key_name_for_id(&encrypted.key_id)? {
               key_manifest::add_key_to_manifest(&manifest.path, &encrypted.key_id, &key_name)?;
           } else {
               eprintln!(
                   "warning: no local key is registered for {}; leaving manifest entry absent for {}",
                   encrypted.key_id,
                   resolved.repo_path.display()
               );
               key_manifest::ensure_manifest(&manifest.path)?;
           }
       }
       Ok(())
   }
   ```

4. Add integration tests.

   Primary success test:

   - Create repo and local `default` key.
   - Use `clean --key default --path secrets/team-a/secret.txt` to produce encrypted bytes in memory.
   - Write those encrypted bytes to `secrets/team-a/secret.txt` directly.
   - Create `secrets/git-zcrypt-keys.json` as the selected manifest boundary.
   - Run `git-zcrypt register team-a/secret.txt` from the `secrets` directory.
   - Assert `secrets/git-zcrypt-keys.json` contains the encrypted blob key id and `default`.
   - Assert root `git-zcrypt-keys.json` is absent if it was not initialized for the test.
   - Assert file bytes are unchanged after running the command.
   - Assert the command resolves cwd-relative input to the intended repository-relative manifest path.
   - Run `git-zcrypt register --manifest-dir .. secret.txt` from a nested directory and assert it writes to the parent manifest.
   - Run `git-zcrypt register a.secret b.secret` and assert both entries are attempted in one invocation.

   Missing-key warning test:

   - Create repo and local `default` key.
   - Produce encrypted bytes with `clean`.
   - Delete the local key.
   - Write encrypted bytes to a file.
   - Run `register <file>` from a subdirectory.
   - Assert command succeeds and warns with `no local key is registered`.
   - Assert the selected manifest file exists and does not contain the missing key id.

   Parser test:

   - Include `git-zcrypt register secrets/a.txt`, `git-zcrypt register secrets/a.txt secrets/b.txt`, and `git-zcrypt register --manifest-dir secrets secrets/a.txt` in `parses_planned_subcommands`.

5. Update docs.

   README wording:

   - Add a short migration paragraph near the manifest/smudge docs.
   - State that `register` expects one or more cwd-relative encrypted file paths.
   - Document the default current-directory manifest and `--manifest-dir <dir>` override.
   - State the precedence: command-line override, current directory.
   - State it adds a manifest entry only when a matching local key exists; otherwise it creates the selected manifest file and warns.

   Data-format docs:

   - Add one sentence under committed key manifests that existing encrypted blobs carry enough key-id metadata to populate manifests, but the local key alias must be known by matching a local key.

6. Validate.

   Run:

   ```sh
   cargo fmt --check
   cargo test --test filter_roundtrip register -- --exact
   cargo test
   cargo build --release
   ruby -e 'puts File.size("target/release/git-zcrypt")'
   ```

   Also check for applicable validators under `.codex/agents/` and `~/.codex/agents/` after implementation.

## Alternatives considered

- `register-key --path <path>`
  - Rejected because it sounds like it registers a key object, not a file's embedded key id.

- `migrate-file --path <path>`
  - Reasonable, but less explicit about the durable side effect. `register` describes adding the encrypted file to the manifest model.

- `add-manifest-entry --path <path>`
  - Accurate but awkward and too tied to implementation detail.

- Require `--key <name>` as well as `--path <path>`
  - Rejected for this migration case because the command can discover the alias from local key material. Requiring `--key` would make the command less useful and would duplicate the risk of a user choosing an alias whose key id does not match the blob.

- Read encrypted bytes from stdin plus an explicit manifest path.
  - Deferred. It is useful for advanced workflows such as `git cat-file`, but the stated need is a command that takes an encrypted file. A file-path-only command is simpler and less ambiguous.

- Always use the existing upward-search manifest and fail if none exists.
  - Rejected because manual migration should create/update the manifest selected by current directory or `--manifest-dir`, which matches shell-completion workflows better.

## Risks

- If the worktree path contains plaintext rather than encrypted blob bytes, `register` will fail with a decode error. This is expected, but docs should be explicit.
- Local key aliases are local names. The command can record only the alias present in this clone; another clone may use a different alias for the same key unless users standardize names.
- Manually duplicated local key files could create multiple aliases for one key id. The plan treats this as an error to avoid nondeterministic manifest output.
- A selected manifest directory that is not an ancestor of every registered file would produce a manifest smudge cannot find. The command rejects that case.
- The command decodes only the blob envelope and does not verify decryption. Matching key id proves the local key material has the expected SHA-256 hash, but the file could still have corrupted ciphertext. That is acceptable because the command's job is manifest migration, not content verification.

## Test strategy

- Unit/parser coverage in `src/cli.rs` for the new subcommand.
- Integration success coverage in `tests/filter_roundtrip.rs` for selected-manifest update and byte preservation.
- Integration coverage for missing matching local key: warning, manifest file creation, and no key entry.
- Existing full suite should continue covering clean/smudge/key-store behavior.
- Release build and binary-size measurement because this changes CLI and command logic.

## Assumptions

- This is approved to remain in the existing `codex/fix-clone-smudge` PR because it is migration support for the same committed-manifest clone-smudge feature.
- `register` arguments are cwd-relative worktree paths for shell completion; implementation converts them to repository-relative filter paths for manifest entries.
- Advanced stdin/input-path support is out of scope for the first PR; this stays file-path-only, with one or more positional file arguments and an optional `--manifest-dir <dir>` manifest selector.
- If no matching local key exists, the migration command should warn, ensure the manifest file exists, and leave the key entry absent so users can add matching keys later and rerun registration.
- Without `--manifest-dir`, the selected manifest directory is the current directory. With `--manifest-dir <dir>`, the selected manifest directory is that cwd-relative directory.

## Open questions

- None.
