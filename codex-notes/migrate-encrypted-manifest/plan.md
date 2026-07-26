# Plan: migrate encrypted file key ids into manifests

## Overview

Add a migration CLI command named `register-file`:

```sh
git-zcrypt register-file --path <path>
```

The command will read the already-encrypted blob bytes from the repository-relative file path and decode the blob header to get its embedded key id. When a matching local key alias exists, it writes that mapping to the nearest `git-zcrypt-keys.json`; when no matching local key exists, it warns and creates the nearest/root manifest file without adding an entry. It will not decrypt, re-encrypt, or rewrite the encrypted file.

This directly supports migrating existing encrypted repositories to the new committed manifest model introduced by the clone-smudge fix.

## Files to change

- `src/cli.rs`
  - Add `Command::RegisterFile { path: PathBuf }`.
  - Parse `register-file --path <path>` with the existing required path parser.
  - Add the command to usage text and parser tests.

- `src/key_store.rs`
  - Add an API that returns the matching local alias for a key id, likely `key_name_for_id(&self, key_id: &str) -> Result<Option<String>>`.
  - Validate the requested key id.
  - Search sorted local key names for deterministic behavior.
  - Error if more than one alias maps to the same key id, because the manifest stores exactly one alias per key id and silent choice would hide a broken local key store.

- `src/key_manifest.rs`
  - Add helper to create/read the nearest manifest for a path without inserting a key entry.

- `src/main.rs`
  - Dispatch `Command::RegisterFile`.
  - Implement `register_file(path: &Path)`:
    - Discover the local key store.
    - Read file bytes from `path` with context.
    - Decode the encrypted blob with `blob::decode`.
    - Find the matching local key alias through the new key-store API.
    - If a matching key exists, call `key_manifest::add_key_for_path(path, &blob.key_id, &key_name)`.
    - If no matching key exists, emit a warning, ensure the nearest/root manifest file exists, and do not add an entry.

- `tests/filter_roundtrip.rs`
  - Add an integration test proving the migration command updates the nearest manifest for an existing encrypted file without rewriting the file.
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
   RegisterFile { path: PathBuf },
   ```

   Add parser branch:

   ```rust
   "register-file" => Command::RegisterFile {
       path: parse_required_path("register-file", &mut args, "--path")?,
   },
   ```

   Add usage line:

   ```text
   git-zcrypt register-file --path <path>
   ```

   Extend `parses_planned_subcommands` with `register-file`.

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
   Command::RegisterFile { path } => register_file(&path),
   ```

   Proposed function behavior:

   ```rust
   fn register_file(path: &Path) -> Result<()> {
       let store = key_store::KeyStore::discover()?;
       let input = std::fs::read(path)
           .with_context(|| format!("failed to read encrypted file {}", path.display()))?;
       let encrypted = blob::decode(&input)
           .with_context(|| format!("failed to decode encrypted file {}", path.display()))?;
       if let Some(key_name) = store.key_name_for_id(&encrypted.key_id)? {
           key_manifest::add_key_for_path(path, &encrypted.key_id, &key_name)?;
       } else {
           eprintln!(
               "warning: no local key is registered for {}; leaving manifest entry absent for {}",
               encrypted.key_id,
               path.display()
           );
           key_manifest::ensure_manifest_for_path(path)?;
       }
       Ok(())
   }
   ```

4. Add integration tests.

   Primary success test:

   - Create repo and local `default` key.
   - Use `clean --key default --path secrets/team-a/secret.txt` to produce encrypted bytes in memory.
   - Write those encrypted bytes to `secrets/team-a/secret.txt` directly.
   - Create `secrets/git-zcrypt-keys.json` as the nearest manifest boundary.
   - Run `git-zcrypt register-file --path secrets/team-a/secret.txt`.
   - Assert `secrets/git-zcrypt-keys.json` contains the encrypted blob key id and `default`.
   - Assert root `git-zcrypt-keys.json` is absent if it was not initialized for the test.
   - Assert file bytes are unchanged after running the command.

   Missing-key warning test:

   - Create repo and local `default` key.
   - Produce encrypted bytes with `clean`.
   - Delete the local key.
   - Write encrypted bytes to a file.
   - Run `register-file --path ...`.
   - Assert command succeeds and warns with `no local key is registered`.
   - Assert the nearest/root manifest file exists and does not contain the missing key id.

   Parser test:

   - Include `git-zcrypt register-file --path secrets/a.txt` in `parses_planned_subcommands`.

5. Update docs.

   README wording:

   - Add a short migration paragraph near the manifest/smudge docs.
   - State that `register-file` expects encrypted blob bytes at the given repository-relative path.
   - State it adds a manifest entry only when a matching local key exists; otherwise it creates the manifest file and warns.

   Data-format docs:

   - Add one sentence under committed key manifests that existing encrypted blobs carry enough key-id metadata to populate manifests, but the local key alias must be known by matching a local key.

6. Validate.

   Run:

   ```sh
   cargo fmt --check
   cargo test --test filter_roundtrip register_file -- --exact
   cargo test
   cargo build --release
   ruby -e 'puts File.size("target/release/git-zcrypt")'
   ```

   Also check for applicable validators under `.codex/agents/` and `~/.codex/agents/` after implementation.

## Alternatives considered

- `register-key --path <path>`
  - Rejected because it sounds like it registers a key object, not a file's embedded key id.

- `migrate-file --path <path>`
  - Reasonable, but less explicit about the durable side effect. `register-file` describes adding the encrypted file to the manifest model.

- `add-manifest-entry --path <path>`
  - Accurate but awkward and too tied to implementation detail.

- Require `--key <name>` as well as `--path <path>`
  - Rejected for this migration case because the command can discover the alias from local key material. Requiring `--key` would make the command less useful and would duplicate the risk of a user choosing an alias whose key id does not match the blob.

- Read encrypted bytes from stdin plus `--path <path>`.
  - Deferred. It is useful for advanced workflows such as `git cat-file`, but the stated need is a command that takes an encrypted file. A file-path-only command is simpler and less ambiguous.

- Require an existing nearest manifest and fail if none exists.
  - Rejected for consistency with `clean`, which calls `add_key_for_path` and creates a root manifest when no manifest exists. Users who need narrower boundaries can create subdirectory manifests first with `init-manifest`.

## Risks

- If the worktree path contains plaintext rather than encrypted blob bytes, `register-file` will fail with a decode error. This is expected, but docs should be explicit.
- Local key aliases are local names. The command can record only the alias present in this clone; another clone may use a different alias for the same key unless users standardize names.
- Manually duplicated local key files could create multiple aliases for one key id. The plan treats this as an error to avoid nondeterministic manifest output.
- Existing `add_key_for_path` root fallback may create a root manifest when users expected a subdirectory manifest. This matches current clean behavior; docs should tell users to run `init-manifest` in subdirectories first when boundaries matter.
- The command decodes only the blob envelope and does not verify decryption. Matching key id proves the local key material has the expected SHA-256 hash, but the file could still have corrupted ciphertext. That is acceptable because the command's job is manifest migration, not content verification.

## Test strategy

- Unit/parser coverage in `src/cli.rs` for the new subcommand.
- Integration success coverage in `tests/filter_roundtrip.rs` for nearest-manifest update and byte preservation.
- Integration coverage for missing matching local key: warning, manifest file creation, and no key entry.
- Existing full suite should continue covering clean/smudge/key-store behavior.
- Release build and binary-size measurement because this changes CLI and command logic.

## Assumptions

- This is approved to remain in the existing `codex/fix-clone-smudge` PR because it is migration support for the same committed-manifest clone-smudge feature.
- `--path` is repository-relative, matching clean/smudge path semantics.
- If no matching local key exists, the migration command should warn, ensure the manifest file exists, and leave the key entry absent so users can add matching keys later and rerun registration.
- Creating a root manifest when no nearer manifest exists is acceptable because it matches `clean` behavior.

## Open questions

- Is `register-file` the accepted command name, or do you want a different name before implementation?
- Should advanced stdin support be included now, for example `register-file --path <repo-path> --input <encrypted-blob-path>` or `--stdin`, or should this stay file-path-only for the first PR?
  - Note: no. this should stay file-path-only for the first PR
