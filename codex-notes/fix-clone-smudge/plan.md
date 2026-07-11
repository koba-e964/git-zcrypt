## Overview

Fix issue 8 by making key-id metadata clone-portable. The local `.git/git-zcrypt/index.json` is non-secret but unavailable in fresh clones, so it should be replaced as the durable mapping by committed non-secret manifest files named `zit-crypt-keys.json`.

The manifest lookup must be path-sensitive: for a filtered file, use the nearest `zit-crypt-keys.json` found by walking from the file's directory upward toward the repository root. To support that, installed Git filter commands must pass the filtered path to `clean` and `smudge` using Git's filter path placeholder. The implementation should verify the placeholder behavior in tests before relying on it.

When smudge sees a well-formed encrypted blob whose key id is allowed by the committed manifest but whose local key file is not present, it should warn to stderr, write the original encrypted bytes to stdout, and exit successfully. This lets clone and checkout complete without local key material. Malformed blobs, manifest mismatches, wrong keys, and decryption failures with an available key remain hard failures.

## Files To Change

- `src/cli.rs`
  - Add path options to the filter commands.
  - `clean` should accept `--path <path>` in addition to `--key <alias>`.
  - `smudge` should accept `--path <path>`.

- `src/git_config.rs`
  - Install path-aware filter commands, likely:
    - `git-zcrypt clean --key <key> --path %f`
    - `git-zcrypt smudge --path %f`
  - Keep `filter.git-zcrypt.required=true` initially.
  - Update `status` to report committed manifest state instead of local index state.

- `src/main.rs`
  - Pass the target path from CLI parsing into `clean` and `smudge`.
  - On clean, update the nearest committed manifest for the path with the blob key id produced for the selected key.
  - On smudge, use the target path to find the nearest committed manifest and validate that the blob key id is declared there.
  - If the manifest declares the blob key id but no local key material exists, warn and pass encrypted bytes through unchanged.

- `src/key_store.rs`
  - Stop using `.git/git-zcrypt/index.json` as the durable key-id mapping.
  - Keep local key files under `.git/git-zcrypt/keys/`.
  - Resolve local key material by computing each local key file's key id and matching it to the manifest-declared blob key id.
  - Preserve duplicate-key-material detection where practical by scanning local keys.
  - Remove or deprecate index write/read paths after replacement behavior is covered.

- New module, likely `src/key_manifest.rs`
  - Own committed `zit-crypt-keys.json` parsing and formatting.
  - Find the nearest manifest for a target path by walking ancestors from file directory upward.
  - Update manifests atomically when clean introduces a key id.
  - Validate key ids with existing `key_store::validate_key_id`.

- `tests/filter_roundtrip.rs`
  - Add integration coverage for path-aware filter commands.
  - Add clone/checkout coverage with committed manifests but no local key material.
  - Update existing missing-key expectations to pass-through behavior only when the manifest authorizes the key id.

- `README.md`
  - Document `zit-crypt-keys.json`, nearest-ancestor lookup, clone behavior without local keys, and how to re-smudge files after importing or deriving keys.

- `docs/data-formats.md`
  - Document the committed manifest format.

- `codex-notes/fix-clone-smudge/feature_list.json`
  - Track implementation tasks and validation commands.

## Detailed Implementation Steps

1. Verify Git filter path placeholder behavior.
   - Add a focused integration test or temporary test harness that configures a filter command containing `%f` and confirms Git passes the filtered path as an argument.
   - Use the validated command shape in `install_filter`.
   - If `%f` needs quoting or has path separator edge cases, encode that in tests before implementation proceeds.

2. Add CLI path parsing for filters.
   - Change `Command::Clean { key }` to `Command::Clean { key, path }`.
   - Change `Command::Smudge` to `Command::Smudge { path }`.
   - Add tests for:
     - `clean --key default --path secrets/a.txt`
     - `smudge --path secrets/a.txt`
     - duplicate/missing/unexpected options.

3. Introduce committed manifest support.
   - Use `zit-crypt-keys.json` as the manifest filename.
   - Start with a constrained JSON object rather than free-form JSON.
   - Proposed schema for planning:
     ```json
     {
       "version": 1,
       "keys": [
         "sha256:<64 lowercase hex chars>"
       ]
     }
     ```
   - Keep keys sorted lexicographically for stable diffs.
   - Reject malformed JSON, unsupported version, missing `keys`, duplicate key ids, and invalid key ids.
   - Find the relevant manifest by walking ancestors of the filtered file path from deepest to shallowest.

4. Replace local index lookup with local key scanning.
   - Keep `.git/git-zcrypt/keys/<alias>.key` as the local secret-key storage.
   - Add a method that scans local key files, computes each key id, and returns the matching key for a requested key id.
   - If no local key matches, return a typed or distinguishable missing-local-key result.
   - If a local key file is malformed, surface a warning or hard error according to the command context:
     - Smudge for a manifest-declared key with no matching local key should pass through only when no matching key exists.
     - Smudge should still fail if it finds a matching key but decrypt/decompress fails.

5. Update key creation commands.
   - `generate-key`, `derive-key`, and `import-key` should still create local key files.
   - They should not write `.git/git-zcrypt/index.json`.
   - Duplicate key material detection should scan local keys rather than consult local index.
   - `delete-key` should remove only local key files; it should not remove committed manifest declarations because those describe repository data, not local possession.

6. Update clean behavior.
   - Resolve selected local key alias as today.
   - Compute its key id and encrypt with that id as today.
   - Find or create the nearest applicable `zit-crypt-keys.json` for the target path.
   - Add the key id if absent and write the manifest with stable formatting.
   - Do not write `.git/git-zcrypt/index.json`.

7. Update smudge behavior.
   - Decode the blob first; malformed blobs remain fatal.
   - Find the nearest committed manifest for the target path.
   - Fail if no manifest exists or if the blob key id is not listed in the manifest.
   - Scan local key files for a matching key id.
   - If no matching key is present, print a warning to stderr, write the original encrypted input to stdout, and return success.
   - If a matching key is present, decrypt and decompress as today.

8. Preserve `filter.git-zcrypt.required=true` unless validation shows it prevents the intended pass-through.
   - The intended pass-through exits with status 0, so `required=true` should remain compatible.
   - Keeping it true preserves hard failures for malformed blobs and manifest mismatches.

9. Document recovery after key setup.
   - Validate a concrete command for re-smudging pass-through files after the user imports or derives a key.
   - Candidate to validate in tests: `git checkout -- path` or an equivalent forced checkout command.
   - Document only the validated command.

10. Update data-format documentation and README.
    - Explain that `zit-crypt-keys.json` is safe to commit because it contains key ids, not raw keys.
    - Explain nearest-ancestor lookup.
    - Explain that a clone without local keys may contain encrypted pass-through bytes until keys are registered and files are re-smudged.

## Alternatives Considered

- Only pass through missing local key errors without a committed manifest.
  - Rejected because it hides too much: a fresh clone cannot know whether the key id is expected for that path or whether the blob is unexpected repository data.

- Commit `.git/git-zcrypt/index.json` directly.
  - Rejected because files under `.git/` are not part of the worktree and cannot be committed normally. The concept is useful, but it needs a committed worktree manifest file.

- Keep both `.git/git-zcrypt/index.json` and committed manifests.
  - Rejected as the durable design because two mapping sources can drift. A short compatibility fallback can be considered only if needed, but the target behavior should use committed manifests.

- Disable `filter.git-zcrypt.required`.
  - Rejected for the initial plan because a status-0 pass-through for the specific missing-local-key case should be compatible with `required=true`, while disabling it would make unrelated filter failures easier to miss.

- Put all key ids in one root-only manifest.
  - Rejected because the requested behavior allows manifests in relevant subdirectories with nearest-ancestor lookup.

## Risks

- Git path placeholder behavior may differ from assumptions. This must be validated before implementing path-sensitive lookup.
- Existing repositories with `.git/git-zcrypt/index.json` will need a transition path or clear breakage note.
- Pass-through files are encrypted bytes in the worktree; users need a validated recovery command after key setup.
- Manifest lookup can fail if the file path is absolute, outside the worktree, or contains `..`; path normalization must be conservative.
- Clean updating a committed manifest means normal encryption can modify both the secret file and `zit-crypt-keys.json`; docs and tests should make this expected.
- Scanning all local key files for each smudge may be slower than index lookup in repositories with many keys. This is acceptable initially, but the implementation should keep the scan simple and measurable.

## Test Strategy

- Unit tests:
  - CLI parses path-aware `clean` and `smudge`.
  - Manifest parser rejects malformed schemas and invalid key ids.
  - Manifest formatter produces stable sorted output.
  - Manifest lookup chooses the nearest ancestor manifest.
  - Local key scanning resolves a key by computed key id.

- Integration tests:
  - `cargo test --test filter_roundtrip raw_key_round_trip_uses_hash_prefixed_key_id -- --exact`
  - New test: clean writes/updates `zit-crypt-keys.json` for the filtered path.
  - New test: smudge fails when the manifest is missing.
  - New test: smudge fails when the manifest does not list the blob key id.
  - New test: smudge passes through with a warning when the manifest lists the key id but no local key exists.
  - New test: clone/checkout with committed manifest and no local key succeeds and leaves encrypted bytes in the worktree.
  - New test: after importing/deriving the key, the validated recovery command rewrites pass-through bytes to plaintext.

- Full validation:
  - `cargo fmt --check`
  - `cargo test`
  - If binary-size-sensitive changes are expected from new dependencies, avoid new dependencies; otherwise build release and report size.

## Assumptions

- `zit-crypt-keys.json` is an acceptable final filename unless review changes it.
- The manifest contains key ids only, not raw keys.
- The local secret key files remain in `.git/git-zcrypt/keys/`.
- A manifest-declared missing local key should warn and pass through.
- A manifest mismatch should fail even if the local key exists.
- `required=true` should remain unless tests show it blocks the intended behavior.

## Open Questions

- Confirm final manifest filename: `zit-crypt-keys.json` versus another exact spelling.
- Confirm final manifest schema before implementation.
- Decide whether to retain a short compatibility fallback for existing `.git/git-zcrypt/index.json`, or remove it entirely in this PR.
- Confirm the validated re-smudge command to document after key setup.
