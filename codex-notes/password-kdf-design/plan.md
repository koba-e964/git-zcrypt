# Plan: Password KDF Design

## Overview

Implement password-derived keys as a setup-time operation. Normal Git filter execution will continue to use stored raw 32-byte keys, so `clean` and `smudge` stay non-interactive and do not run Argon2id.

The main storage change is to stop treating user-facing key names as blob key ids. Key names become local aliases, while encrypted blobs store a hash-prefixed key id derived from the raw key bytes, initially `sha256:<hex>`. A local `.git/git-zcrypt/index.json` maps those key ids back to local aliases for smudge.

Password derivation will not store per-key KDF metadata. The derived raw key is recoverable from the password by using fixed application-level Argon2id parameters and fixed application-level derivation input. This intentionally means the same password produces the same raw key and therefore the same key id.

## Dependency Recommendation

These dependency choices are part of the plan and require approval before implementation:

- `argon2 = { version = "0.5.3", default-features = false, features = ["alloc", "zeroize"] }`
  - Chosen instead of latest `0.6.0-rc.8` because `0.5.3` is the latest stable line found during research.
  - Used only during setup-time password derivation.
- `rpassword = { version = "7.5.4", default-features = false }`
  - Used for hidden terminal passphrase prompts.
- `sha2 = { version = "0.11.0", default-features = false }`
  - Used for `sha256:<hex>` key ids derived from raw key material.

No separate hex or JSON crate is planned. Hex encoding is small enough to implement locally with a fixed lowercase alphabet. The index format is a constrained JSON object whose keys and values are strings, so implement a small local parser/formatter for that exact shape instead of pulling in `serde`/`serde_json`.

`serde-lite` was considered as a smaller alternative to `serde`, but it does not by itself provide JSON file-format parsing/formatting; it is still a serialization framework layer. For this small index file, a constrained local JSON object reader/writer should be smaller and easier to audit.

## Argon2id Parameters

Benchmark method:

- Throwaway project under `/private/tmp/git-zcrypt-argon2-bench`.
- `argon2@0.5.3`, release build, `hash_password_into`, 5 runs per candidate, median reported.
- This machine is assumed to be newer than the target 10-year-old laptop.

Observed medians on this machine:

- `m=8192 KiB, t=1, p=1`: 5.6 ms
- `m=16384 KiB, t=1, p=1`: 7.6 ms
- `m=32768 KiB, t=1, p=1`: 15.5 ms
- `m=65536 KiB, t=1, p=1`: 29.2 ms
- `m=16384 KiB, t=2, p=1`: 11.8 ms
- `m=32768 KiB, t=2, p=1`: 26.4 ms
- `m=65536 KiB, t=2, p=1`: 56.7 ms
- `m=131072 KiB, t=1, p=1`: 59.3 ms

Planned parameters:

- Algorithm: Argon2id
- Version: `0x13`
  - This is the Argon2 algorithm version number, exposed by the Rust crate as `Version::V0x13`, not the git-zcrypt file/blob format version.
- Memory: `32768 KiB`
- Iterations: `2`
- Parallelism: `1`
- Output length: `32` bytes
- Derivation input: fixed application domain string, for example `git-zcrypt password key v1`

Planned Rust invocation shape:

```rust
use argon2::{Algorithm, Argon2, Params, Version};

const ARGON2_MEMORY_KIB: u32 = 32 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const PASSWORD_DOMAIN: &[u8] = b"git-zcrypt password key v1";

let params = Params::new(
    ARGON2_MEMORY_KIB,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
    Some(RAW_KEY_LEN),
)?;
let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
let mut key = [0_u8; RAW_KEY_LEN];
argon2.hash_password_into(password_bytes, PASSWORD_DOMAIN, &mut key)?;
```

Rationale:

- `64 MiB, t=2` is already 56.7 ms on this newer machine and may exceed the 0.1 second target on older laptops.
- `32 MiB, t=2` is 26.4 ms here, leaving more room for older hardware while still being materially stronger than very small memory settings.
- `p=1` avoids depending on CPU core availability and keeps behavior predictable.

## Files To Change

- `Cargo.toml`
  - Add the approved dependency declarations.
- `Cargo.lock`
  - Update via Cargo after dependencies are added.
- `src/key_store.rs`
  - Add key id calculation.
  - Add index read/write/update logic.
  - Change read paths to support alias lookup and key-id lookup.
  - Add password-derived key creation.
- `src/crypto.rs`
  - Stop validating encryption key ids as local key names.
  - Accept hash-prefixed key ids for AAD.
- `src/git_config.rs`
  - Update `status` output to include aliases with key ids.
  - Surface key/index mismatch warnings.
- `src/main.rs`
  - Add the password-derived setup command.
  - Wire clean to encrypt with derived key ids instead of local aliases.
  - Wire smudge to resolve blob key ids through the index.
- `tests/filter_roundtrip.rs`
  - Update integration tests for hash-prefixed blob key ids.
  - Add password-derived key setup tests.
- `README.md`
  - Replace the "password-derived keys are out of scope" note with approved usage.
- `progress.toml`
  - Mark `password-kdf-design` complete only after implementation and validation pass.

## Detailed Implementation Steps

1. Add dependency declarations.
   - Use exactly the feature selections listed above.
   - Run `cargo update` or `cargo check` to refresh `Cargo.lock`.

2. Add key id helpers in `src/key_store.rs`.
   - `key_id_for_key(key: &[u8; RAW_KEY_LEN]) -> String`
   - Return lowercase `sha256:<64 hex chars>`.
   - Add `validate_key_id` for hash-prefixed key ids.
   - Keep `validate_key_name` for local aliases only.

3. Add index support in `src/key_store.rs`.
   - Path: `.git/git-zcrypt/index.json`.
   - Representation: `BTreeMap<String, String>` mapping key id to alias.
   - Read missing index as empty.
   - Parse only a constrained JSON object with string keys and string values. Reject arrays, nested objects, non-string values, duplicate keys, invalid escapes, and trailing non-whitespace data.
   - Serialize pretty JSON with object keys sorted lexicographically by key-id string.
   - Write to a temp file in `.git/git-zcrypt/`, sync the temp file, rename into place, then best-effort sync the state directory on Unix if practical.
   - Keep `{` on the first formatted line by using object-shaped pretty JSON.

4. Update raw key writes.
   - `generate-key` and `import-key` still create raw 32-byte keys under `.git/git-zcrypt/keys/<name>.key`.
   - Before writing, reject an existing alias unless the implementation deliberately adds an explicit overwrite path. The first implementation should avoid silent overwrite.
   - Compute the key id and reject registration if the same key id already exists under any alias.
   - Write the key file with existing `0600` handling, then update `index.json`.

5. Add password-derived setup.
   - Add a CLI command named `derive-key`.
   - `git-zcrypt derive-key --name <alias>` reads a hidden passphrase twice from the terminal and errors if confirmation differs.
   - `git-zcrypt derive-key --name <alias> --stdin` reads the passphrase from stdin until EOF with no confirmation.
   - Do not add command-line passphrase arguments.
   - Derive a 32-byte raw key using the fixed Argon2id parameters, write it through the same registration path as generated/imported raw keys, then zeroize temporary password and key buffers.

6. Update clean/smudge behavior.
   - `clean --key <alias>` reads the local alias key, computes its key id, and passes that key id to `crypto::encrypt`.
   - `smudge` decodes the blob key id, resolves it through `.git/git-zcrypt/index.json`, reads the mapped local alias key, verifies the raw key still computes to the blob key id, then decrypts.
   - If the index is missing the blob key id, fail with a contextual missing-key error.
   - If the index points to a missing file or a file whose raw key computes to a different key id, emit a warning to stderr and fail for decrypting commands.

7. Update `status`.
   - Print keys as `alias (sha256:...)`.
   - Do not label keys as raw, generated, imported, or password-derived.
   - Emit warnings when index entries reference missing key files, key files are not present in the index, or an indexed key file computes to a different key id.

8. Update tests.
   - Unit-test key id formatting, index read/write sorting, duplicate-key rejection, and mismatch warnings where practical.
   - Integration-test raw key round trips with hash-prefixed blob key ids.
   - Integration-test password-derived setup using `derive-key --stdin`.
   - Integration-test duplicate password-derived keys fail because they produce the same key id.

9. Update docs.
   - Document `derive-key` prompt and stdin modes.
   - Document that exported keys are raw 32-byte keys.
   - Document that password-derived keys do not store KDF metadata and same passwords produce same key ids.

## Alternatives Considered

- Store KDF metadata in blobs.
  - Rejected because the desired design keeps password support setup-time only and does not broaden the blob wire format.
- Store per-key KDF metadata under `.git/git-zcrypt/`.
  - Rejected because password-derived keys should be recoverable only from the password and fixed application parameters.
- Derive during `clean` or `smudge`.
  - Rejected because Git filters often run non-interactively and should not prompt or spend KDF time during normal operation.
- Use `64 MiB, t=2` Argon2id.
  - Rejected for the first implementation because it measured 56.7 ms on this newer machine and may exceed 0.1 seconds on old laptops.
- Export encrypted key bundles or KDF metadata.
  - Rejected because export should remain raw-key-only.

## Risks

- Fixed KDF inputs make identical passwords produce identical raw keys and key ids. This is an accepted design tradeoff.
- `index.json` can become inconsistent with key files. The implementation must warn and fail safely for decryption rather than choosing the wrong key.
- `clean` output changes from alias key ids to hash-prefixed key ids. There is no backward compatibility requirement, but existing encrypted blobs from earlier experiments may not smudge.
- Hidden prompt behavior is hard to integration-test fully without a TTY. Unit-test the derivation path and integration-test `--stdin`; keep prompt code thin.
- The planned Argon2id parameters are based on one local benchmark. They may need adjustment if user testing on older hardware misses the target.

## Test Strategy

- Use exact test names in validation commands and pre-check test discovery with `cargo test -- --list` or `cargo test --test <name> -- --list`.
  - This avoids silent success when an expected test has not been added or was renamed.
- Required exact unit tests:
  - `cargo test key_store::tests::key_id_for_key_uses_sha256_prefix -- --exact`
  - `cargo test key_store::tests::index_json_round_trips_sorted_key_ids -- --exact`
  - `cargo test key_store::tests::index_json_rejects_invalid_shapes -- --exact`
  - `cargo test key_store::tests::register_key_rejects_duplicate_key_material -- --exact`
  - `cargo test kdf::tests::argon2id_derives_expected_32_byte_key -- --exact`
  - `cargo test kdf::tests::derive_key_from_password_stdin_trims_single_trailing_newline -- --exact`
  - `cargo test kdf::tests::hidden_prompt_confirmation_mismatch_fails -- --exact`
  - `cargo test git_config::tests::status_lists_aliases_with_hash_prefixed_key_ids -- --exact`
  - `cargo test git_config::tests::status_warns_on_key_index_mismatch -- --exact`
- Required exact integration tests:
  - `cargo test --test filter_roundtrip raw_key_round_trip_uses_hash_prefixed_key_id -- --exact`
  - `cargo test --test filter_roundtrip password_derived_key_round_trips_from_stdin_setup -- --exact`
- Manual prompt smoke test after implementation:
  - `git-zcrypt derive-key --name default` in a test repo, entering matching hidden passphrases.
- Optional timing check:
  - Add or run a temporary local benchmark with the final parameters to confirm setup-time derivation remains interactive.

## Assumptions

- `sha256:<hex>` is acceptable as the initial key id format.
- `derive-key` is an acceptable command name for password-derived setup.
- Rejecting existing aliases is acceptable for the first implementation because silent overwrite can corrupt the alias/index relationship.
- Warnings should go to stderr.
- A local constrained JSON object parser/formatter is acceptable for `.git/git-zcrypt/index.json` to avoid the executable-size cost of `serde`/`serde_json`.

## Open Questions

- Should `derive-key --stdin` trim a trailing newline, or treat stdin bytes exactly?
  - Planned default: trim one trailing `\n` and optional preceding `\r`, matching common shell input behavior, and document it.
- Should a future explicit overwrite command exist for replacing an alias?
  - Planned default: no overwrite in this implementation.
