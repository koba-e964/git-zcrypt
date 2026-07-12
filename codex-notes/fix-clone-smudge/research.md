## Relevant Files And Modules

- `src/main.rs`
  - Dispatches CLI commands and implements the filter entry points.
  - `clean` loads a named local key, compresses stdin, encrypts, encodes a blob, and writes ciphertext to stdout.
  - `smudge` reads stdin, decodes a blob, resolves the blob key id through local key state, decrypts, decompresses, and writes plaintext to stdout.

- `src/key_store.rs`
  - Discovers repository-local state below `.git/git-zcrypt/`.
  - Stores keys under `.git/git-zcrypt/keys/`.
  - Stores key-id-to-alias mappings in `.git/git-zcrypt/index.json`.
  - `read_key_by_id` is the current smudge lookup path and fails if the blob key id is not registered locally.
  - Review correction: `.git/git-zcrypt/index.json` is not secret, but it is local-only. The intended direction is for committed manifest files to replace this local index as the durable key-id mapping.

- `src/git_config.rs`
  - `install_filter` writes local Git config:
    - `filter.git-zcrypt.clean = git-zcrypt clean --key <key>`
    - `filter.git-zcrypt.smudge = git-zcrypt smudge`
    - `filter.git-zcrypt.required = true`
  - The required flag means a filter process failure blocks checkout.
  - Current filter commands do not pass the target path to `clean` or `smudge`.

- `src/blob.rs`
  - Defines the committed encrypted blob format.
  - `decode` validates magic, version, key id length, nonce length, reserved byte, UTF-8 key id, and non-empty key id.

- `tests/filter_roundtrip.rs`
  - Integration tests execute the built `git-zcrypt` binary.
  - Existing missing-key coverage currently expects smudge to fail after deleting a key.

- `.gitattributes`
  - Applies `filter=git-zcrypt diff=git-zcrypt` to `secrets/**`.
  - Does not currently identify a committed key manifest path.

- Proposed committed key manifest, per review note
  - A non-secret JSON file should be checked into the repository.
  - Preferred name direction: `zit-crypt-keys.json` or similar.
  - It may live at the repository root or in relevant subdirectories.
  - If multiple manifests are found, file-specific lookup should use the first manifest found by walking ancestor directories from the target file directory upward.
  - This committed manifest should replace the local `.git/git-zcrypt/index.json` role, not merely duplicate it.

## Execution Flow And Call Graph

Clean path:

1. Git invokes `git-zcrypt clean --key <alias>`.
2. `Cli::parse_env` produces `Command::Clean`.
3. `run` calls `clean`.
4. `clean` calls `KeyStore::discover`.
5. `clean` calls `KeyStore::read_key_with_id`.
6. `clean` reads stdin, compresses, encrypts, blob-encodes, and writes stdout.

Smudge path:

1. Git invokes `git-zcrypt smudge`.
2. `Cli::parse_env` produces `Command::Smudge`.
3. `run` calls `smudge`.
4. `smudge` calls `KeyStore::discover`.
5. `smudge` reads stdin.
6. `smudge` calls `blob::decode`.
7. `smudge` calls `KeyStore::read_key_by_id`.
8. `read_key_by_id` validates the key id, reads `.git/git-zcrypt/index.json`, and requires a matching alias.
9. If found, it reads the key file and checks that the key computes to the requested key id.
10. `smudge` decrypts, decompresses, and writes plaintext.

Path-sensitive committed manifest lookup is not possible with the current smudge command shape:

1. Current Git config invokes `git-zcrypt smudge` with only blob bytes on stdin.
2. The command does not receive the target file path.
3. Without the target path, smudge cannot walk from the target file directory upward to choose the nearest committed manifest.
4. A plan that uses per-directory manifests therefore needs a way to pass the target path into the filter command, likely by changing installed filter config and CLI parsing.

Failure observed while creating the issue worktree:

1. Checkout reached `secrets/secret.txt`.
2. Git invoked `git-zcrypt smudge`.
3. The blob decoded with key id `sha256:a8a3cfd8a3833578e4d66ca0acc596fc0aa90df5656d354b3cf91fbd740d4f6c`.
4. No local key index entry existed in the new worktree state.
5. `read_key_by_id` returned `no local key is registered for ...`.
6. Git treated the required smudge filter failure as fatal and aborted checkout.

## Data Structures And Invariants

- Encrypted blob format:
  - Magic: `GZC1\0\0\0\0`
  - Version: `1`
  - Header carries key id length, nonce length, and one reserved byte.
  - Key id is authenticated metadata and must be present.
  - Nonce length must be 12 bytes.

- Key ids:
  - Must be `sha256:` plus 64 lowercase hex characters.
  - Are derived from the raw 32-byte key material.
  - Are used in committed blobs, unlike local aliases.

- Local key store:
  - Key aliases are local names.
  - `.git/git-zcrypt/index.json` maps committed key ids to local aliases.
  - Key files live outside the worktree and are not committed.
  - Current local index contents are not secret; the problem is clone portability, because the file is stored under `.git/` and is therefore absent from fresh clones.

- Committed key manifest:
  - Should contain only non-secret metadata safe to commit.
  - Needs to identify which key ids are expected for files governed by that manifest.
  - Should not contain raw key material.
  - Replaces the current local key-id mapping role now handled by `.git/git-zcrypt/index.json`.
  - Needs a clearly documented relationship to `.gitattributes`: the manifest controls which key ids are expected; attributes control which paths run through the filter.

## Existing Architectural Patterns

- Modules are small and direct: CLI parsing, Git config, key storage, blob encoding, compression, and crypto are separate.
- Errors use the repository-local `Error` type with `Context`, `bail!`, and `ensure!`.
- Secret key bytes use `Zeroizing<Vec<u8>>`.
- Tests prefer black-box integration through the compiled binary for filter behavior.

## Naming Conventions

- CLI commands are explicit verbs: `generate-key`, `derive-key`, `install-filter`, `delete-key`, `clean`, `smudge`.
- Key aliases are called `key` or `name`.
- Stable committed identifiers are called `key_id`.
- Tests are descriptive snake_case function names.

## Error Handling Patterns

- Invalid user input and malformed formats return `Error::msg`.
- `Context` wraps IO and parse failures with path or operation context.
- Existing smudge behavior treats missing local key registration as a hard error.
- Git filter failures surface through stderr and non-zero exit status.
- Review note resolved: warning text is preferred when smudge passes through because a local key is unavailable, as long as the warning does not inhibit Git filter behavior.

## Potential Pitfalls

- Passing through every smudge error would hide corruption or wrong-key failures.
  - Review note: To address this, the repository should check in a non-secret key manifest. The preferred name is `zit-crypt-keys.json` or similar. It can be placed at the repo root or in relevant directories. If multiple manifests are found, use the first one in the target file's ancestor directories, searched from the file directory upward.
- Passing through only missing local key registration preserves validation for malformed blobs and cryptographic failures.
- If smudge succeeds without decrypting, the worktree file contains encrypted bytes. That is acceptable for clone completion but must be documented.
- Because `filter.git-zcrypt.required=true`, any non-zero smudge exit during checkout remains fatal.
- Tests that run Git checkout/clone need filter config available in the cloned repo or command-local config, since local Git config is not committed.
- If a file was checked out as encrypted pass-through bytes before keys were registered, Git will not necessarily rewrite it to plaintext merely because key state changes later. Documentation or setup flow may need to tell users how to force Git to run smudge again after registering the key.
- A manifest lookup based on ancestor directories depends on knowing the target path. The current smudge command lacks that information.
- Keeping both committed manifest files and `.git/git-zcrypt/index.json` as independent key-id mapping sources would create drift risk. The intended design should replace the local index with committed manifests rather than maintaining two durable mappings.

## Constraints

- The fix should keep one logical PR scope: clone/checkout with unavailable local key should not fail.
- Existing encrypted blob format should not change.
- Existing key file format should not change.
- `.git/git-zcrypt/index.json` has never been secret, but it is local-only and should be replaced by committed manifest lookup rather than kept as the durable mapping.
- Normal decryption with a registered key must keep working.
- Missing-key pass-through must not weaken tamper detection when a key is registered.
- Warning text on missing-key pass-through should be included unless testing shows it breaks Git filter behavior.
- Per-directory manifest selection requires path-aware filter invocation.

## Unknowns

- Whether `install-filter` should keep `required=true`.
  - Review note: this is not decided yet.
  - Current research implication: `required=true` is compatible with clone-safe behavior if smudge exits successfully only for the specific missing-local-key case. Disabling `required=true` globally would also let malformed blobs or other filter failures pass checkout more easily, so it needs explicit plan-level justification if chosen.
- Exact user-facing recovery command after importing or deriving the key for a clone that currently has encrypted pass-through bytes in the worktree.
  - The issue is not key registration itself; it is making Git apply smudge again to files already materialized as encrypted bytes.
  - Candidate commands belong in the plan/test phase, where they can be validated instead of guessed.
- Exact committed manifest schema.
  - The research identifies the need for committed, non-secret key-id metadata, but schema choices belong in the plan.
- Migration/removal strategy for `.git/git-zcrypt/index.json`.
  - Current commands write and read this local index.
  - The plan must decide whether to delete this code path immediately, retain a compatibility fallback, or convert existing local index data into committed manifests.
- Exact installed filter command shape for passing target paths.
  - The current command is insufficient for nearest-ancestor manifest lookup.
  - The plan must verify the Git filter placeholder behavior locally before implementation.
