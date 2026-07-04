# Research: Password KDF Design

## Relevant files and modules

- `progress.toml` tracks `password-kdf-design` as deferred work requiring Argon2id/KDF/password planning.
- `Cargo.toml` currently has explicit `default-features = false` dependency declarations for crypto-adjacent crates. Any new KDF/password dependencies must follow that pattern.
- `src/main.rs` defines the CLI. Current key-related commands are `generate-key`, `import-key`, `export-key`, `install-filter`, `clean`, and `smudge`.
- `src/key_store.rs` owns repository-local state under `.git/git-zcrypt/`, validates key names, stores raw 32-byte keys as `.git/git-zcrypt/keys/<name>.key`, and reads those keys for filters.
- `src/crypto.rs` only accepts a 32-byte key and uses it with ChaCha20-Poly1305. It does not care whether the key is random, imported, or derived.
- `src/blob.rs` stores only `key_id`, nonce, and ciphertext in the encrypted blob format. KDF metadata is not in the blob.
- `src/git_config.rs` installs `filter.git-zcrypt.clean = git-zcrypt clean --key <name>` and `filter.git-zcrypt.smudge = git-zcrypt smudge`.
- `tests/filter_roundtrip.rs` exercises the binary using generated raw keys.
- `README.md` explicitly says password-derived keys are out of scope until this design is approved.

## Execution flow and call graph

Current clean path:

- `main.rs` parses `clean --key <name>`.
- `clean` discovers `KeyStore`.
- `KeyStore::read_key(name)` reads `.git/git-zcrypt/keys/<name>.key` and enforces exactly 32 bytes.
- `compression::compress` compresses stdin bytes.
- `crypto::encrypt` validates key length and key name, generates a random 96-bit nonce, authenticates header/key metadata as AAD, and returns a `Blob`.
- `blob::encode` writes the `GZC1` binary blob to stdout.

Current smudge path:

- `main.rs` parses `smudge`.
- `blob::decode` reads the blob and extracts `key_id`.
- `KeyStore::read_key(blob.key_id)` reads the matching 32-byte local key.
- `crypto::decrypt` authenticates and decrypts.
- `compression::decompress` restores plaintext bytes.

Current setup path:

- `init` creates `.git/git-zcrypt/keys/`.
- `generate-key` creates a random 32-byte raw key file.
- `import-key` copies a user-provided 32-byte raw key file into local storage.
- `export-key` copies the stored raw key to a user-provided output path.
- `install-filter` writes local Git config pointing clean at `clean --key <name>` and smudge at `smudge`.

## Data structures and invariants

- A usable encryption key is exactly 32 bytes, matching ChaCha20-Poly1305 key size.
- Key names are ASCII alphanumeric plus `_` and `-`; they are used in paths and embedded as blob key ids.
- Key names should remain local aliases only. They should not be the stable cross-environment key identity for encrypted blobs.
- The blob key id should be derived from the raw 32-byte key material, for example SHA-256 of the raw key, so different environments can decrypt with the same password-derived or imported raw key without coordinating a shared alias. The key id must include the hash function prefix, such as `sha256:001122...`, to leave room for future hash migration.
- A local key index at `.git/git-zcrypt/index.json` can map derived blob key ids back to local aliases, for example a JSON object shaped like `{"sha256:0123...": "default"}`. Registering a raw key whose derived key id already exists should be a hard error instead of silently adding a second alias for the same key material.
- Local key material lives below `.git/git-zcrypt/`, outside the worktree.
- Current key files are raw bytes only. They have no magic, version, KDF metadata, source type, salt, or parameters. A versioned local key format may be useful, but version `1` can remain stable for a long time while the tool is still unused.
- Blob format version is currently `1` and carries no KDF metadata. Smudge only knows which local key name to load.
- Key files are written with mode `0600` on Unix and synced with `sync_all`.
- Secret key vectors returned from `read_key` use `Zeroizing<Vec<u8>>`. Temporary generated/imported fixed arrays are explicitly zeroized.
- Error messages include paths and lengths but do not print key contents.

## Existing architectural patterns

- Modules are small and domain-specific: blob encoding, compression, crypto, git config, and key storage are separated.
- CLI subcommands delegate quickly to module functions.
- Integration tests spawn the compiled `git-zcrypt` binary in temporary Git repositories.
- Dependency declarations explicitly disable defaults and enable only required features.
- New security-sensitive dependencies require approval before implementation.
- Notes live under `codex-notes/<task-slug>/`, with a separate `feature_list.json` during planning.

## Naming conventions

- Tool and Git filter name: `git-zcrypt`.
- Local state directory: `.git/git-zcrypt/`.
- Current raw key path convention: `.git/git-zcrypt/keys/<name>.key`.
- Current CLI uses explicit verbs such as `generate-key`, `import-key`, and `export-key`.
- Existing docs use “raw 32-byte key” and “password-derived keys” terminology.

## Error handling patterns

- Code uses `anyhow::{Context, ensure, bail}` for user-facing CLI errors.
- Git command failures are converted into contextual errors with stderr content.
- Authentication/decryption failures are intentionally generic: `decryption failed`.
- Invalid key length errors include the observed byte length but not secret data.
- Test assertions commonly check only command success/failure, not exact stderr text.

## Typing conventions

- Key bytes are represented as slices for crypto APIs and `Zeroizing<Vec<u8>>` when read from disk.
- Nonces use fixed `[u8; 12]` arrays.
- Blob data uses owned `Vec<u8>` for encoded/ciphertext bytes.
- Paths are `Path`/`PathBuf`.
- CLI values are owned `String`/`PathBuf` via `clap`.

## Dependency findings

- `argon2` latest from crates.io is `0.6.0-rc.8`, a release candidate. It supports `Argon2id` and has features including `alloc`, `getrandom`, `password-hash`, `kdf`, `parallel`, `rand_core`, and `zeroize`.
- `argon2@0.5.3` is the latest stable Argon2 crate line found. It supports Argon2 variants and features including `alloc`, `password-hash`, `rand`, `std`, and `zeroize`.
- `password-hash` latest is `0.6.1`, stable, and provides PHC/password hash format support with optional `alloc`, `getrandom`, `phc`, and `rand_core` features.
- `rpassword` latest checked is `7.5.4`; it can read hidden passwords from a terminal.
- `secrecy` latest checked is `0.10.3`; it wraps secret values and wipes them on drop.
- The project already has `zeroize`, so password/passphrase bytes can be cleared without necessarily adding `secrecy`.
- Because KDF/password handling is essential security behavior, dependency selection and exact feature flags need explicit approval in the plan.

## Potential pitfalls

- Password-derived keys conventionally use a random salt and fixed KDF parameters. The desired design does not store per-key KDF metadata, which means password derivation must either use fixed application-level derivation inputs or accept that same passwords produce identical raw keys.
- If salt and KDF metadata are stored only under `.git/`, they are not shared by Git. That is acceptable for local setup but means each clone must import or recreate the same metadata to decrypt shared blobs.
- If password-derived key files store only the derived 32-byte key, the password is only a setup mechanism and cannot be re-derived or verified later without preserving metadata elsewhere.
- A key id derived from raw key material, such as SHA-256 of the raw key, solves alias portability but reveals when two encrypted blobs use the same raw key.
- If KDF metadata is stored in the encrypted blob, the blob format changes and every encrypted file carries password/KDF parameters. This makes password smudge portable but broadens the wire format.
- Current blob key id selects a local key by name. It cannot distinguish random raw keys from password-derived keys unless the local key store records that metadata.
- Terminal password prompts are awkward for Git clean/smudge filters, because Git invokes filters non-interactively in many contexts. Prompting during `clean` or `smudge` can hang or fail in automation.
- Passing passwords on command lines leaks through shell history and process listings.
- Reading passwords from environment variables reduces interactivity but can leak through process environments and shell/session configuration.
- Storing raw derived keys locally preserves current clean/smudge behavior but means local compromise of `.git/git-zcrypt/keys/` is enough to decrypt data, just like current raw keys.
- Argon2 parameter choices affect usability: high memory/time costs improve password resistance but can make Git operations slow because clean/smudge may run many times.
- Re-deriving Argon2 on every clean/smudge invocation would be expensive. Password support should instead be a setup-time operation that derives and stores a local raw key for normal filter use.
- If password-derived keys are recoverable only from the password and no KDF metadata is stored, identical passwords can produce identical raw keys and therefore identical key ids. This leakage is an accepted tradeoff for this design.
- There is no backward-compatibility requirement because no one uses the tool yet. This allows changing key file format, blob version, command names, or setup flow if the plan justifies it.

## Constraints

- User explicitly said no backward compatibility is needed because no one uses the tool yet.
- The existing clean/smudge crypto requires a 32-byte key.
- Secrets should not be committed to the repository.
- Git filters need to work with binary stdin/stdout and must not require interactive prompts during normal Git operations unless explicitly designed as an opt-in mode.
- Password support should be setup-time only. Normal `clean` and `smudge` should read stored raw keys and should not prompt for passwords.
- Password entry should support hidden terminal prompts and non-interactive import from stdin. Hidden prompt creation should ask for confirmation. Command-line password arguments should be avoided.
- Raw key commands should remain available after password support, matching the git-crypt-style capability to generate, import, and export raw key material.
- Password-derived key export should export only the raw key when export is supported. KDF metadata should not be stored or exported.
- Once a key is stored, raw generated/imported keys and password-derived keys should be operationally indistinguishable because only raw 32-byte key material is persisted.
- `status` should report available keys by local alias plus derived key id, for example `keys: default (sha256:001122...)`, without trying to label whether the key came from raw import/generation or password derivation.
- `.git/git-zcrypt/index.json` should be updated atomically with temp-file-and-rename because the index does not contain secret material. The JSON object keys, which are hash-prefixed key ids, should be sorted lexicographically by hash/key-id string for easier lookup, and the formatted JSON should have `{` on the first line.
- If key files and `.git/git-zcrypt/index.json` disagree, commands should emit warnings rather than silently ignoring the mismatch.
- Argon2id parameters should be chosen for setup-time use, but the target must be interactive: derivation should finish in about 0.1 seconds on a roughly 10-year-old laptop.
- Dependency defaults must not be accepted blindly; new dependencies need explicit minimal feature selections.
- KDF parameters, salt storage, migration behavior, and secret handling must be designed before implementation.
- The current workflow requires plan approval before implementation.

## Unknowns

- Exact Argon2id parameters: memory cost, time cost, parallelism, output length, and whether to use a fixed application salt/domain separator or another deterministic derivation input. The plan should choose concrete values rather than leaving this open. Planning should benchmark Argon2id on this machine and assume this machine is newer than the 10-year-old-laptop target.
