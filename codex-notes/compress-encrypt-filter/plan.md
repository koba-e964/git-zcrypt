# Plan: Compress and Encrypt Git Filter

## Overview

Build an initial Rust CLI named `git-zcrypt` that works as a Git clean/smudge filter:

- `clean`: read plaintext bytes from stdin, compress with zlib/deflate, encrypt with ChaCha20-Poly1305, and write a self-describing encrypted blob to stdout.
- `smudge`: read a blob produced by `clean`, authenticate/decrypt it, decompress it, and write plaintext bytes to stdout.
- Setup/key commands: create local state under `.git/git-zcrypt/`, generate/import/export raw 32-byte keys, install local Git filter config, and report status.

The first implementation should support raw 32-byte symmetric keys only. Password/passphrase support should be deferred until a separate KDF design is approved, because KDF parameters and secret handling are security-sensitive and should not be squeezed into the first change. The deferred KDF/password work is tracked outside this task directory in repo-global `progress.toml` so it is not incorrectly treated as part of the compress/encrypt filter v1 scope.

## Dependency recommendation requiring approval

Before implementation, approve these essential dependencies:

- `chacha20poly1305`: RustCrypto ChaCha20-Poly1305 AEAD implementation.
- `getrandom`: OS-backed random byte generation for 32-byte keys and 96-bit nonces.
- `flate2`: zlib/deflate compression and decompression.
- `zeroize`: clear in-memory secret key buffers where practical.
- `anyhow`: CLI error context without exposing secret values.
- `clap`: subcommand and option parsing.
- `tempfile`: test-only temporary repositories/files.

Rejected for the first implementation:

- `argon2`, `password-hash`: defer password/passphrase input until a separate KDF feature.
- OpenSSL CLI or shell pipelines: cross-version AEAD behavior and binary handling are more fragile than typed Rust code.

## Files to change

- `Cargo.toml`: define the Rust package, binary, dependencies, and dev-dependencies.
- `src/main.rs`: CLI entry point and top-level subcommand dispatch.
- `src/blob.rs`: encrypted blob wire format encode/decode.
- `src/crypto.rs`: ChaCha20-Poly1305 encrypt/decrypt and nonce generation.
- `src/compression.rs`: zlib/deflate compression and decompression helpers.
- `src/key_store.rs`: locate `.git/git-zcrypt/`, read/write raw key files, generate/import/export keys.
- `src/git_config.rs`: install local Git filter configuration and status checks.
- `tests/filter_roundtrip.rs`: integration tests for clean/smudge round trips and tamper rejection.
- `README.md`: usage, setup, `.gitattributes`, key safety, and limitations.
- `.gitignore`: ignore local build outputs if needed; key material stays under `.git/`, not the worktree.

## Command surface

Implement these subcommands first:

- `git-zcrypt init`: create `.git/git-zcrypt/keys/` and metadata directories for the current repository.
- `git-zcrypt generate-key --name <name>`: generate a 32-byte random key and store it locally.
- `git-zcrypt import-key --name <name> --input <path>`: import a 32-byte raw key file.
- `git-zcrypt export-key --name <name> --output <path>`: export a raw local key for backup or transfer.
- `git-zcrypt install-filter --name <name>`: write local Git config:
  - `filter.git-zcrypt.clean = git-zcrypt clean --key <name>`
  - `filter.git-zcrypt.smudge = git-zcrypt smudge`
  - `filter.git-zcrypt.required = true`
- `git-zcrypt status`: report whether local state exists, which key names are available, and whether Git filter config is installed.
- `git-zcrypt clean --key <name>`: filter stdin to stdout using the selected local key.
- `git-zcrypt smudge`: filter stdin to stdout; select the key by key id stored in the encrypted blob.

Key names should be restricted to ASCII alphanumeric, `_`, and `-`.

## Blob format

Use a new project-specific binary format:

```text
magic:      8 bytes   "GZC1\0\0\0\0"
version:    1 byte    1
key_id_len: 1 byte
nonce_len:  1 byte    12
reserved:   1 byte    0
key_id:     key_id_len bytes, UTF-8 key name
nonce:      12 bytes, random per encryption
ciphertext: remaining bytes, includes ChaCha20-Poly1305 authentication tag as produced by the AEAD crate
```

The authenticated associated data should include the fixed header fields and `key_id`, so tampering with metadata is rejected during smudge.

## Detailed implementation steps

1. Scaffold the Rust project with a binary crate and module files.
2. Define the CLI and stub all approved subcommands so the command surface is visible early.
3. Implement key-store discovery:
   - Run `git rev-parse --git-dir` to locate the repository git dir.
   - Store keys under `<git-dir>/git-zcrypt/keys/<name>.key`.
   - Use restrictive permissions on Unix when writing key files.
4. Implement `generate-key`, `import-key`, and `export-key`.
   - Enforce exactly 32-byte raw keys.
   - Validate key names before using them in paths.
5. Implement zlib compression helpers with deterministic defaults.
6. Implement blob encode/decode with strict validation of magic, version, lengths, and reserved fields.
7. Implement encrypt/decrypt:
   - Generate a fresh 96-bit nonce with `getrandom` for every `clean`.
   - Use ChaCha20-Poly1305 with the selected 32-byte key.
   - Include header metadata as AAD.
8. Implement `clean` and `smudge` using binary stdin/stdout only.
9. Implement `install-filter` and `status` with local Git config commands.
10. Add integration tests:
    - Arbitrary binary bytes round trip.
    - Empty input round trip.
    - Tampered ciphertext fails.
    - Unknown key id fails.
    - Invalid key length import fails.
11. Write README setup:
    - `cargo install --path .` or `cargo build`.
    - `git-zcrypt init`.
    - `git-zcrypt generate-key --name default`.
    - `git-zcrypt install-filter --name default`.
    - `.gitattributes` example: `secrets/** filter=git-zcrypt diff=git-zcrypt`.
    - Warning that `.gitattributes` should be configured before adding sensitive files.
    - Warning that keys are not committed and must be backed up/transferred securely.

## Alternatives considered

- Gzip container: rejected because gzip headers can include metadata; zlib/deflate is simpler and closer to Git's internal compression family.
- Deterministic nonce derived from plaintext: rejected for the first implementation because nonce derivation needs careful cryptographic review and can leak plaintext equality. Random 96-bit nonces are the conservative AEAD pattern.
- Password/passphrase input in v1: rejected because a secure KDF design needs explicit parameters, salt storage, upgrade/migration behavior, and user-facing recovery semantics.
- git-crypt-compatible key format: rejected because this project uses ChaCha20-Poly1305, not git-crypt's AES/HMAC key fields.

## Risks

- Random nonces are probabilistic; a 96-bit nonce collision is negligibly likely for normal repository use but not mathematically impossible.
- Re-cleaning identical plaintext will produce different ciphertext because of random nonces, which may affect Git blob stability.
- Local Git filter config is not committed, so every clone must run setup.
- If a user adds sensitive files before `.gitattributes` and filter setup are correct, plaintext may already be in history.
- Key loss makes encrypted blobs unrecoverable.
- This initial design does not support password-derived keys; users must manage raw key files securely.

## Test strategy

- Run `cargo fmt`.
- Run `cargo test`.
- Run manual smoke tests in a temporary Git repository:
  - initialize local state,
  - generate a key,
  - install filter,
  - add a `.gitattributes` rule,
  - verify `git check-attr filter -- <path>` reports `git-zcrypt`,
  - verify a clean/smudge round trip from stdin/stdout.

## Assumptions

- Rust is acceptable for the project.
- No compatibility with `git-crypt` is required.
- Raw 32-byte key support is enough for the first implementation.
- The binary will be available on `PATH` when Git invokes the filter.
- Local key storage under `.git/git-zcrypt/` satisfies the requirement that secrets are not committed.

## Open questions

- Approve the dependency set listed above before implementation?
- Should password/passphrase support be added later as a separate feature using Argon2id?
- Should the default filter name be fixed as `git-zcrypt`, or should `install-filter` support custom filter names in the first version?

## Deferred tracked work

- See repo-global `progress.toml` for cross-task deferred work such as `password-kdf-design`.
