# Research: Compress and Encrypt Git Filter

## Relevant files and modules

- The repository currently has no tracked project files and no commits.
- Existing local Git configuration only contains default repository settings in `.git/config`.
- No `.gitattributes`, filter scripts, Makefile, README, package metadata, or test harness exists yet.
- Upstream git-crypt references checked only for key-file and Git-filter behavior:
  - `key.cpp` / `key.hpp` use a binary field-based key file with a `\0GITCRYPTKEY` preamble, format version, optional key name, and per-version key entries.
  - The upstream key entry fields are AES and HMAC specific, so they are a format reference but not a direct payload match for ChaCha20-Poly1305.
  - The upstream README documents `.gitattributes` as the file-selection mechanism and warns that rules must be in place before sensitive files are added.
  - No compatibility with git-crypt is required.

## Execution flow and call graph

Git content filters are normally wired through `.gitattributes` and local Git config:

- `.gitattributes` assigns `filter=<name>` to path patterns.
- `filter.<name>.clean` transforms worktree content before it is stored in Git.
- `filter.<name>.smudge` transforms stored Git content back into worktree content.

For this request, the intended flow is:

- Clean path: plaintext file bytes from stdin -> compress -> encrypt -> encrypted blob bytes to stdout.
- Smudge path: encrypted blob bytes from stdin -> decrypt -> decompress -> plaintext file bytes to stdout.

Git can run clean and smudge commands as one-shot stdin/stdout filters, which keeps the implementation simple and portable.

## Data structures and invariants

- The filter must preserve arbitrary bytes, so implementation must use binary stdin/stdout.
- Clean output must be acceptable as a Git blob.
- Smudge must exactly invert clean for bytes produced by this filter.
- Compression must run before encryption, because encrypted data is effectively incompressible.
- Decryption must run before decompression in the reverse path.
- Key material must not be committed to the repository.
- Git filter config is local by default; `.gitattributes` can be committed, but secret-bearing config must not be.
- Local keys and derived artifacts should follow a git-internal storage pattern under `.git/git-zcrypt/`, so key material remains outside the worktree and is not committed.
- Because the requested algorithm is ChaCha20-Poly1305, each usable key entry needs at least a 32-byte symmetric encryption key and enough version/name metadata to select it.
- Clean output needs a self-describing blob header carrying at least format magic/version, key identifier or key version, nonce, authentication tag, and ciphertext.
- Key files should use a new ChaCha20-Poly1305-specific format rather than mimicking git-crypt's AES/HMAC fields, to avoid confusion with keys for other services/tools.
- Externally supplied key input may be either raw key material or a password/passphrase. If it is a password, the design needs password-based key derivation with salt and work parameters; the derived/stretched artifact may be stored under `.git/git-zcrypt/`.

## Existing architectural patterns

- None exist yet. This is an empty repository.
- Because there is no existing language or build system, the implementation can establish the project structure.
- User note: Rust is preferred, so a Cargo-based CLI is the expected implementation direction.

## Naming conventions

- No project conventions exist yet.
- The tool/filter name should be `git-zcrypt`; `zcrypt` alone should be avoided because similar names are already taken in multiple places.
- CLI subcommands should make the clean and smudge roles explicit, for example `clean` and `smudge`.
- Key names should be restrictive if they are used in filter names or file paths; git-crypt validates key names as alphanumeric plus `-` and `_`.

## Error handling patterns

- No repository patterns exist.
- Git filters should fail with a non-zero exit status on invalid configuration, encryption failure, decryption failure, or decompression failure.
- Error messages should go to stderr and never include secret values.

## Typing conventions

- No typed language conventions exist.
- If implemented in POSIX shell, correctness depends on delegating binary handling to tools that safely process stdin/stdout.
- If implemented in Python, binary I/O and authenticated encryption can be handled explicitly, but this introduces a runtime and crypto dependency unless using external commands.
- If implemented in Rust, binary I/O, key parsing, compression, and ChaCha20-Poly1305 can be explicit and testable through typed modules and CLI subcommands.
- Rust crypto/random dependencies should come from widely used, maintained sources. Because encryption, randomness, and compression are essential parts, dependency choices require explicit user approval before adoption.
- Crate research:
  - Proposed compression crate: `flate2`, which supports DEFLATE compression/decompression through zlib, gzip, and raw deflate streams, with a default pure-Rust backend.
  - Proposed encryption crate: `chacha20poly1305`, a RustCrypto AEAD crate for ChaCha20-Poly1305 with `getrandom` support by default.
  - Proposed randomness basis: `getrandom`, which retrieves random data from the system source.
  - Password/KDF candidate research:
    - `argon2` latest is `0.6.0-rc.8`, which is a release candidate and should not be adopted for essential KDF behavior without explicit approval of that risk.
    - `argon2@0.5.3` is the latest stable line found; it supports Argon2 variants and has an optional `zeroize` feature.
    - `password-hash` provides PHC/password-hash traits and format support.
    - `zeroize` provides secret memory zeroing support and may be useful for keys/passwords.
  - KDF, password hashing, and secret-memory handling are essential dependency choices and require explicit user approval before adoption.

## Potential pitfalls

- Shell variables cannot safely hold arbitrary binary data; the filter should stream bytes through tools.
- Compression formats may include timestamps or metadata depending on the tool. Deterministic output matters for stable Git blobs.
- Git clean/smudge filters are not automatically configured for every clone unless setup instructions or scripts are provided.
- If a user commits `.gitattributes` before configuring the local filter, Git operations may fail or store unexpected content.
- ChaCha20-Poly1305 is authenticated encryption, so the stored blob format must carry enough metadata to recover the nonce and authentication tag for smudge.
- OpenSSL command-line flags vary across versions, especially for AEAD modes such as ChaCha20-Poly1305. A conservative implementation should verify the selected tool supports the required mode.
- Git filters are deterministic stdin/stdout transforms from Git's perspective, but ChaCha20-Poly1305 normally requires a unique nonce per encryption. The design must choose a nonce strategy that avoids reuse for the same key.
- If random nonces are used, re-cleaning unchanged plaintext may produce different ciphertext, which can affect Git's change detection and blob stability.
- If deterministic nonces are derived from plaintext or compressed plaintext, the design must avoid undermining ChaCha20-Poly1305 security requirements.
- Cryptographically random nonces are not literally guaranteed unique, but 96-bit OS-backed random nonces make collision probability negligible for ordinary repository-scale use. The plan should still state the assumption and limits.
- git-crypt's existing key format carries AES and HMAC keys, while this project needs ChaCha20-Poly1305 key material. Reusing its exact field IDs would be misleading, and no git-crypt compatibility is required.
- Password-based input is possible. If the provided key is a password/passphrase, stretching and salts are necessary; KDF salt, parameters, and derived artifacts can be stored under `.git/git-zcrypt/`.
- Git internally compresses objects using zlib/deflate, not a `.gz` container as a Git filter format.
- Compression recommendation: use zlib/deflate via Rust `flate2`, not gzip. This avoids gzip timestamp/header metadata concerns while staying close to Git's compression family and using a mature streaming Rust API. This requires explicit user approval before implementation.

## Constraints

- Starting point is an empty repository.
- The implementation should avoid committing secrets.
- The clean filter must perform "compress + encryption".
- The smudge filter must perform "decryption + decompress".
- The encryption algorithm must be ChaCha20-Poly1305.
- The filter should be usable with Git's stdin/stdout filter protocol.
- Rust is preferred for the implementation.
- Key material should be supplied externally and stored locally under `.git/git-zcrypt/`.
- File selection should be handled by Git attributes and filter configuration rather than custom path logic in the filter.
- A README is wanted.
- The implementation should include setup and key-management commands, not only `clean` and `smudge`.
- Initial implementation workflow should create stubs for the full command surface first, then implement commands one by one.
- After implementation starts, tasks should be represented in `feature_list.json`, and each command/feature should be small enough to commit separately when commits are requested.

## Resolved notes from review

- Preferred language/runtime: Rust.
- Key source: external key provisioning, with local key/derived-artifact storage under `.git/git-zcrypt/`.
- Target file patterns: handled by Git filters via `.gitattributes`.
- Documentation: include README guidance.
- Key format: prefer a new ChaCha20-Poly1305-specific format to avoid confusion with git-crypt or other service keys.
- Compatibility: no git-crypt compatibility required.
- Command surface: provide setup/key commands in addition to filter commands.
- Compression algorithm recommendation: zlib/deflate via `flate2`, not gzip. Approval required.
- Encryption/randomness dependency recommendation: RustCrypto `chacha20poly1305` plus OS-backed `getrandom`. Approval required.
- Nonce generation recommendation: OS-backed cryptographically random nonce generation is acceptable; uniqueness is probabilistic with negligible collision risk if implemented correctly. Approval required with dependency selection.
- Password/KDF recommendation needed: if password input is supported, choose a password KDF and secret-handling approach. Candidate research currently points to stable `argon2@0.5.3` rather than latest `argon2` release candidate, plus possible `password-hash`/`zeroize`. Approval required.

## Remaining unknowns

- Exact command surface:
  - Which setup/key commands to include in the first implementation, such as `init`, `install-filter`, `import-key`, `export-key`, `status`, and/or `generate-key`.
- Nonce strategy:
  - Needs explicit design detail in the plan, but the research decision is OS-backed random nonces. The plan must specify exact API use and validation so "implemented properly" is defensible.
- Password input scope:
  - Need to decide whether the first implementation supports passwords/passphrases directly, raw key files only, or both. If passwords are in scope, KDF parameters and storage format must be planned.
