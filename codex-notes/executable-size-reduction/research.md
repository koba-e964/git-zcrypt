# Executable Size Reduction Research

## Relevant Files and Modules

- `Cargo.toml`: release profile and dependency feature selection.
- `Cargo.lock`: concrete dependency graph for binary-size contributors.
- `src/main.rs`: top-level dispatch, stdin/stdout IO, and command routing.
- `src/cli.rs`: hand-written CLI parser, usage text, and parser errors.
- `src/blob.rs`: encrypted blob container encoding/decoding and AAD construction.
- `src/compression.rs`: zlib compression/decompression through `flate2` with the Rust backend.
- `src/crypto.rs`: ChaCha20-Poly1305 encryption/decryption and nonce generation.
- `src/kdf.rs`: Argon2id password-to-key derivation and hidden prompt input.
- `src/key_store.rs`: key file storage, key index management, Git directory discovery, key-id hashing, and durable file writes.
- `src/git_config.rs`: local Git filter configuration and status reporting.
- `src/index_json.rs`: small project-local JSON string-map formatter/parser to avoid a JSON dependency.

## Current Size Baseline

Command:

```sh
cargo bloat --release --crates
```

Observed output summary:

- File size: `762.8KiB` as reported by `cargo bloat`.
- Exact filesystem size: `781080` bytes from `ls -l target/release/git-zcrypt`.
- `.text` section: `333.8KiB`.
- Largest crate-level contributors:
  - `std`: `241.0KiB` text, `72.2%` of text.
  - `git_zcrypt`: `32.5KiB` text, `9.7%`.
  - `miniz_oxide`: `14.8KiB` text, `4.4%`.
  - `[Unknown]`: `10.4KiB` text, `3.1%`.
  - `anyhow`: `10.4KiB` text, `3.1%`.
  - `blake2`: `6.5KiB` text, `1.9%`.
  - `rpassword`: `6.3KiB` text, `1.9%`.
  - `flate2`: `5.8KiB` text, `1.7%`.
  - `argon2`: `3.5KiB` text, `1.0%`.

Command:

```sh
cargo bloat --release
```

Observed top symbols:

- `git_zcrypt::run`: `13.7KiB`.
- Several `std::backtrace_rs::symbolize::gimli` / `addr2line` functions in the `8.4KiB`, `7.6KiB`, `6.5KiB`, `5.7KiB`, `4.1KiB`, `3.7KiB`, `3.1KiB`, and `3.0KiB` range.
- `<std::process::Command>::output`: `6.8KiB`.
- `blake2::Blake2bVarCore::compress`: `6.1KiB`.
- `miniz_oxide::inflate::core::decompress`: `4.8KiB`.
- `<flate2::zlib::read::ZlibEncoder<R> as std::io::Read>::read`: `4.7KiB`.
- `rpassword::prompt_password`: `3.7KiB`.

## Execution Flow and Call Graph

`main` calls `Cli::parse_env()` and then `run(cli)`. Errors are printed with `eprintln!("error: {error:#}")`, then the process exits with status `1`.

`run` matches one enum variant per subcommand:

- `help`: print static usage.
- `init`: discover Git directory and create `.git/git-zcrypt/keys`.
- `generate-key`: discover key store, generate 32 random bytes, write key, update index.
- `import-key`: read raw 32-byte key from a file, write key, update index.
- `derive-key`: read a password from prompt or stdin, derive a 32-byte Argon2id key, write key, zeroize derived material.
- `export-key`: read a stored key and write raw key material to a destination.
- `delete-key`: remove a key file and any index mapping.
- `install-filter`: set local Git filter config.
- `status`: inspect key/index/config state and print a text summary.
- `clean`: read stdin, compress with zlib, encrypt with ChaCha20-Poly1305, encode blob, write stdout.
- `smudge`: read stdin, decode blob, locate key by id, decrypt, decompress, write stdout.

External process use is limited to `git rev-parse --absolute-git-dir` in `key_store::git_dir`, and `git config --local ...` in `git_config`.

## Data Structures and Invariants

- Raw keys are exactly `32` bytes (`RAW_KEY_LEN`).
- Key ids are `sha256:` followed by exactly 64 lowercase hex chars.
- Key names must be non-empty ASCII alphanumeric plus `_` and `-`.
- Stored key files use a fixed 12-byte header: magic `GZCKEY\0\0`, version `1`, key length `32`, and two reserved zero bytes.
- Blob files use a fixed 12-byte header: magic `GZC1\0\0\0\0`, version `1`, key-id length, nonce length `12`, and one reserved zero byte.
- Encryption AAD is the blob header prefix plus key id.
- The key index is a `BTreeMap<String, String>` persisted as a JSON object from key id to key name.
- Secret key buffers are wrapped in `Zeroizing` or manually zeroized after use.

## Existing Architectural Patterns

- The binary avoids common large CLI/JSON dependencies by using a hand-written argument parser and hand-written JSON parser/formatter.
- Error handling uses `anyhow::{Result, Context, bail, ensure}` throughout production modules.
- Dependency feature sets are already minimized with `default-features = false`.
- The release profile already prioritizes size with `opt-level = "z"`, `lto = "fat"`, and `codegen-units = 1`.
- Tests live in module-local `#[cfg(test)]` blocks plus `tests/filter_roundtrip.rs`.

## Naming Conventions

- Public command-level functions use direct verb names: `clean`, `smudge`, `install_filter`, `print_status`.
- Internal helpers use descriptive snake_case names such as `validate_key_name`, `write_secret_file`, and `aad_for_key_id`.
- Constants are all caps with domain prefixes where useful, for example `RAW_KEY_LEN`, `KEY_FILE_MAGIC`, and `ARGON2_MEMORY_KIB`.

## Error Handling Patterns

- Context-rich filesystem and process errors use `.with_context(...)`.
- Validation failures use `ensure!` and `bail!`.
- AEAD errors are mapped to generic user-facing messages to avoid exposing internals.
- The top-level printer uses alternate formatting `{error:#}`, which may keep more formatting code reachable than a simpler formatter.

## Typing Conventions

- Module APIs generally return `anyhow::Result<T>`.
- Secret key data is either `[u8; RAW_KEY_LEN]` or `Zeroizing<Vec<u8>>`.
- Parsed commands are represented by a `Command` enum.
- Paths use `Path`/`PathBuf`; command-line args begin as `OsString` and are converted to UTF-8 only where required.

## Potential Pitfalls

- Changing compression implementation or level can affect stored clean/smudge data compatibility if the output ceases to be zlib-compatible. Any compression change must preserve zlib decode compatibility for existing encrypted blobs.
- Changing key derivation parameters or algorithm breaks derived-key reproducibility. The existing Argon2id test pins the derived bytes for `b"password"`.
- Replacing `sha2` or key-id formatting changes persisted key ids and encrypted blob lookup.
- Removing rich error context may reduce binary size but would make user failures harder to diagnose.
- Some apparent bloat is from `std`, especially backtrace/symbolization code; profile settings may remove much of it without code-level behavior changes, but must be measured.
- `panic = "abort"` can reduce size, but is not acceptable for this task.
- `strip = "symbols"` can reduce on-disk size, but is not acceptable for this task because local inspection should remain easy.
- `cargo bloat` can show different attribution after stripping or profile changes; exact byte size should be reported separately with `ls -l`.

## Constraints

- Must preserve CLI behavior and data format compatibility.
- Must preserve encryption, randomness, and key derivation security properties.
- Dependency changes in crypto/randomness/KDF/compression are essential project behavior and should be deliberate.
- The repo already optimizes for small dependency surface; remaining easy wins are likely release profile settings and small error/dispatch shape changes.
- Before/after release binary byte sizes and delta must be reported after changes.
- Do not use `strip = "symbols"`; preserving local inspection matters more than that on-disk size reduction.
- Do not use `panic = "abort"`.
- Do not spend time investigating platform-specific strip behavior.
- Split binary / feature-gated command layouts are allowed in principle, but should only be pursued if measurement shows a clear, coherent split. The current command set does not obviously suggest a useful feature boundary.

## Unknowns

- Whether reducing `anyhow` usage in hot/high-fanout dispatch paths would produce enough measurable size improvement to justify the loss of rich context.
- Whether `std::process::Command::output` can be avoided or factored in a way that materially changes binary size without making Git integration worse.
- Whether small code-shape changes around `run`, formatting, and status output move the needle after measuring with the rejected profile levers excluded.
