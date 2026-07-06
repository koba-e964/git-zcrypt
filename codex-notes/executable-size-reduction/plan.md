# Executable Size Reduction Plan

## Overview

Reduce the release executable size without using the rejected levers:

- Do not add `strip = "symbols"`.
- Do not add `panic = "abort"`.
- Do not spend time on platform-specific strip behavior.
- Do not change crypto, randomness, KDF, compression format, or persisted data formats.

The work should be measurement-driven. First establish a clean worktree-local baseline, then test small, reversible candidate changes. Keep only changes that measurably reduce `target/release/git-zcrypt` size without harming CLI behavior, error usefulness, or local symbol inspection.

## Files to Change

Likely files:

- `src/main.rs`: possible top-level error formatting and command dispatch shape changes.
- `src/git_config.rs`: possible factoring of repeated Git subprocess handling if it reduces duplicated `Command::output` usage.
- `src/key_store.rs`: possible factoring of Git directory subprocess handling with `git_config.rs` if measurement supports it.
- `Cargo.toml`: only for profile settings that preserve inspection and panic behavior, if measured useful.

Planning and tracking files:

- `codex-notes/executable-size-reduction/plan.md`
- `codex-notes/executable-size-reduction/feature_list.json`

Files not expected to change:

- `src/crypto.rs`
- `src/kdf.rs`
- `src/compression.rs`
- `src/blob.rs`
- `src/index_json.rs`
- `Cargo.lock`

## Detailed Implementation Steps

1. Rebuild the current worktree baseline:

   ```sh
   cargo build --release
   ls -l target/release/git-zcrypt
   cargo bloat --release --crates
   cargo bloat --release
   ```

   Record exact file bytes, `.text` size, top crates, and top methods.

2. Probe non-invasive profile/link behavior without committing it first:

   - Try only options that preserve panic behavior and symbol inspection.
   - Do not test `strip = "symbols"` or `panic = "abort"`.
   - If a probe requires a platform-specific linker flag, treat it as evidence only and do not commit it unless it is clearly portable or target-gated.

3. Measure a top-level error formatting change:

   Current:

   ```rust
   eprintln!("error: {error:#}");
   ```

   Candidate:

   ```rust
   eprintln!("error: {error}");
   ```

   This may reduce formatting and context-chain code reachability, but it weakens multi-context diagnostics. Keep it only if the byte savings are meaningful enough to justify the user-facing tradeoff.

4. Measure command dispatch/code-shape changes around `run`:

   - `git_zcrypt::run` is the largest project-local symbol.
   - Try factoring repeated `KeyStore::discover()?` branches or splitting branch bodies into small command functions.
   - Keep only changes that reduce size after `cargo build --release`; LLVM may inline or outline differently, so source-level intuition is not enough.

5. Measure subprocess helper consolidation:

   - `std::process::Command::output` appears high in `cargo bloat --release`.
   - `key_store.rs` and `git_config.rs` both shell out to Git and then convert status/stdout/stderr into `anyhow` errors.
   - Try a small shared helper only if it does not make error messages vague.
   - Keep it only if it reduces binary size and does not create an awkward cross-module abstraction.

6. Stop when marginal candidate changes no longer produce meaningful reductions.

   The goal is a smaller executable, not broad refactoring. If a candidate saves only noise-level bytes while making the code harder to read, revert that candidate.

7. Validate the final patch:

   ```sh
   cargo test
   cargo build --release
   cargo bloat --release --crates
   cargo bloat --release
   ls -l target/release/git-zcrypt
   ```

   Report before/after byte sizes and delta in the final response.

## Alternatives Considered

- `strip = "symbols"`: rejected because preserving local inspection matters.
- `panic = "abort"`: rejected by user.
- Changing compression libraries or formats: rejected for this task because it risks stored clean/smudge compatibility and touches core behavior.
- Changing KDF or crypto dependencies: rejected because this is core security behavior and the current bloat attribution does not justify that risk.
- Feature-gating subcommands or creating split binaries: allowed in principle, but no coherent feature boundary is apparent in the current CLI. It should not be pursued unless measurement reveals a clear split.
- Replacing `anyhow` wholesale: likely too invasive for a first size pass. Consider only targeted reductions if measurement shows enough value.

## Risks

- Size measurements can fluctuate due to incremental build state or symbol attribution. Use exact file bytes as the primary on-disk metric and `cargo bloat` as diagnostic support.
- Error-format reductions may make failures less actionable.
- Refactoring dispatch or subprocess helpers may save little after optimization and could reduce readability.
- Running Git status in this worktree needs git-zcrypt filter overrides because the worktree lacks the local key for `secrets/secret.txt`.

## Test Strategy

- Run `cargo test` to preserve behavior.
- Run `cargo build --release` and compare `target/release/git-zcrypt` byte size against the baseline.
- Run `cargo bloat --release --crates` and `cargo bloat --release` to confirm which contributors changed.
- Use Git status with filter overrides:

  ```sh
  git -c filter.git-zcrypt.clean=cat -c filter.git-zcrypt.smudge=cat -c filter.git-zcrypt.required=false status --short
  ```

## Assumptions

- The exact baseline from research is still representative: `781080` bytes for `target/release/git-zcrypt`.
- The desired output is one scoped patch that reduces the release binary size while preserving existing CLI and data format behavior.
- Small, measured readability-neutral changes are preferred over invasive architectural splits.

## Open Questions

- What threshold counts as "meaningful" savings for a readability tradeoff? Default assumption: keep only changes that save at least a few KiB or are readability-neutral.
