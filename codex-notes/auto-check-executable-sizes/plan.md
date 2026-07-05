# Plan: auto-check-executable-sizes

## Overview

Add a GitHub Actions CI workflow with standard Rust checks and a release executable-size gate for Linux, macOS, and Windows.

## Files To Change

- `.github/workflows/ci.yml`
- `progress.toml`
- `codex-notes/auto-check-executable-sizes/research.md`
- `codex-notes/auto-check-executable-sizes/plan.md`
- `codex-notes/auto-check-executable-sizes/feature_list.json`

## Implementation Steps

1. Create a workflow triggered by pull requests, pushes to `main`, manual `workflow_dispatch`, and a weekly schedule.
2. Add a `rust` job on `ubuntu-latest` that runs:
   - `cargo fmt --check`
   - `cargo clippy --locked --all-targets -- -D warnings`
   - `cargo test --locked`
3. Add an `executable-size` job with a matrix for `ubuntu-latest`, `macos-latest`, and `windows-latest`.
4. Use `actions/checkout@v7`, the latest verified stable tag, which is allowed by the GitHub Actions guardrail.
5. Build each platform executable with `cargo build --release --locked`.
6. Measure executable byte size with Ruby's `File.size`, available on GitHub-hosted runners and portable across the matrix.
7. Set thresholds from GitHub Actions run `28735183007`, with modest headroom over measured sizes:
   - Linux: measured `768480`, threshold `850000`
   - macOS: measured `676032`, threshold `750000`
   - Windows: measured `476672`, threshold `550000`
8. Update `progress.toml` validation to check for the workflow, general Rust CI commands, platform thresholds, portable byte-size measurement, and locked release build.
9. Validate the workflow includes the manual trigger and weekly Monday 00:00 UTC cron schedule.

## Alternatives Considered

- Shell `stat`: rejected because GNU and BSD flags differ.
- Bash `wc -c < file`: plausible, but more fragile on Windows than a Ruby one-liner.
- A separate executable-size workflow: rejected after user clarified that general Rust CI checks should be included too.
- Third-party Rust toolchain actions: unnecessary because GitHub-hosted runners already include Rust here, and avoiding third-party actions keeps workflow pinning simple.
- Older `actions/checkout` tags: rejected because workflow dependencies should use the latest compatible tag unless the user requests otherwise.

## Risks

- Hosted runner toolchain updates can change binary size. The selected thresholds include modest headroom above measured GitHub Actions sizes while still catching large regressions.

## Test Strategy

- Run `cargo fmt --check`.
- Run `cargo clippy --locked --all-targets -- -D warnings`.
- Run `cargo test --locked`.
- Run `cargo build --release --locked`.
- Compare thresholds to GitHub Actions run `28735183007` executable sizes.
- Run the updated `progress.toml` validation command.
