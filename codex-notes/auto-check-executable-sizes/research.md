# Research: auto-check-executable-sizes

## Relevant Files

- `progress.toml`: tracks task completion. `auto-check-executable-sizes` currently has `validation = "false"` and `passes = false`.
- `Cargo.toml`: defines package name `git-zcrypt` and release profile optimized for size with `opt-level = "z"`, `lto = "fat"`, and `codegen-units = 1`.
- `.github/workflows/`: absent before this task, so no existing CI conventions need to be preserved.
- `README.md`: install instructions already use `cargo build --release`; no size policy is documented there.

## Execution Flow

- General Rust CI should check formatting, lints, and tests.
- Release executable size CI should build the binary on each target platform.
- CI should also be available by manual `workflow_dispatch` and should run periodically once per week.
- After `cargo build --release --locked`, the workflow can read the built executable byte size from `target/release/git-zcrypt` or `target/release/git-zcrypt.exe`.
- The job fails when the measured byte size is above a platform-specific threshold.

## Data And Invariants

- The package executable name is `git-zcrypt`.
- Windows uses the `.exe` suffix; Linux and macOS do not.
- Thresholds should be plain byte counts and not comma-separated.
- Thresholds should be based on observed GitHub Actions runner sizes once those measurements are available.
- The check should print the measured size for diagnostics.

## Existing Patterns

- Existing task validation commands in `progress.toml` use `rg` checks and concrete command-line validation.
- GitHub Actions security rules allow `actions/*` by tag. Use the latest compatible `actions/*` tag after verification. Third-party actions must be pinned, so the workflow should avoid third-party actions.

## Pitfalls

- GNU `stat -c%s` is not portable to macOS; BSD `stat -f%z` is not portable to Linux.
- Windows shell differences can make PowerShell/Bash-specific syntax fragile.
- A threshold too close to the current executable size can create CI noise from toolchain variation.

## Constraints

- Use GitHub Actions.
- Include general Rust CI checks.
- Decide executable-size thresholds for each platform.
- Keep the PR scoped to this single task.
