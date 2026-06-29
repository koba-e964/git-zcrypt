# git-zcrypt

`git-zcrypt` is a Git clean/smudge filter that compresses file bytes with zlib
and encrypts them with ChaCha20-Poly1305 before Git stores them.

This first version uses raw 32-byte symmetric keys stored locally under
`.git/git-zcrypt/`. Password-derived keys are intentionally out of scope until a
separate KDF design is approved.

## Install

Build the CLI from this checkout:

```sh
cargo build --release
```

For normal Git filter use, ensure `git-zcrypt` is available on `PATH`. During
local development, this can be done with:

```sh
cargo install --path .
```

## Set Up A Repository

Initialize local state:

```sh
git-zcrypt init
```

Generate a new raw key:

```sh
git-zcrypt generate-key --name default
```

Install the local Git filter config:

```sh
git-zcrypt install-filter --name default
```

Add a `.gitattributes` rule before adding sensitive files:

```gitattributes
secrets/** filter=git-zcrypt diff=git-zcrypt
```

Check local setup:

```sh
git-zcrypt status
```

## Key Import And Export

Import an existing 32-byte raw key:

```sh
git-zcrypt import-key --name default --input default.key
```

Export a local key for backup or transfer:

```sh
git-zcrypt export-key --name default --output default.key
```

Key files are not committed by `git-zcrypt`; they live under `.git/git-zcrypt/`.
Back them up and transfer them securely. Losing the key makes encrypted blobs
unrecoverable.

## Safety Notes

Configure `.gitattributes` and run `git-zcrypt install-filter` before adding
sensitive files. If plaintext was committed before the filter was active, it may
already be present in Git history and needs separate history cleanup.

Clean uses a fresh random nonce, so re-cleaning identical plaintext can produce
different ciphertext.
