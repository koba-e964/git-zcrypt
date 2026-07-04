# git-zcrypt

`git-zcrypt` is a Git clean/smudge filter that compresses file bytes with zlib
and encrypts them with ChaCha20-Poly1305 before Git stores them.

Keys are stored locally under `.git/git-zcrypt/`. Raw 32-byte keys can be
generated or imported directly, and password-derived keys can be created with
Argon2id. Encrypted blobs store a hash-prefixed key id such as `sha256:...`;
local aliases map to those ids through `.git/git-zcrypt/index.json`.

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
git-zcrypt generate-key --key default
```

Or derive a key from a password:

```sh
git-zcrypt derive-key --key default
```

For scripted setup, pass the password on stdin. One trailing LF or CRLF is
trimmed before derivation:

```sh
printf '%s\n' "$GIT_ZCRYPT_PASSWORD" | git-zcrypt derive-key --key default --stdin
```

Install the local Git filter config:

```sh
git-zcrypt install-filter --key default
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
git-zcrypt import-key --key default --input default.key
```

Export a local key for backup or transfer:

```sh
git-zcrypt export-key --key default --output default.key
```

Key files and `index.json` are not committed by `git-zcrypt`; they live under
`.git/git-zcrypt/`. Exported keys are raw 32-byte keys. Password-derived keys do
not store KDF metadata; the fixed Argon2id parameters make the same password
produce the same key id. Back keys up and transfer them securely. Losing the key
makes encrypted blobs unrecoverable.

## Safety Notes

Configure `.gitattributes` and run `git-zcrypt install-filter` before adding
sensitive files. If plaintext was committed before the filter was active, it may
already be present in Git history and needs separate history cleanup.

Clean uses a fresh random nonce, so re-cleaning identical plaintext can produce
different ciphertext.
