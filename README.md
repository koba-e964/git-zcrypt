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

For example, deriving key `test` from password `password` produces this raw key
material, whose SHA-256 hash is the stored key id:

```console
$ printf '4fa631b6f1efa130f281c5cca3658b78cc6352f24469a4620bfc83909e0cf483' | xxd -r -p | shasum -a 256
a8a3cfd8a3833578e4d66ca0acc596fc0aa90df5656d354b3cf91fbd740d4f6c  -
```

After `derive-key`, the raw key lives under `.git/git-zcrypt/keys/` and the key
id is recorded in `.git/git-zcrypt/index.json`:

```console
$ hexdump -C .git/git-zcrypt/keys/test.key
00000000  4f a6 31 b6 f1 ef a1 30  f2 81 c5 cc a3 65 8b 78  |O.1....0.....e.x|
00000010  cc 63 52 f2 44 69 a4 62  0b fc 83 90 9e 0c f4 83  |.cR.Di.b........|
$ shasum -a 256 .git/git-zcrypt/keys/test.key
a8a3cfd8a3833578e4d66ca0acc596fc0aa90df5656d354b3cf91fbd740d4f6c  .git/git-zcrypt/keys/test.key
$ cat .git/git-zcrypt/index.json
{
  "sha256:a8a3cfd8a3833578e4d66ca0acc596fc0aa90df5656d354b3cf91fbd740d4f6c": "test"
}
```

Install the local Git filter config:

```sh
git-zcrypt install-filter --key default
```

Add a `.gitattributes` rule before adding sensitive files:

```gitattributes
secrets/** filter=git-zcrypt diff=git-zcrypt
```

For example, this rule filters only files under `secrets/`:

```console
$ mkdir -p secrets
$ printf 'test-secret\n' > secrets/secret.txt
$ git check-attr filter diff -- secrets/secret.txt README.md
secrets/secret.txt: filter: git-zcrypt
secrets/secret.txt: diff: git-zcrypt
README.md: filter: unspecified
README.md: diff: unspecified
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
