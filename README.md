# git-zcrypt

`git-zcrypt` is a Git clean/smudge filter that compresses file bytes with zlib
and encrypts them with ChaCha20-Poly1305 before Git stores them.

Keys are stored locally under `.git/git-zcrypt/`. Raw 32-byte keys can be
generated or imported directly, and password-derived keys can be created with
Argon2id. Encrypted blobs store a hash-prefixed key id such as `sha256:...`.
Committed `git-zcrypt-keys.json` manifests map those key ids to local aliases
without storing raw key material.

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

After `derive-key`, the key lives under `.git/git-zcrypt/keys/` in the versioned
local key format. The key id is recorded in a committed manifest when filtered
content is cleaned:

```console
$ hexdump -C .git/git-zcrypt/keys/test.key
00000000  47 5a 43 4b 45 59 00 00  01 20 00 00 4f a6 31 b6  |GZCKEY... ..O.1.|
00000010  f1 ef a1 30 f2 81 c5 cc  a3 65 8b 78 cc 63 52 f2  |...0.....e.x.cR.|
00000020  44 69 a4 62 0b fc 83 90  9e 0c f4 83              |Di.b........|
$ tail -c 32 .git/git-zcrypt/keys/test.key | shasum -a 256
a8a3cfd8a3833578e4d66ca0acc596fc0aa90df5656d354b3cf91fbd740d4f6c  -
$ cat git-zcrypt-keys.json
{
  "sha256:a8a3cfd8a3833578e4d66ca0acc596fc0aa90df5656d354b3cf91fbd740d4f6c": "test"
}
```

Create a root manifest explicitly when setting up a repository, or let the first
clean create it automatically at the repository root:

```sh
git-zcrypt init-manifest
```

To create a narrower manifest boundary for a subdirectory, initialize one there:

```sh
git-zcrypt init-manifest --path secrets/team-a
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

## Filter Example

Highly compressible input stays compact after clean, and smudge restores the
original bytes:

```console
$ </dev/zero head -c 500000 | wc
       0       1  500000
$ </dev/zero head -c 500000 | git-zcrypt clean --key test --path secrets/zero.bin | wc
       2      14     617
$ </dev/zero head -c 500000 | sha384sum
478a159989441dac6279a2dd45b32a62ecc42f3ffccc976a1652da63e3e7ca4708d43b0f28fd147c5b4072f938cab913  -
$ </dev/zero head -c 500000 | git-zcrypt clean --key test --path secrets/zero.bin | git-zcrypt smudge --path secrets/zero.bin | sha384sum
478a159989441dac6279a2dd45b32a62ecc42f3ffccc976a1652da63e3e7ca4708d43b0f28fd147c5b4072f938cab913  -
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

Delete a local key when it should no longer be available in this clone:

```sh
git-zcrypt delete-key --key default
```

Key files are not committed by `git-zcrypt`; they live under
`.git/git-zcrypt/`. Stored key files are versioned, while exported keys are raw
32-byte keys. Password-derived keys do not store KDF metadata; the fixed
Argon2id parameters make the same password produce the same key id.

`git-zcrypt-keys.json` is committed and contains only key ids and local alias
names. Smudge uses the nearest manifest found by walking from the filtered file's
directory upward to the repository root. If a clone has the manifest but lacks
the matching local key, smudge leaves the encrypted blob bytes in the worktree
and exits successfully with a warning so clone and checkout can finish. After
importing or deriving the missing key, re-smudge a file with:

```sh
git restore --source=HEAD --worktree -- secrets/secret.txt
```

Back keys up and transfer them securely. Losing or deleting the only copy of a
key makes encrypted blobs that use it unrecoverable.

See [docs/data-formats.md](docs/data-formats.md) for the committed encrypted
blob format, committed manifest format, and local key format.

## Safety Notes

Configure `.gitattributes` and run `git-zcrypt install-filter` before adding
sensitive files. If plaintext was committed before the filter was active, it may
already be present in Git history and needs separate history cleanup.

Clean uses a fresh random nonce, so re-cleaning identical plaintext can produce
different ciphertext.
