# Data Formats

`git-zcrypt` handles two persistent data structures: committed encrypted blobs
and local repository keys. Encrypted blobs are part of Git history. Local keys
and the key index live under `.git/git-zcrypt/` and are not committed by
`git-zcrypt`.

## Encrypted Blob Format

Clean writes a project-specific binary blob. Before encryption, plaintext bytes
are compressed as a zlib stream. The compressed bytes are encrypted with
ChaCha20-Poly1305, and the AEAD tag is stored as part of the ciphertext bytes
returned by the cipher implementation.

```text
offset  size              field
0       8 bytes           magic: "GZC1\0\0\0\0"
8       1 byte            version: 1
9       1 byte            key_id_len
10      1 byte            nonce_len: 12
11      1 byte            reserved: 0
12      key_id_len bytes  key_id, UTF-8, non-empty
...     12 bytes          ChaCha20-Poly1305 nonce
...     remaining bytes   ChaCha20-Poly1305 ciphertext and tag
```

The authenticated associated data is the header through `key_id`: magic,
version, `key_id_len`, `nonce_len`, reserved byte, and `key_id`. Smudge rejects
unknown magic, unsupported versions, non-12-byte nonces, non-zero reserved bytes,
empty or non-UTF-8 key ids, and authentication failures.

Key ids are currently `sha256:` followed by 64 lowercase hex characters. The
hash is SHA-256 over the raw 32-byte key material, not over a key alias or file
name.

## Local Key File Format

Each local key file is a versioned binary wrapper around raw key material:

```text
offset  size            field
0       8 bytes         magic: "GZCKEY\0\0"
8       1 byte          version: 1
9       1 byte          raw_key_len: 32
10      2 bytes         reserved: 0, 0
12      32 bytes        ChaCha20-Poly1305 key bytes
```

Key names are local aliases and may contain only ASCII letters, digits, `_`, and
`-`. On Unix, `git-zcrypt` writes key files with mode `0600`. Generated,
imported, and password-derived keys all persist in this same versioned format.
Password-derived keys do not persist Argon2id parameters, salt, or other KDF
metadata. `export-key` writes only the raw 32-byte key payload for backup or
transfer.

The local key index maps committed blob key ids back to local aliases:

```json
{
  "sha256:<64 lowercase hex chars>": "<key-name>"
}
```

The index file is `.git/git-zcrypt/index.json`. It is a constrained JSON object
whose keys are hash-prefixed key ids and whose values are key names. Entries are
written in lexicographic key order, duplicate JSON keys are rejected, and both
key ids and key names are validated when the index is read.
