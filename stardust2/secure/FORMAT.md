# `secure` encrypted-file format, version 1

All integer fields are unsigned and little-endian. File offsets below are in
bytes. The format deliberately carries no password, key identifier, filename,
timestamp, or other plaintext metadata.

## Header

Every authenticated encrypted file begins with this 64-byte header:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 8 | ASCII magic `SECRv001` |
| 8 | 1 | Format version: `1` |
| 9 | 1 | Algorithm: `1` AES-GCM-SIV, `2` XChaCha20-Poly1305, `3` Serpent, `4` Threefish |
| 10 | 2 | Flags: zero |
| 12 | 4 | Plaintext chunk size: `1,048,576` |
| 16 | 8 | Total plaintext length |
| 24 | 32 | Random per-file salt from the operating-system CSPRNG |
| 56 | 8 | Reserved: zero |

The complete header is authenticated with every chunk. Unknown versions,
flags, algorithms, extensions, chunk sizes, truncation, and trailing bytes are
rejected.

## Key derivation

The complete adjacent key file is read as a stream. It must contain at least
32 bytes. A 32-byte master key is:

```text
BLAKE3 derive_key(ALGORITHM_CONTEXT, LE64(key_file_length) || key_file_bytes)
```

The contexts are:

```text
secure/file-key-master/aes-256-gcm-siv/v1
secure/file-key-master/xchacha20-poly1305/v1
secure/file-key-master/serpent-256-ctr-hmac-sha256/v1
secure/file-key-master/threefish-1024-ctr-hmac-sha256/v1
```

Per-file material is the required number of BLAKE3 keyed-XOF bytes:

```text
BLAKE3_keyed(master_key, PER_FILE_CONTEXT || header_salt)
```

The per-file contexts have the same algorithm suffixes as above, prefixed by
`secure/per-file/`. AES and XChaCha use 32 bytes. Serpent uses 32 encryption
bytes followed by 32 HMAC bytes. Threefish uses 128 encryption bytes followed
by 32 HMAC bytes.

## Chunk records

There are `ceil(plaintext_length / 1,048,576)` records, except that an empty
file has one zero-length record. A record is ciphertext followed by its tag.
The final ciphertext length follows from the authenticated total plaintext
length. Additional authenticated data for chunk `i` is:

```text
header || LE64(i) || LE32(plaintext_chunk_length)
```

AES-256-GCM-SIV uses a 12-byte nonce consisting of four zero bytes followed by
`LE64(i)`, and writes its 16-byte tag. XChaCha20-Poly1305 uses 16 zero bytes
followed by `LE64(i)`, and writes its 16-byte tag. Nonces safely restart in each
file because the random salt derives an independent per-file key.

Serpent-256 and Threefish-1024 use counter mode with independently derived
per-file encryption keys. The global block counter starts at zero and is the
little-endian 128-bit block input; unused Threefish block bytes are zero.
Threefish uses an all-zero tweak. Each resulting ciphertext chunk is followed
by:

```text
HMAC-SHA-256(mac_key, additional_authenticated_data || ciphertext_chunk)
```

The MAC is verified in constant time before counter-mode decryption.

## Deterministic `keymake`

The password bytes are processed with Argon2id version 1.3, 65,536 KiB memory,
three iterations, one lane, a 32-byte output, and the fixed salt
`secure/keymake/argon2id/v1`. A BLAKE3 keyed XOF then uses that output as its
key and absorbs:

```text
secure/keymake/blake3-xof/v1 || LE64(requested_size)
```

The requested number of XOF bytes is `key.key`. Including the exact requested
size separates keys of different lengths. The fixed salt is necessary for the
requested reproducibility; consequently, password guessing is inherently an
offline attack if an attacker obtains enough known key output.
