# aes — AES-256-GCM-SIV Encryption CLI

A minimal, rock-solid command-line tool for encrypting and decrypting files using **AES-256-GCM-SIV** (RFC 8452).

Designed for maximum reliability and data safety:

- Entire file processed **in memory** (no streaming, no partial writes of ciphertext).
- **Refuses to overwrite** any existing output file (for both encrypt and decrypt).
- Input, output and `key.key` **must be plain filenames in the current working directory** (no path separators). This keeps behaviour identical across platforms.
- Atomic write: data is written to a temporary file then renamed into place.
- Uses the well-audited RustCrypto `aes-gcm-siv` crate (no hand-rolled crypto).
- Key material is zeroized after use.
- Clear, actionable error messages; no panics on expected failure paths.

## Requirements

- Rust 1.85+ (edition 2024, tested with 1.97.1)
- A 32-byte key file named exactly `key.key` in the current working directory.

### Generating a key

```bash
# Linux / macOS
head -c 32 /dev/urandom > key.key

# or with OpenSSL
openssl rand -out key.key 32

# Windows (PowerShell)
[System.IO.File]::WriteAllBytes("key.key", (New-Object byte[] 32 | ForEach-Object { Get-Random -Maximum 256 }))
```

**Keep `key.key` secret.** Anyone with the key can decrypt the files.

## Usage

```text
aes <E|D> <input> <output>
```

- `E` — Encrypt
- `D` — Decrypt
- `<input>` / `<output>` — simple filenames only (no directories, no `..`, no absolute paths)

### Examples

```bash
# Encrypt
aes E secret.txt secret.enc

# Decrypt
aes D secret.enc secret.txt
```

## File format (encrypted)

```
[12-byte nonce][ciphertext || 16-byte tag]
```

The nonce is randomly generated for every encryption and is stored in the clear at the front of the output file. AES-GCM-SIV is misuse-resistant; nonce reuse is far less catastrophic than with classic AES-GCM, but uniqueness is still strongly recommended (and guaranteed by using a CSPRNG).

## Building

```bash
cargo build --release
# binary is at target/release/aes
```

## Security notes

- Uses AES-256-GCM-SIV via the RustCrypto `aes-gcm-siv` 0.11.1 crate.
- No associated data (AAD is empty).
- Maximum practical file size is limited only by available RAM (the whole file is loaded into memory).
- The tool never overwrites existing files and never leaves partial ciphertext behind on failure.
- Always verify that decryption produces the expected content after encryption.

## License

MIT OR Apache-2.0
