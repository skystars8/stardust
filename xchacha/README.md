# xchacha — XChaCha20-Poly1305 Encryption CLI

A minimal, rock-solid command-line tool for encrypting and decrypting files using **XChaCha20-Poly1305**.

Designed for maximum reliability and data safety:

- Entire file processed **in memory** (no streaming, no partial writes of ciphertext).
- **Refuses to overwrite** any existing output file (for both encrypt and decrypt).
- Input, output and `key.key` **must be plain filenames in the current working directory** (no path separators). This keeps behaviour identical across platforms.
- Atomic write: data is written to a temporary file then renamed into place.
- Uses the well-audited RustCrypto `chacha20poly1305` crate (no hand-rolled crypto).
- Key material is zeroized after use.
- Clear, actionable error messages; no panics on expected failure paths.

## Why XChaCha20-Poly1305?

- 192-bit (24-byte) nonce → safe to generate randomly with negligible collision risk.
- Extremely fast in pure software (no AES-NI required).
- Widely deployed (WireGuard, libsodium, etc.).
- Simple and constant-time by design.

## Requirements

- Rust 1.97.1 (edition 2024)
- A 32-byte key file named exactly `key.key` in the current working directory.

### Generating a key

```bash
# Linux / macOS
head -c 32 /dev/urandom > key.key

# or with OpenSSL
openssl rand -out key.key 32
```

**Keep `key.key` secret.** Anyone with the key can decrypt the files.

## Usage

```text
xchacha <E|D> <input> <output>
```

- `E` — Encrypt
- `D` — Decrypt
- `<input>` / `<output>` — simple filenames only (no directories, no `..`, no absolute paths)

### Examples

```bash
# Encrypt
xchacha E secret.txt secret.enc

# Decrypt
xchacha D secret.enc secret.txt
```

## File format (encrypted)

```
[24-byte nonce][ciphertext || 16-byte tag]
```

The nonce is randomly generated for every encryption and is stored in the clear at the front of the output file. The large nonce size makes random nonces safe.

## Building

```bash
cargo build --release
# binary is at target/release/xchacha
```

## Security notes

- Uses XChaCha20-Poly1305 via the RustCrypto `chacha20poly1305 0.11.0` crate.
- No associated data (AAD is empty).
- Maximum practical file size is limited only by available RAM (the whole file is loaded into memory).
- The tool never overwrites existing files and never leaves partial ciphertext behind on failure.
- Always verify that decryption produces the expected content after encryption.

## License

MIT OR Apache-2.0
