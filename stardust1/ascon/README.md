# ascon — Ascon-AEAD128 Encryption CLI

A minimal, rock-solid command-line tool for encrypting and decrypting files using **Ascon-AEAD128** (NIST SP 800-232 lightweight AEAD).

Designed for maximum reliability and data safety:

- Entire file processed **in memory** (no streaming, no partial writes of ciphertext).
- **Refuses to overwrite** any existing output file (for both encrypt and decrypt).
- Input, output and `key.key` **must be plain filenames in the current working directory** (no path separators). This keeps behaviour identical across platforms.
- Atomic write: data is written to a temporary file then renamed into place.
- Uses the RustCrypto `ascon-aead` crate (no hand-rolled crypto).
- Key material is zeroized after use.
- Clear, actionable error messages; no panics on expected failure paths.

## Why Ascon-AEAD128?

- Winner of the NIST Lightweight Cryptography competition.
- Designed for constrained environments while remaining secure and efficient on modern CPUs.
- 128-bit key and 128-bit nonce.
- Simple, elegant design with strong security margins.

## Requirements

- Rust 1.97.1 (edition 2024)
- A **16-byte** key file named exactly `key.key` in the current working directory.

### Generating a key

```bash
# Linux / macOS
head -c 16 /dev/urandom > key.key

# or with OpenSSL
openssl rand -out key.key 16
```

**Keep `key.key` secret.** Anyone with the key can decrypt the files.

## Usage

```text
ascon <E|D> <input> <output>
```

- `E` — Encrypt
- `D` — Decrypt
- `<input>` / `<output>` — simple filenames only (no directories, no `..`, no absolute paths)

### Examples

```bash
# Encrypt
ascon E secret.txt secret.enc

# Decrypt
ascon D secret.enc secret.txt
```

## File format (encrypted)

```
[16-byte nonce][ciphertext || 16-byte tag]
```

The nonce is randomly generated for every encryption and is stored in the clear at the front of the output file.

## Building

```bash
cargo build --release
# binary is at target/release/ascon
```

## Security notes

- Uses Ascon-AEAD128 via the `ascon-aead 0.6` crate.
- No associated data (AAD is empty).
- Maximum practical file size is limited only by available RAM.
- The tool never overwrites existing files and never leaves partial ciphertext behind on failure.

## License

MIT OR Apache-2.0
