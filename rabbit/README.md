# rabbit

Secure, password-based, authenticated in-place file encryption using the **Rabbit** stream cipher.

- **Cipher**: Rabbit (128-bit key, 64-bit IV) from the RustCrypto ecosystem
- **KDF**: Argon2id (64 MiB memory, 3 iterations)
- **MAC**: BLAKE3 keyed (encrypt-then-MAC)
- **Atomic**: writes to a temporary file then renames (same filesystem required)
- **Cross-platform**: Linux, macOS, Windows, etc.
- **Streaming**: handles large files with fixed 128 KiB buffers

## Install

```bash
cargo install --path .
# or
cargo build --release
```

## Usage

```bash
# Encrypt (or decrypt) a file in place — mode is auto-detected from the header
rabbit secret.txt
```

You will be prompted for a password. On encryption you must confirm it.

- Files that start with the magic `RABBITv2` are treated as encrypted and decrypted.
- Everything else is encrypted.

## Format

```
[8 bytes magic "RABBITv2"]
[16 bytes salt]
[8 bytes IV]
[ciphertext ...]
[32 bytes BLAKE3 MAC]
```

The MAC covers the IV + ciphertext. Wrong password or any modification causes verification failure and the original file is left untouched.

## Security notes

- MAC comparison is constant-time.
- Password and intermediate key material are zeroized.
- Use a strong unique password. Argon2id parameters are suitable for interactive desktop use.
- Atomic replace only works when the temporary file is on the same filesystem as the target.
- Rabbit is a solid eSTREAM cipher; the construction is encrypt-then-MAC with a modern keyed hash.

## License

MIT OR Apache-2.0
