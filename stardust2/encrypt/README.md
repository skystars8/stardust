# encrypt

Production-grade streaming encryption CLI written in Rust.

**Reliability over speed.** Files of any practical size are processed in 1 MiB chunks so RAM stays bounded. Outputs never overwrite existing files. Finalization is atomic: write to a temp file, `fsync`, then rename.

## Commands

| Command | Purpose | Key file |
|---------|---------|----------|
| `keymake <bytes>` | Deterministic `key.key` from password (prompted twice) | creates `key.key` |
| `otp <in> <out>` | XOR with `key.key` (OTP-style; key ≥ input) | `key.key` |
| `aes <in> <out>` | AES-256-GCM-SIV (auto encrypt/decrypt) | `aes.key` (≥32 B) |
| `xcha <in> <out>` | XChaCha20-Poly1305 (auto encrypt/decrypt) | `key.key` (≥32 B) |
| `ser <in> <out>` | Serpent-256 CTR + HMAC-SHA256 (auto) | `key.key` (≥32 B) |
| `tf <in> <out>` | Threefish-1024 CTR + HMAC-SHA256 (auto) | `key.key` (≥128 B) |

Authenticated modes detect ciphertext by a file magic header: if present → decrypt, otherwise → encrypt.

## keymake

```text
encrypt keymake 1048576
```

- Size range: **1 byte … 20 GiB**
- Password entered twice; mismatch aborts
- Pipeline: **Argon2id** (64 MiB, t=3) → 32-byte seed → **BLAKE3 XOF** expand
- Output is **not** a repeating short block; same password + size → same key
- Refuses to overwrite existing `key.key`

## Build

Requires Rust **1.97.1** (see `rust-toolchain.toml`).

```bash
cargo build --release
```

Binary: `target/release/encrypt` (or `encrypt.exe` on Windows).

## Safety notes

- Wrong password / key → authentication failure (AEAD/HMAC), no silent garbage
- Partial outputs are deleted on error
- Sensitive buffers are zeroized where practical
- OTP is only secure if `key.key` is secret, never reused for two plaintexts, and ≥ file size
