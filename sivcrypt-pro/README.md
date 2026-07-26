# sivcrypt-pro  🦀
A fast, chunked, **AES‑256‑GCM‑SIV** file encryption CLI with robust operations: file locking, symlink refusal, metadata preservation, progress reporting, and **atomic output replace**. It supports **Argon2id passphrase** derivation **or** 32‑byte **key files**, uses a safer chunk layout that binds every chunk to its position (prevents cut‑and‑paste reordering), and decrypts legacy **v2** files while writing safer **v3**.

> **Why this tool?**  
> Each chunk’s nonce is derived from `base_nonce8 || u32_be(index)` and the **entire header is AAD**, so tampering with parameters or reordering chunks breaks authentication.

---

## Features
- **AES‑256‑GCM‑SIV** AEAD (misuse‑resistant to nonce reuse)
- **Chunked encryption/decryption** for bounded memory (great for huge files)
- **Order integrity**: per‑chunk nonce derived from `base_nonce8 || u32_be(index)` (**not stored**)
- **Header‑as‑AAD**: algorithm, version, sizes, salt, KDF params are authenticated
- **Two keying modes**:
  - 32‑byte **key file** (strict permission checks on Unix; defaults to `./key.key`)
  - **Argon2id** passphrase (`--password` or `AES_PASSWORD` env)
- **Atomic replace** of the destination path
- **Operational hardening**: exclusive file locks, symlink refusal, progress bar, restore original permissions & mtime
- **Backward compatible**: decrypts older **v2** files; writes **v3** format

---

## Install / Build
**Version 0.3.0** (Rust 1.94+ / 2024 edition)


git clone <your-repo-or-local-path> sivcrypt-pro
cd sivcrypt-pro
cargo build --release
# optional: install globally
cargo install --path .


Binary: `target/release/sivcrypt-pro`

---

## Quick Start
Encrypt in place with password (Argon2id):

sivcrypt-pro --password --encrypt ./data.bin


Decrypt to a new file:

sivcrypt-pro --decrypt --out ./plain.bin ./data.bin


Use default key file (`key.key` next to input):

sivcrypt-pro --encrypt ./movie.mkv


---

## Usage

USAGE:
    sivcrypt-pro [--encrypt | --decrypt] [OPTIONS] <FILE>


**Modes** (auto-detected if omitted):
- `--encrypt`  
- `--decrypt`

**I/O**:
- `--out <PATH>`          Write output here (default: overwrite input)
- `--chunk-size <N>`      e.g. 4M, 8M, 1M (max 64M, default 4M)
- `--quiet`               No progress bar
- `--yes`                 Assume “yes” for overwrite prompts

**Keying**:
- `--keyfile <PATH>`      32-byte key file (explicit)
- `--password`            Use interactive passphrase (or `AES_PASSWORD` env)

Environment: `AES_PASSWORD` (used instead of prompt)

---

## Security Design
- Full 64-byte header is **AAD** for every chunk  
- Nonce = `base_nonce8 || u32_be(chunk_index)` (v3)  
- Body (v3): `ciphertext || tag(16)`  
- Legacy v2 support with strict validation  
- Atomic writes + fsync + permission/mtime restore  
- Keys are zeroized, passwords never echoed

---

## File Format (v3)
**Header** (exactly 64 bytes):

| Field              | Bytes | Format   | Notes |
|--------------------|-------|----------|-------|
| Magic              | 10    | ASCII    | `AESGCM-SIV` |
| Version            | 1     | u8       | `3` |
| Algorithm          | 1     | u8       | `1` = AES‑256‑GCM‑SIV |
| Flags              | 2     | u16LE    | bit 0 = Argon2 key |
| Chunk size         | 4     | u32LE    | plaintext bytes per chunk |
| File size          | 8     | u64LE    | original plaintext size |
| base_nonce8        | 8     | bytes    | random per file |
| salt16             | 16    | bytes    | only for Argon2 |
| Argon2 m_cost      | 4     | u32LE    | KiB (else 0) |
| Argon2 t_cost      | 4     | u32LE    | iterations (else 0) |
| Argon2 lanes       | 4     | u32LE    | parallelism (else 0) |
| Reserved           | 2     | zero     | padding |

**Body** (per chunk *i*): `ciphertext_i || tag_i(16)`  
Nonce for chunk *i*: `base_nonce8 || u32_be(i)`

---

## Performance & Tuning
- Default chunk size: **4 MiB** (fast & low memory)
- Larger chunks = higher throughput, smaller = lower RAM

---

## Operational Notes
- **Default key file**: If neither `--keyfile` nor `--password` is given, the tool automatically uses `<input_dir>/key.key`
- **Unix key files**: Must be `0600` (tool refuses group/world readable)
- **Windows**: In-place overwrite is disabled — always use `--out` when input == output
- `AES_PASSWORD` env var works for both encrypt & decrypt

---

## Troubleshooting
- “file already appears encrypted” → use `--encrypt` to force
- “key file must be exactly 32 bytes” → `head -c 32 /dev/urandom > key.key && chmod 600 key.key`
- “authentication failed” → wrong password/key or corrupted file
- “trailing data” / length mismatch → file was truncated or tampered with

---

## Roadmap
- `--verify` (read-only integrity check)
- `--stdout` streaming
- `--wipe-input`
- Tunable Argon2 parameters

---

## License
MIT. See `LICENSE`.

---

