
# Cipher — Modern Linux File Encryption Tool 🦀

**Secure, fast, and atomic in-place file encryption for Linux.**

A minimalist yet powerful CLI tool that uses **Argon2id** (memory-hard key derivation) + **ChaCha20-Poly1305** (authenticated encryption).  
It encrypts files **in-place atomically** — meaning the original file is only deleted after a successful encrypted version is written, so you never lose data even if the process is interrupted.

---

## Features

- **Linux-only** (optimized atomic operations using `rename()`)
- **Argon2id** key derivation (much stronger than PBKDF2)
- **ChaCha20-Poly1305** AEAD cipher (fast, modern, and secure)
- **Atomic in-place operations**:
  - `encrypt` → creates `.cph` file then safely deletes original
  - `decrypt` → restores original filename then safely deletes `.cph`
- Password confirmation on encryption
- Smart filename handling (restores original extension on decrypt)
- Interactive mode for beginners
- Tiny binary (~1–2 MB after release build)
- No external runtime dependencies
- Built with Rust 2024 edition (requires Rust ≥ 1.94)

---

## Quick Start


# 1. Build the release binary
cargo build --release

# 2. Encrypt a file (replaces original with .cph version)
./cypher encrypt myfile.txt

# 3. Decrypt it (restores original filename)
./cipher decrypt myfile.txt.cph


---

## Usage

### Encrypt a file

cipher encrypt <input-file> [--output <custom.cph>]


- Prompts for password **twice** (confirmation)
- Creates `<filename>.cph`
- **Atomically deletes** the original file after success

**Example:**

cipher encrypt secret.txt
# → secret.txt.cph is created, secret.txt is removed


### Decrypt a file

cipher decrypt <encrypted-file.cph> [--output <custom-name>]


- Prompts for password once
- Restores the original filename and extension
- **Atomically deletes** the `.cph` file after success

**Example:**

cipher decrypt secret.txt.cph
# → secret.txt is restored, secret.txt.cph is removed


### Interactive mode

cipher interactive

Simple menu-driven mode (great for quick use).

---

## Security Notes

- **Strong defaults**: Argon2id with 64 MiB memory, 3 iterations, 4 parallelism.
- All encryption is **authenticated** — any tampering or wrong password is detected.
- Password is never stored or logged.
- Uses cryptographically secure random number generation.
- **This tool has not been independently audited**. Use it for personal or non-critical data. For high-security needs, consider combining with other tools.

**Important**: Always keep a backup until you are comfortable with the tool. Even though operations are atomic, user error (wrong password) or hardware failure can still occur.

---

## Building from Source

```bash
git clone <your-repo>   # or just work in your local folder
cd cipher
cargo build --release
```

The final binary will be at `target/release/cipher`.

**Requirements:**
- Rust 1.94 or newer (`rustup default stable` is usually sufficient)

---

## Project Structure

- `src/main.rs` — Everything is in a single file (no other `.rs` files)
- `Cargo.toml` — Minimal and optimized for size/speed

---

## License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute it however you like.

---

**Made for Linux users who want simple, secure, and reliable file encryption.**

Enjoy! 🔐


---



