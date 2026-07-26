# 🔐 AES — Secure File Encryption Tool (AES-256-GCM-SIV)

---

## Overview

**AES** is a secure, minimal, and robust file encryption tool written in Rust. It is designed with strong cryptographic guarantees, safe file handling, and resistance to common implementation mistakes.

It uses **AES-256-GCM-SIV**, a modern authenticated encryption mode that remains secure even if nonces are accidentally reused.

TINY codebase, absurdly easy to audit or maintain. 

---

## ⚠️ Design Philosophy

This tool is intentionally opinionated:

* ✅ **Linux/Unix only**
* ✅ **No passwords** (no KDF, no passphrase mode)
* ✅ Requires a **raw 32-byte key file (`key.key`)**
* ✅ Focused on **security, simplicity, and correctness**

> This is not a beginner-friendly encryption tool. It assumes you understand key management.

---

## Features

### 🔒 Cryptographic Security

* AES-256-GCM-SIV (misuse-resistant AEAD)
* Full authentication (integrity + authenticity)
* Header authenticated via AEAD AAD
* Per-chunk independent authentication

### 📦 File Safety

* Atomic writes (`.tmp` → rename)
* Crash-safe design
* Detection of:

  * Corruption
  * Truncation
  * Extra trailing data
  * Chunk reordering

### ⚡ Performance

* Streaming encryption (8 MB chunks)
* Constant memory usage
* Handles very large files

---

## Installation

### Requirements

* Rust (latest stable recommended)

### Build


cargo build --release


Binary will be located at:


target/release/aes


---

## 🔑 Key Setup

You **must** create a file named:


key.key


### Requirements:

* Exactly **32 bytes** (256 bits)
* File permissions: **0600**
* Located in the **same directory as the executable**

### Generate a secure key:


head -c 32 /dev/urandom > key.key
chmod 600 key.key


---

## Usage

### Encrypt a file


./aes E input.txt output.enc


### Decrypt a file


./aes D output.enc decrypted.txt


### Verify a file (no output written)


./aes V output.enc


---

## File Format Specification

Header (fixed size):


[ MAGIC (9 bytes) | VERSION (1) | FLAGS (1) | BASE_NONCE (8) | FILE_SIZE (8) | CHUNK_COUNT (4) ]


Then repeated:


[ ciphertext_chunk | authentication_tag (16 bytes) ]


### Details

| Field       | Description                  |
| ----------- | ---------------------------- |
| MAGIC       | "SIVCRYPT1" identifier       |
| VERSION     | Format version (currently 1) |
| FLAGS       | Reserved                     |
| BASE_NONCE  | Random per file              |
| FILE_SIZE   | Original plaintext size      |
| CHUNK_COUNT | Number of chunks             |

---

## 🔐 Security Model

### Encryption

Each chunk is encrypted independently:

* Nonce = `base_nonce || counter`
* AAD = `header || counter || chunk_len`

### Guarantees

* Tampering → detected
* Reordering → detected
* Truncation → detected
* Wrong key → detected

### Limits

* Max chunks: `2^32`
* With 8MB chunks → ~32 TB max file size

---

## ⚠️ Security Considerations

### Key Management

* **Losing the key = permanent data loss**
* **Leaking the key = total compromise**

### This tool does NOT provide:

* Password-based encryption
* Key recovery
* Plausible deniability

---

## Error Messages

| Message                | Meaning                     |
| ---------------------- | --------------------------- |
| invalid file format    | Not a SIVCRYPT file         |
| unsupported version    | Version mismatch            |
| authentication failed  | Wrong key or corrupted data |
| truncated              | File cut off                |
| trailing data detected | Extra data appended         |

---

## Example Workflow


# Generate key
head -c 32 /dev/urandom > key.key
chmod 600 key.key

# Encrypt
echo "secret" > file.txt
./aes E file.txt file.enc

# Verify
./aes V file.enc

# Decrypt
./aes D file.enc output.txt


---

## Design Choices Explained

### Why AES-GCM-SIV?

* Resistant to nonce reuse
* Strong integrity guarantees
* Modern and recommended

### Why no password mode?

* Avoids weak KDF usage
* Forces correct key handling

### Why chunked encryption?

* Handles large files safely
* Avoids loading entire file into memory

---

## Limitations

* Linux/Unix only
* No Windows support
* No streaming stdin/stdout
* No metadata encryption (filenames, timestamps)

---

## Future Improvements (Optional)

* Password-based mode (Argon2)
* CLI flags (`--key`, `--progress`)
* Cross-platform support
* File metadata encryption

---

## License

MIT or Apache-2.0 (your choice)

---

## Final Notes

This tool prioritizes **correctness over convenience**.

If you use it, you are responsible for:

* Safely storing your key
* Backing it up securely

---

**Use carefully. This is real cryptography.**
