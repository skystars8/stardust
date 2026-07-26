# threefish-cli

A simple, reliable command-line file encryption tool using **Threefish-1024**.

Only the filename is required.  
- Any normal file → encrypted to `<filename>.enc`  
- Only `.enc` files can be decrypted (the `.enc` extension is stripped on success)

A binary key file named **`key.key`** must be present in the **same directory** as the target file.

### Features

- **Threefish-1024** (1024-bit key / 1024-bit block) in CTR mode
- Fixed 192-byte binary key file (no passwords, no KDF)
- **HMAC-SHA-512** authentication (Encrypt-then-MAC)
- Unique random nonce (Threefish tweak) per file
- Atomic writes (temp file + fsync + rename) – no half-written output
- Key material is zeroized after use
- Clear failure on wrong key or corrupted file (nothing is written)

### Key file format

`key.key` must be **exactly 192 bytes** of raw binary data:

```
bytes   0 .. 128  → Threefish-1024 encryption key
bytes 128 .. 192  → HMAC-SHA-512 key
```

Generate one with:

```bash
# Linux / macOS
dd if=/dev/urandom of=key.key bs=192 count=1

# or with OpenSSL
openssl rand -out key.key 192
```

Keep `key.key` safe. Anyone who obtains it can decrypt every file protected by it. Losing it means the data is permanently unrecoverable.

### Build

Requires a recent Rust toolchain (edition 2021).

```bash
cargo build --release
```

Binary: `target/release/threefish-cli` (or `threefish-cli.exe` on Windows)

### Usage

```text
threefish-cli <file>
```

**Encrypt**
```text
threefish-cli document.pdf
# → creates document.pdf.enc
# (key.key must be in the same directory)
```

**Decrypt**
```text
threefish-cli document.pdf.enc
# → restores document.pdf
```

### File format (version 2)

```
[4 bytes]  Magic   "T3F1"
[1 byte]   Version 2
[16 bytes] Nonce / Threefish tweak
[variable] Ciphertext (CTR)
[64 bytes] HMAC-SHA-512 tag
```

(Version 1 files that used password-based Argon2id are no longer supported.)

---

## Reliability notes

**Data safety and correct use of Threefish-1024 were the primary design goals.**

| Aspect | Status | Why it matters |
|--------|--------|----------------|
| **Authenticated encryption** | Correct | Encrypt-then-MAC with HMAC-SHA-512 over header + ciphertext. Wrong key or any corruption is detected *before* any plaintext is written. |
| **MAC-first design** | Correct | You never get a partially decrypted or silently corrupted file. |
| **Key material** | Fixed binary | Exactly 192 bytes, split into independent encryption + MAC keys. No derivation step that could be mis-implemented. |
| **Nonce / tweak** | Correct | Fresh 16-byte random value used as Threefish tweak every time → no keystream reuse under the same key. |
| **Mode of operation** | Correct | Manual CTR with a full 128-byte big-endian counter starting at zero. No padding → original length is preserved exactly. |
| **Atomic writes** | Correct | Write to temp file → `fsync` → rename. Crash or power loss cannot leave a half-written result. |
| **Secret handling** | Good | Key material is zeroized on drop. |
| **File format rules** | Clear | Only `.enc` files can be decrypted; non-`.enc` → encrypt. |

### Realistic caveats

1. **Key management is entirely your responsibility.**  
   The tool never generates, stores, or backs up `key.key`. Treat it like the only copy of a master password that can never be recovered.

2. **Same-directory layout.**  
   Convenience over isolation. An attacker who obtains the directory gets both the ciphertext and the key. For higher security, move `key.key` to a separate, tightly permissioned location and adjust the path logic if needed.

3. **Threefish-1024 remains uncommon.**  
   The algorithm is sound, but the ecosystem is thinner than AES or ChaCha20. The CTR mode and MAC construction around it are implemented carefully.

4. **Whole-file-in-memory.**  
   Large multi-GB files will consume corresponding RAM. Fine for documents and typical personal files.

5. **No formal security audit.**  
   This is a carefully written personal tool.

### Bottom line

For personal offline file encryption where you control both the data and the key file, the construction is solid: correct use of Threefish-1024 in CTR, proper Encrypt-then-MAC, unique tweaks, atomic writes, and fail-closed authentication. Wrong key or bit-flipped ciphertext produces a clean error and never writes garbage.
