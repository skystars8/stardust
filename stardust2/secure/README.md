# secure

`secure` is a local, streaming file-encryption CLI. It refuses to overwrite any
existing directory entry and writes through a private temporary file in the
destination directory. A completed output is published only after all reads,
writes, authentication checks, and file synchronization succeed.

The minimum supported compiler is Rust 1.97.1. Cargo refuses to build this
package with an older compiler.

## Build

```text
cargo build --release
```

The executable is `target/release/secure.exe` on Windows and
`target/release/secure` on Unix-like systems.

## Commands

```text
secure keymake SIZE
secure otp INPUT OUTPUT
secure aes INPUT OUTPUT [--mode auto|encrypt|decrypt]
secure xcha INPUT OUTPUT [--mode auto|encrypt|decrypt]
secure ser INPUT OUTPUT [--mode auto|encrypt|decrypt]
secure tf INPUT OUTPUT [--mode auto|encrypt|decrypt]
```

`keymake` prompts twice and deterministically creates `key.key` in the current
directory. `SIZE` is an exact byte count from 1 through 20,000,000,000. It uses
Argon2id (64 MiB, three iterations) followed by the BLAKE3 extendable-output
function. The requested size is domain-separated, so the same password and
size reproduce the same key, while different sizes produce unrelated streams.

`otp` XORs the input with `key.key` beside the input file. The key must be at
least as long as the input. Applying the command a second time with the same
key reverses it.

The encrypted-file commands automatically decrypt inputs carrying this
program's authenticated header and encrypt other inputs. Use `--mode decrypt`
when a damaged header should be treated as an error instead of relying on
autodetection. Key files are found beside the input:

| Command | Construction | Key file |
| --- | --- | --- |
| `aes` | AES-256-GCM-SIV | `aes.key` |
| `xcha` | XChaCha20-Poly1305 | `key.key` |
| `ser` | Serpent-256 CTR + HMAC-SHA-256 | `key.key` |
| `tf` | Threefish-1024 CTR + HMAC-SHA-256 | `key.key` |

Cryptographic key files must contain at least 32 bytes. The complete key file is
streamed through a domain-separated KDF, so RAM use does not depend on its size.
Each encrypted file uses a fresh operating-system-generated 256-bit salt and
independent per-file encryption and authentication keys. Data is processed in
authenticated 1 MiB chunks; an empty file still has an authenticated chunk.
These are versioned application formats, not formats interoperable with other
encryption tools. The exact, stable version-1 binary layout and derivation
rules are recorded in [FORMAT.md](FORMAT.md) for recovery and independent
implementation.

## Critical key guidance

A deterministic password-derived `key.key` is a pseudorandom keystream, not a
true information-theoretic one-time pad: its security cannot exceed the
password's entropy. Use a long, unique, randomly generated passphrase.

Never reuse OTP key bytes for more than one input. Reuse exposes relationships
between plaintexts, and known plaintext reveals corresponding key bytes. Do not
use the same `key.key` for `otp` and the other encryption commands. Keep
separate, backed-up keys; losing a key makes authenticated ciphertext
unrecoverable.
cgpt
