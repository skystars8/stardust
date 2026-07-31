# enc

`enc` is a small file-encryption command-line program with a deliberately simple
interface:

```powershell
enc "C:\path\to\report.pdf" E
enc "C:\path\to\report.pdf.enc" D
```

- Encryption creates `report.pdf.enc`.
- Decryption creates `report.pdf.dec`.
- The input is never changed or deleted.
- Existing output files are never overwritten.

## Build

```powershell
cargo build --release
```

The executable will be at `target\release\enc.exe`.

Run it directly from this project directory with:

```powershell
.\target\release\enc.exe "C:\path\to\report.pdf" E
.\target\release\enc.exe "C:\path\to\report.pdf.enc" D
```

## Data-safety design

- XChaCha20-Poly1305 provides authenticated encryption. Damage, tampering, a
  wrong key, truncation, and appended data are detected.
- Files are processed in 1 MiB chunks, so file size is not limited by memory.
- Output is written to a temporary file in the destination directory. It is
  flushed to storage and renamed into place only after the complete operation
  succeeds.
- Temporary plaintext is removed automatically after an error.
- A new random nonce is generated for every encryption.
- The encrypted format is versioned so a future format cannot be mistaken for
  the current one.

## Critical key warning

The 256-bit key is embedded in `src/key.rs`, as requested. Back up that file
securely before using the program for important data:

- Losing or changing the key permanently makes existing encrypted files
  unrecoverable.
- Anyone who obtains the source or executable can extract the embedded key.
- Do not publish this repository or executable if the encrypted files must
  remain secret from its recipients.

For real protection across multiple users or machines, a password-derived key
or operating-system credential store is safer than an embedded key.

## Operational safety

Keep a separate backup until you have tested decryption. Do not modify an input
file while it is being processed. On Windows the program asks the OS to prevent
concurrent mutation; on other systems it also checks the input size and
modification time before publishing the result.
