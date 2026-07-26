# key_converter

A small, strict Rust CLI that converts between a carefully formatted list of byte values and a binary encryption key (`key.key`).

Designed for **AES-256** and **XChaCha20** (both need a 32-byte key).

The input format is intentionally very strict so that mistakes are almost impossible.

## Modes

| Mode | Direction | Command |
|------|-----------|---------|
| `key` | text → binary | `cargo run --release -- key` |
| `txt` | binary → text | `cargo run --release -- txt` |

Both modes **overwrite** the destination file if it already exists.

## How to use

1. Put the program, `in.txt`, and/or `key.key` in the **same directory**.
2. Choose the mode:

### key mode (text → binary)

Edit `in.txt` with your 32 numbers (one per line), then:

```bash
cargo run --release -- key
# or
./target/release/key_converter key
```

Reads `in.txt` and writes (overwrites) `key.key`.

### txt mode (binary → text)

```bash
cargo run --release -- txt
# or
./target/release/key_converter txt
```

Reads `key.key` and writes (overwrites) `in.txt` with one number per line.

## Input format (strict) – used by `key` mode

`in.txt` must contain **exactly 32 lines**, each with a single integer from 0 to 255:

```
12
34
56
78
...
(exactly 32 numbers, one per line)
```

### Rules enforced by the program

| Rule | Why it exists |
|------|---------------|
| Exactly one number per line | Prevents accidental merging of values |
| Only digits allowed on the line | Rejects spaces, commas, signs, letters, etc. |
| Value must be 0–255 | A byte cannot be larger |
| Exactly 32 numbers | Required key length for AES-256 / XChaCha20 |
| No empty lines in the middle | Avoids silent missing values |
| Clear error with line number | You know exactly where the problem is |

Leading/trailing whitespace on a line is ignored, but nothing else is allowed.

## Example

```bash
# Create a valid 32-byte input
cat > in.txt << 'EOF'
5
233
6
4
255
0
128
42
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
EOF

cargo run --release -- key
```

Output:

```
✓ Successfully wrote 32-byte key to 'key.key'

Key (hex):
  0000: 05 e9 06 04 ff 00 80 2a 01 02 03 04 05 06 07 08 
  0010: 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 

You can verify the file with:
  xxd key.key
  or  od -An -tx1 key.key
```

To reverse it:

```bash
cargo run --release -- txt
```

Output:

```
✓ Successfully wrote 32 numbers to 'in.txt'
```

## Why this format instead of free-form spaces/commas?

Free-form text is easy to mistype:

- `5 2336 4` → two numbers become one
- Extra comma or missing number silently changes the key
- Hard to see which value is wrong

One-number-per-line + exact count + strict character check makes the key generation **error-proof**.

## Changing the key length

If you need AES-128 (16 bytes) or AES-192 (24 bytes), edit this constant in `src/main.rs`:

```rust
const EXPECTED_KEY_LEN: usize = 32;
```

Then rebuild.

## Building

```bash
cargo build --release
```

Binary: `target/release/key_converter`
