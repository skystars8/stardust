
# RKM - Random Key/Bytes Generator

`rkm` is a simple Rust command-line tool that generates a file filled with random bytes of a specified size. It uses the OS-provided random number generator, ensuring cryptographically secure random data.

## Features
- Generates a file of random bytes based on user-specified size.
- Supports various units like `bytes`, `KB`, `MB`, and `GB`.
- Optionally allows the user to specify the output file name.
- Prevents overwriting existing files.

## Usage

```bash
rkm <size> [output_file]
```

### Examples:

- Generate a file with 32 bytes of random data (saved as `rand.key` by default):
  ```bash
  rkm 32bytes
  ```

- Generate a 20MB file with random data and save it as `output.bin`:
  ```bash
  rkm 20mb output.bin
  ```

- Generate a 5GB file of random data (saved as `rand.key`):
  ```bash
  rkm 5gb
  ```

## How to Build

1. Install Rust by following the instructions at [rust-lang.org](https://www.rust-lang.org/).
2. Clone the repository:
   ```bash
   git clone <repo-url>
   cd rkm
   ```
3. Build the project:
   ```bash
   cargo build --release
   ```

4. The compiled binary will be in the `target/release/` directory.

## Notes:
- Supported size units: `bytes`, `kb`, `mb`, `gb`.
- If no output file is specified, the random data will be written to `rand.key` by default.
- The program will exit with an error if the output file already exists to prevent overwriting.

## License

This project is licensed under the MIT License.
