# Ultimate (Deterministic) Key Maker

This project is a command-line application written in Rust that generates a deterministic cryptographic key based on a password. The generated key is unique, highly randomized, and repeatable given the same inputs. The key is output in raw binary form, making it suitable for secure applications where reproducibility and high entropy are desired.

## Features
- **Deterministic Key Generation**: Given the same password and compile-time parameters, the generated key will always be the same. This makes the tool ideal for use cases where you need reproducibility.
- **Highly Random and Secure**: The key generation uses HKDF (HMAC-based Extract-and-Expand Key Derivation Function) combined with AES-256 in CTR mode for generating random bytes, ensuring cryptographic security and avoiding simple patterns.
- **Configurable Key Size**: You can specify the desired key size in bytes, megabytes, or gigabytes, ranging from 1 byte to 5 GB.
- **Configurable IV for Compile-time Uniqueness**: By changing the Initialization Vector (IV) value before compiling, you can produce different deterministic keys for the same password, effectively making each compiled version unique.

## Usage
To use this key generator, execute it from the command line with the following syntax:

```sh
ukm <size> <bytes|mb|gb> <password>
```

- **size**: The size of the key you want to generate. For example, `200` can be used to specify 200 units.
- **bytes|mb|gb**: The unit for the size. Use "bytes" for raw byte count, "mb" for megabytes, or "gb" for gigabytes.
- **password**: The password used to generate the key. This ensures determinism and allows you to recreate the same key later.

### Example
```sh
ukm 200 mb my_secure_password
```
This command will generate a 200 MB key file named `key1.key1` using `my_secure_password` as the input password.

## Configuration
### Changing the Initialization Vector (IV)
The Initialization Vector (IV) is defined at the top of `main.rs`:
```rust
// Initialization Vector (IV) - Change last 16 numbers to produce different deterministic keys at each compile
const IV: [u8; 16] = [12, 85, 240, 66, 171, 19, 55, 129, 200, 33, 147, 89, 78, 123, 211, 34];
```
You can modify the `IV` value before compiling the program to produce different sets of deterministic keys. This is a useful feature if you want the same password to generate different keys between different compiled versions.

### Installation
To build and use this project, ensure that you have [Rust](https://www.rust-lang.org/tools/install) installed. Clone the repository and build the binary using the following commands:

```sh
git clone <repository_url>
cd ukm
cargo build --release
```

After building, the binary will be located at `target/release/ukm`.

## Dependencies
This project relies on the following crates:

- **hkdf** (`v0.12.4`): Used for HMAC-based key derivation to ensure high entropy.
- **sha2** (`v0.10.8`): Provides the SHA-256 hashing algorithm for generating a unique salt from the password.
- **aes** (`v0.8.4`): Provides AES-256 encryption functionality, specifically in CTR mode.
- **ctr** (`v0.9.2`): Enables AES encryption to operate in Counter (CTR) mode, which turns AES into a secure stream cipher.

Ensure that these dependencies are listed in your `Cargo.toml` file:
```toml
[dependencies]
hkdf = "0.12.4"
sha2 = "0.10.8"
aes = "0.8.4"
ctr = "0.9.2"
```

## How It Works
1. **Password Hashing**: The password is hashed using SHA-256 to produce a salt, adding a layer of randomness to the key generation process.
2. **HKDF Key Derivation**: HKDF is used to derive a key from the hashed password and salt. This derived key serves as the starting point for the random key generation.
3. **AES-256 CTR Mode**: The derived key is then used in AES-256 in CTR mode to create a pseudo-random stream of bytes, which makes up the key material.
4. **Whitespace Filtering**: The generated key is filtered to remove any whitespace characters (spaces, newlines, tabs) to ensure a clean output.

## Notes
- **Output File**: The generated key is saved in a file named `key1.key1`. If this file already exists, the program will terminate without overwriting it.
- **Compile-time IV Changes**: By changing the IV and recompiling, the key generation will produce different keys even with the same password.
- **Deterministic Keys**: The key generation is deterministic given a particular IV, password, and configuration. This means you can recreate the exact same key if you use the same input parameters and IV.

## Security Considerations
- This tool is intended for use cases where deterministic key generation is required. While the key generation is designed to be highly secure, be mindful of the implications of using a constant IV. For applications where non-deterministic encryption is required, consider a fully random IV generated at runtime.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to submit a pull request.

## Author
Developed by [Your Name].

