# XChaCha20 File Encryptor

XChaCha20 File Encryptor is a command-line tool for secure file encryption and decryption using XChaCha20-Poly1305. This app offers a simple and robust way to protect your data, providing commands to generate encryption keys, encrypt files, and decrypt files.

## Features

- **Generate Encryption Key**: Generate a secure 32-byte key for encryption and decryption.
- **Encrypt Files**: Encrypt any file using XChaCha20-Poly1305 with a securely generated nonce.
- **Decrypt Files**: Decrypt encrypted files using the same key.
- **Authenticated Encryption**: Utilizes XChaCha20-Poly1305 to ensure both confidentiality and data integrity.

## Prerequisites

Before running the XChaCha20 File Encryptor, ensure you have the following dependencies installed:

- Rust toolchain (to build the program)
- [Clap](https://crates.io/crates/clap) for command-line argument parsing
- [chacha20poly1305](https://crates.io/crates/chacha20poly1305) for XChaCha20-Poly1305 encryption/decryption
- [rand](https://crates.io/crates/rand) for generating secure random keys and nonces
- [anyhow](https://crates.io/crates/anyhow) for error handling
- [zeroize](https://crates.io/crates/zeroize) for secure memory management

To install the required dependencies, add them to your `Cargo.toml`:

```toml
[dependencies]
chacha20poly1305 = "0.9"
clap = { version = "4.0", features = ["derive"] }
rand = "0.8"
anyhow = "1.0"
zeroize = "1.4"
```

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/xchacha20-file-encryptor.git
   cd xchacha20-file-encryptor
   ```

2. Build the application using Cargo:

   ```sh
   cargo build --release
   ```

3. The executable will be available in the `target/release` directory:

   ```sh
   ./target/release/xchacha20-file-encryptor
   ```

## Usage

The XChaCha20 File Encryptor has several commands: `gen-key`, `encrypt`, and `decrypt`. Below are the usage instructions for each command.

### Generate Key

Generate a random 32-byte key for encryption and decryption:

```sh
./xchacha20-file-encryptor gen-key [-k <KEY_PATH>]
```

- **`-k, --key`** (optional): Specifies the path to save the generated key. If not provided, the key will be saved as `key.key`.

### Encrypt File

Encrypt a file with an existing key:

```sh
./xchacha20-file-encryptor encrypt <INPUT> <OUTPUT> [-k <KEY_PATH>]
```

- **`<INPUT>`**: Path to the input file to be encrypted.
- **`<OUTPUT>`**: Path to the output file for the encrypted data.
- **`-k, --key`** (optional): Path to the key file. If not provided, the default `key.key` will be used.

### Decrypt File

Decrypt an encrypted file with an existing key:

```sh
./xchacha20-file-encryptor decrypt <INPUT> <OUTPUT> [-k <KEY_PATH>]
```

- **`<INPUT>`**: Path to the input file to be decrypted.
- **`<OUTPUT>`**: Path to the output file for the decrypted data.
- **`-k, --key`** (optional): Path to the key file. If not provided, the default `key.key` will be used.

### Example Usage

1. **Generate a Key**

   ```sh
   ./xchacha20-file-encryptor gen-key -k my_secret.key
   ```

2. **Encrypt a File**

   ```sh
   ./xchacha20-file-encryptor encrypt myfile.txt encrypted.bin -k my_secret.key
   ```

3. **Decrypt a File**

   ```sh
   ./xchacha20-file-encryptor decrypt encrypted.bin decrypted.txt -k my_secret.key
   ```

## Security Considerations

- **Key Management**: Keep your key file (`key.key` or your custom key) secure. Anyone with access to the key can decrypt your data.
- **Nonce Handling**: Each encryption generates a unique nonce, which is stored with the ciphertext. Do not reuse nonces with the same key, as it may compromise security.
- **Zeroization**: Keys, plaintexts, and sensitive data are zeroized when they go out of scope to reduce the risk of them being recovered from memory.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Author

Developed by [Your Name]. Contributions and feedback are welcome!

## Contributions

Feel free to fork the repository and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.

## Issues

If you encounter any issues or have suggestions for improvement, please open an issue on GitHub.

## Disclaimer

This tool is intended for educational purposes only. Use it at your own risk. The author is not responsible for any misuse or data loss.

