# AES-SIV Encryption App

AES-SIV Encryption App is a command-line tool for secure file encryption and decryption using AES-SIV (AES Synthetic Initialization Vector). The app provides a straightforward way to protect your data, offering commands to generate encryption keys, encrypt files, and decrypt files.

## Features

- **Generate Encryption Key**: Generate a secure 64-byte key for encryption/decryption.
- **Encrypt Files**: Encrypt any file using AES-SIV with optional associated data (AAD).
- **Decrypt Files**: Decrypt encrypted files using the same key and associated data.
- **Authenticated Encryption**: Utilizes AES-SIV to ensure that both data confidentiality and integrity are maintained.

## Prerequisites

Before running the AES-SIV Encryption App, ensure you have the following dependencies installed:

- Rust toolchain (to build the program)
- [Clap](https://crates.io/crates/clap) for command-line argument parsing
- [aes-siv](https://crates.io/crates/aes-siv) for AES-SIV encryption/decryption
- [rand](https://crates.io/crates/rand) for generating secure random keys
- [anyhow](https://crates.io/crates/anyhow) for error handling
- [zeroize](https://crates.io/crates/zeroize) for secure memory management

To install the required dependencies, add them to your `Cargo.toml`:

```toml
[dependencies]
aes-siv = "0.6"
clap = { version = "4.0", features = ["derive"] }
rand = "0.8"
anyhow = "1.0"
zeroize = "1.4"
```

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/aes-siv-encryption-app.git
   cd aes-siv-encryption-app
   ```

2. Build the application using Cargo:

   ```sh
   cargo build --release
   ```

3. The executable will be available in the `target/release` directory:

   ```sh
   ./target/release/aes-siv-encryption-app
   ```

## Usage

The AES-SIV Encryption App has several commands: `gen-key`, `encrypt`, and `decrypt`. Below are the usage instructions for each command.

### Generate Key

Generate a random 64-byte key for encryption and decryption:

```sh
./aes-siv-encryption-app gen-key [-k <KEY_PATH>]
```

- **`-k, --key`** (optional): Specifies the path to save the generated key. If not provided, the key will be saved as `key.key`.

### Encrypt File

Encrypt a file with an existing key:

```sh
./aes-siv-encryption-app encrypt <INPUT> <OUTPUT> [-k <KEY_PATH>] [-a <ASSOCIATED_DATA>]
```

- **`<INPUT>`**: Path to the input file to be encrypted.
- **`<OUTPUT>`**: Path to the output file for the encrypted data.
- **`-k, --key`** (optional): Path to the key file. If not provided, the default `key.key` will be used.
- **`-a, --aad`** (optional): Associated data to bind to the ciphertext for additional authentication.

### Decrypt File

Decrypt an encrypted file with an existing key:

```sh
./aes-siv-encryption-app decrypt <INPUT> <OUTPUT> [-k <KEY_PATH>] [-a <ASSOCIATED_DATA>]
```

- **`<INPUT>`**: Path to the input file to be decrypted.
- **`<OUTPUT>`**: Path to the output file for the decrypted data.
- **`-k, --key`** (optional): Path to the key file. If not provided, the default `key.key` will be used.
- **`-a, --aad`** (optional): Associated data used during encryption to validate the ciphertext.

### Example Usage

1. **Generate a Key**

   ```sh
   ./aes-siv-encryption-app gen-key -k my_secret.key
   ```

2. **Encrypt a File**

   ```sh
   ./aes-siv-encryption-app encrypt myfile.txt encrypted.bin -k my_secret.key -a "metadata"
   ```

3. **Decrypt a File**

   ```sh
   ./aes-siv-encryption-app decrypt encrypted.bin decrypted.txt -k my_secret.key -a "metadata"
   ```

## Security Considerations

- **Key Management**: Keep your key file (`key.key` or your custom key) secure. Anyone with access to the key can decrypt your data.
- **Associated Data**: Use associated data (`-a` flag) to add an extra layer of authentication. This data must match exactly during decryption.
- **Zeroization**: Keys and sensitive data are zeroized when they go out of scope to reduce the risk of them being recovered from memory.

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

