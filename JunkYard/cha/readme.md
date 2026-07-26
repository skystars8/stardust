# XChaCha20 File Encryptor

## Overview
The **XChaCha20 File Encryptor** is a simple command-line application that provides encryption and decryption capabilities for files using the XChaCha20-Poly1305 algorithm. This tool allows you to secure files by encrypting them, and it also provides an option to generate a new encryption key.

The application makes use of the `clap` crate for parsing command-line arguments and is designed to work with a variety of file types. It is important to note the implications when encrypting certain file types, especially **executables**.

## Features
- **Generate Key**: Create a new encryption key and store it securely.
- **Encrypt Files**: Encrypt files of various formats using the XChaCha20-Poly1305 encryption scheme.
- **Decrypt Files**: Decrypt files that have been previously encrypted with the same key.

## Installation
To use this tool, you need to have [Rust](https://www.rust-lang.org/) installed. Clone this repository and use `cargo` to build and run the application:

```sh
# Clone the repository
git clone <repository-url>

# Navigate into the project directory
cd xchacha20_file_encryptor

# Build the project
cargo build --release

# Run the executable
./target/release/xchacha20_file_encryptor
```

## Usage
The application provides several subcommands to perform key operations.

### Generating an Encryption Key
```sh
xchacha20_file_encryptor gen-key
```
This command generates a 32-byte key that will be used for encryption and decryption. The key is saved to a file named `key.key`.

### Encrypting a File
```sh
xchacha20_file_encryptor encrypt <INPUT> <OUTPUT>
```
- `<INPUT>`: The path to the file you want to encrypt.
- `<OUTPUT>`: The path where you want to save the encrypted file.

**Note**: If you are encrypting an executable file, it is recommended that you first compress it into a `.zip` or `.tar` file to prevent corruption of its internal structure.

### Decrypting a File
```sh
xchacha20_file_encryptor decrypt <INPUT> <OUTPUT>
```
- `<INPUT>`: The path to the encrypted file.
- `<OUTPUT>`: The path where you want to save the decrypted file.

## Implications for Executable Files
When encrypting and decrypting non-text files such as executables (`.exe` on Windows, `.bin` on Unix-based systems), there are some crucial considerations:

### Additional Data in Files
- The encryption process **adds 24 bytes** to the start of the file to store the nonce.
- When encrypting an executable file, adding these extra bytes would corrupt the file structure if the process is reversed improperly or if some part of the additional data is mismanaged. Executable files have very strict internal formats, and even small changes to the header or the structure can prevent them from running correctly.

### Decryption Requirement
- During decryption, the code assumes the nonce is the first 24 bytes of the file. If the file has been modified, or if decryption is attempted without the exact same logic, data loss or corruption may occur.
- Any interruption during the encryption or decryption process can render the executable file unusable.

### Risks of Data Loss or Corruption
- If you mistakenly try to run a partially encrypted file or an improperly decrypted file, it could lead to crashes, errors, or even system instability.
- Additionally, if the nonce or key is misplaced, recovery of the original executable would be impossible, leading to **permanent data loss**.

### Recommendations for Handling Executable Files
#### Avoid Encrypting Executable Files Directly
- Unless you have a good reason and are certain of the integrity of the encryption-decryption cycle, avoid encrypting executables directly using this kind of scheme.
- Executable files have specific headers and metadata that are critical for their execution, and altering these parts with additional information can easily break them.

#### Use an Archive Approach
- A safer approach would be to first compress or archive the executable into a `.zip` or `.tar` file and then encrypt the archive. This way, the executable’s structure remains intact during the encryption and decryption phases, as the nonce is applied to the archive file rather than the executable itself.
- Tools like `tar` or `zip` are suitable for wrapping the executable, and this method also helps ensure that no original data is lost due to accidental mismanagement.

#### Restore Original File Contents Exactly
- The current implementation should be used with caution to ensure that the nonce is properly read and removed during decryption so that the output matches the original input byte-for-byte.
- For critical files, always verify the integrity of decrypted files (using checksums like `SHA256`) to ensure that the file is restored correctly.

#### Separate Metadata and Encrypted Data
- If you need more flexibility and are dealing with highly sensitive executable files, consider storing the nonce separately from the file (e.g., in a different metadata file). This avoids injecting information directly into the file content.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author
- Your Name (<youremail@example.com>)

## Acknowledgements
- Thanks to the Rust community and contributors to the `chacha20poly1305`, `rand`, and `clap` crates for making this project possible.

