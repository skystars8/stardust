# Post-Quantum File Encryption with Kyber1024

This project is an implementation of file encryption and decryption using **post-quantum cryptography** (Kyber1024) in Rust. The application allows users to encrypt and decrypt files with high security, leveraging lattice-based encryption that is designed to be secure even against quantum computing attacks.

## Features
- **Kyber1024 Key Encapsulation**: Uses Kyber1024, a post-quantum key encapsulation mechanism (KEM), to securely exchange symmetric encryption keys.
- **Symmetric XOR Encryption**: Uses a simple XOR-based encryption for file content with the shared secret derived from Kyber1024.
- **Interactive Encryption and Decryption**: Prompts the user for encryption (`E`) or decryption (`D`), and allows specifying custom filenames for input and output.
- **Persistent Keys**: If key files (`public_key.bin` and `secret_key.bin`) are available, the program will use them; otherwise, it generates new keys and saves them for future use.

## Requirements
- **Rust**: You need to have Rust installed to build and run the program.
- **pqcrypto-kyber crate**: The implementation uses the `pqcrypto` library, specifically `pqcrypto-kyber` for Kyber1024.

## Dependencies
Add the following dependencies to your `Cargo.toml` file:

```toml
[dependencies]
pqcrypto = "0.17.0"
pqcrypto-kyber = "0.8.1"
rand = "0.8.5"
```

## How to Build and Run

1. **Clone the repository** (if applicable) or copy the source files to your local machine.

2. **Create an input file** to be encrypted. For example, `example.txt` in the same directory as the code.

3. **Compile the project** using Cargo:
   ```sh
   cargo build
   ```

4. **Run the executable** to encrypt or decrypt a file:
   ```sh
   cargo run
   ```

5. **Follow the prompts** to choose the mode (encrypt or decrypt), specify the input file, and provide the output file name.

The program will generate the required key files (`public_key.bin` and `secret_key.bin`) if they are not already present. These keys will be used for future encryption and decryption operations.

## Code Overview

- **Key Generation and Handling**:
  - Checks for `public_key.bin` and `secret_key.bin` in the current directory.
  - If the keys are not found, generates a new keypair and saves them.
  - If the keys are found, loads them for use.

- **Encryption**:
  - Uses `encapsulate()` to generate a shared secret for file encryption and a ciphertext for key encapsulation.
  - Encrypts the file content using a simple XOR-based encryption with the shared secret.

- **Decryption**:
  - Uses `decapsulate()` to recover the shared secret from the ciphertext.
  - Decrypts the file content using the shared secret.

## File Structure

- **`example.txt`**: An example file to be encrypted.
- **`example.enc`**: The output encrypted file.
- **`example.dec.txt`**: The output decrypted file.
- **`public_key.bin`** and **`secret_key.bin`**: Files storing the public and secret keys for encryption and decryption.

## Example Usage
Upon running the program, the user will be prompted to enter a mode:
- **`E` for encryption**: Prompts the user for an input file (e.g., `example.txt`) and an output file (e.g., `example.enc`). The file is encrypted, and the encrypted version is saved.
- **`D` for decryption**: Prompts the user for an encrypted input file and an output file. The encrypted content is decrypted and saved.

## Notes
- **Security Warning**: The XOR-based encryption used in this example is not secure for real-world applications. It is used here for simplicity. Consider replacing it with a more sophisticated symmetric encryption algorithm like AES.
- **Post-Quantum Cryptography**: Kyber1024 is a post-quantum key encapsulation method that provides protection against attacks from quantum computers, unlike traditional public-key systems like RSA or ECC.

## Troubleshooting
- **Key File Not Found**: Ensure that both `public_key.bin` and `secret_key.bin` exist if you're running the decryption process separately. If they are missing, you can re-run encryption to regenerate them.
- **Memory Issues**: If decryption fails due to an unrealistic or excessively large data length, it may be due to data corruption or incorrect file handling.

## License
This project is licensed under the MIT License.

## Contribution
Contributions are welcome! Feel free to fork the repository, submit issues, or create pull requests to improve this project.

