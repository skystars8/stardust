# Post Quantum File Crypto

## Overview
This project demonstrates a simple file encryption and decryption tool utilizing post-quantum cryptographic algorithms. It uses FrodoKEM (a lattice-based key encapsulation mechanism) and BLAKE3 hashing to derive a secure symmetric key. The encryption and decryption process is implemented in Rust, emphasizing the use of post-quantum cryptographic primitives that can withstand quantum computing attacks.

The tool provides an easy-to-use command-line interface to encrypt or decrypt files, making it ideal for individual users interested in experimenting with post-quantum cryptographic methods.

## Features
- **Post-Quantum Key Generation**: Uses FrodoKEM to generate a secure shared secret.
- **Symmetric Key Derivation**: BLAKE3 is used to derive a strong symmetric key from the shared secret.
- **Simple XOR-based Encryption/Decryption**: The derived key is used for file encryption/decryption using an XOR-based approach.
- **Chunk-based Processing**: File encryption and decryption are handled in chunks to support files of any size, making it memory-efficient.

## Prerequisites
To build and run this project, you will need:
- Rust (edition 2021) installed. You can install Rust using [rustup](https://rustup.rs/).

## Installation
1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd post_quantum_file_crypto
   ```

2. Ensure you have the required dependencies by adding the following to your `Cargo.toml`:
   ```toml
   [dependencies]
   pqcrypto-frodo = "0.4.11"
   pqcrypto-traits = "0.3.5"
   blake3 = "1.5.4"
   rand = "0.8.5"
   ```

3. Build the project:
   ```sh
   cargo build
   ```

## Usage
To run the file encryption tool, use the following command:
```sh
cargo run
```
Upon running, the tool will prompt for:
1. **Mode**: Enter `E` for encryption or `D` for decryption.
2. **Input Filename**: Provide the path to the input file to encrypt/decrypt.
3. **Output Filename**: Provide the path where the encrypted/decrypted file should be saved.

### Example
- To encrypt a file:
  1. Enter `E` when prompted for the mode.
  2. Provide the path to the file you want to encrypt.
  3. Specify the output path for the encrypted file.

- To decrypt a file:
  1. Enter `D` when prompted for the mode.
  2. Provide the path to the encrypted file.
  3. Specify the output path for the decrypted file.

## How It Works
### Key Generation
- The program uses **FrodoKEM** to generate a key pair.
- A **shared secret** is derived using encapsulation with the public key.
- The shared secret is then hashed with **BLAKE3** to produce a strong 32-byte symmetric key.
- The generated key is saved in a file called `key.key` for future use.

### Encryption/Decryption
- The tool reads the input file in chunks of 4096 bytes (4 KB) to ensure it can handle large files efficiently.
- **XOR-based encryption** is applied to each chunk using the symmetric key derived earlier.
- The same process is used for decryption since XOR is symmetric, meaning applying XOR twice with the same key returns the original data.

## Security Considerations
- This implementation uses **XOR-based encryption**, which is not secure for real-world applications without additional cryptographic measures. It serves as a simple demonstration of post-quantum key generation and symmetric key derivation.
- For production-grade security, consider using a stronger symmetric encryption scheme (e.g., AES-GCM) after deriving the symmetric key.
- The focus here is to demonstrate the integration of **post-quantum cryptography** (FrodoKEM) with symmetric key encryption.

## Limitations
- **XOR Encryption**: The current encryption scheme (XOR) is purely for educational purposes and should not be used in production environments.
- **Key Management**: The key is stored in a file (`key.key`), which could be a potential security risk if not handled properly.

## Future Improvements
- Replace the XOR encryption with a more robust symmetric encryption algorithm such as **AES** or a **post-quantum symmetric cipher**.
- Implement key rotation and secure key storage mechanisms.
- Add authentication (e.g., HMAC) to ensure the integrity of encrypted files.

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to enhance the functionality or security of the tool.

## License
This project is licensed under the MIT License.

## Acknowledgments
- **pqcrypto**: For providing post-quantum cryptographic algorithms.
- **BLAKE3**: For the fast and secure hash function used to derive the symmetric key.

If you have any questions or suggestions, please feel free to reach out!

