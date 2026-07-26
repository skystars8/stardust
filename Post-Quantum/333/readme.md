# Post-Quantum File Encryption Tool

## Overview
The **Post-Quantum File Encryption Tool** is a Rust-based utility designed to encrypt and decrypt files using **post-quantum cryptographic algorithms**. This tool leverages **FrodoKEM** (a post-quantum Key Encapsulation Mechanism) in combination with the **XChaCha20-Poly1305** authenticated encryption scheme. This combination ensures a strong, quantum-resistant key exchange and secure, authenticated encryption for file protection. It is particularly suitable for users who are interested in experimenting with and learning about modern cryptographic techniques that can resist future quantum computing threats.

This project was primarily created for educational purposes to explore the integration of post-quantum key exchange mechanisms with robust symmetric encryption.

## Features
- **Post-Quantum Key Exchange**: Uses **FrodoKEM-640-SHAKE** from the `pqcrypto-frodo` crate to generate quantum-safe key material.
- **Symmetric Key Derivation**: Uses the **BLAKE3** hash function to derive a symmetric key from the shared secret, ensuring strong entropy.
- **Authenticated Encryption**: Encrypts files using the **XChaCha20-Poly1305** stream cipher, providing authenticated encryption with a secure nonce.
- **Passphrase Protection**: The encryption key is protected using a user-provided passphrase, which is hashed with BLAKE3 and used to encrypt the key.
- **Command-Line Interface**: Provides an interactive command-line interface to encrypt or decrypt files easily.

## Cryptographic Concepts Used
1. **FrodoKEM (FrodoKEM-640-SHAKE)**: A post-quantum key exchange mechanism used to securely generate a shared secret between two parties. The generated secret is later used to derive a symmetric key.
2. **BLAKE3 Hash Function**: A cryptographic hash function that provides high performance and security. It is used to derive a symmetric key from the shared secret and to hash user-provided passphrases.
3. **XChaCha20-Poly1305**: An authenticated encryption scheme used to provide both confidentiality and integrity. It uses a randomly generated nonce to prevent ciphertext reuse attacks.

## How It Works
The tool encrypts or decrypts files using a symmetric key derived from a post-quantum secure key encapsulation mechanism. Below is a detailed description of the process:

### 1. Key Generation
- The tool first generates a **keypair** using **FrodoKEM**.
- It encapsulates a randomly generated shared secret, resulting in a symmetric shared secret.
- The shared secret is then hashed with **BLAKE3** to derive a **32-byte symmetric key** for file encryption.

### 2. File Encryption/Decryption
- The **XChaCha20-Poly1305** authenticated encryption scheme is used for both encryption and decryption.
- A **24-byte random nonce** is generated for each encryption, ensuring that even identical plaintexts yield different ciphertexts.
- The encrypted key is saved securely to disk, protected by a user-provided passphrase.
- During decryption, the key is retrieved by providing the correct passphrase, and the nonce is used to decrypt the file data.

### 3. Key Storage and Retrieval
- The generated key is encrypted using a passphrase-derived key and then saved in a key file (`key.key`).
- The nonce used for key encryption is stored along with the key, allowing for proper decryption during file decryption.

## Usage
### Prerequisites
- **Rust**: Make sure Rust is installed. You can install it from [rust-lang.org](https://www.rust-lang.org/tools/install).

### Build and Run
1. **Clone the Repository**:
   ```sh
   git clone <repository_url>
   cd post_quantum_file_crypto
   ```

2. **Build the Project**:
   ```sh
   cargo build --release
   ```

3. **Run the Program**:
   ```sh
   cargo run --release
   ```
   The program will prompt the user to enter the mode (`E` for encryption, `D` for decryption), the input file path, and the output file path.

### Example Execution
- **Encrypt a File**:
  ```plaintext
  Enter mode (E for encrypt, D for decrypt):
  E
  Enter input filename:
  example.txt
  Enter output filename:
  encrypted.txt
  Enter a passphrase to secure the key:
  ```
  After entering the passphrase, the file will be encrypted and saved as `encrypted.txt`.

- **Decrypt a File**:
  ```plaintext
  Enter mode (E for encrypt, D for decrypt):
  D
  Enter input filename:
  encrypted.txt
  Enter output filename:
  decrypted_example.txt
  Enter passphrase to unlock the key:
  ```
  After entering the correct passphrase, the file will be decrypted and saved as `decrypted_example.txt`.

## Notes
- **Key File (`key.key`)**: The key used for encryption and decryption is saved to a file called `key.key`. Make sure to back up this file securely, as it is required for decryption.
- **Passphrase**: Use a strong passphrase to protect the key. If the passphrase is lost, the encrypted files cannot be decrypted.

## Dependencies
- `pqcrypto-frodo`: Provides post-quantum cryptography algorithms like **FrodoKEM**.
- `pqcrypto-traits`: Defines traits used by `pqcrypto-frodo`.
- `blake3`: Used for hashing shared secrets and deriving symmetric keys.
- `rand`: Used for generating random values (e.g., nonces).
- `chacha20poly1305`: Provides the **XChaCha20-Poly1305** cipher for authenticated encryption.
- `rpassword`: Reads passphrases securely from the command line.

### Cargo.toml
```toml
[package]
name = "post_quantum_file_crypto"
version = "0.3.0"
edition = "2021"

[dependencies]
pqcrypto-frodo = "0.4.11"
pqcrypto-traits = "0.3.5"
rand = { version = "0.8.5", features = ["std"] }
chacha20poly1305 = "0.10.1"
rpassword = "7.3.1"
blake3 = "1.5.4"
```

## Security Considerations
- **Post-Quantum Security**: The key exchange is secure against quantum computer attacks due to **FrodoKEM**, which is a candidate for post-quantum cryptography.
- **Nonce Handling**: The **XChaCha20-Poly1305** scheme uses a unique nonce for each file, ensuring that identical plaintexts do not yield the same ciphertext. Nonces are stored alongside encrypted data to ensure correct decryption.
- **Key Management**: The key file (`key.key`) is critical for decryption. Ensure it is securely stored and protected. Losing the key file means losing access to your data.
- **Passphrase Strength**: Always use a strong passphrase to encrypt the key. A weak passphrase could be brute-forced, compromising the encryption key and hence the data.

## Future Improvements
- **Authenticated Encryption of Files**: Currently, file data is encrypted using **XChaCha20**, but incorporating an **authentication tag** for each file could further ensure data integrity.
- **Randomized Nonce for Key Encryption**: Use a fresh, unique nonce each time the key is encrypted and store it along with the key securely.
- **Improved CLI**: Add command-line argument support using `clap` or another crate for better automation and user experience.
- **Memory Management**: For very large files, consider implementing chunk-wise encryption with consistent handling to limit memory use.

## License
This project is licensed under the **MIT License**.

## Acknowledgments
- **Rust Crate Authors**: Thanks to the authors of the `pqcrypto`, `chacha20poly1305`, `blake3`, and `rpassword` crates for providing the building blocks for this project.
- **Learning Opportunity**: This project was developed as a personal learning exercise to explore modern cryptographic techniques, particularly those resilient to quantum threats.

## Contact
For questions, suggestions, or discussions, feel free to contact the author through the project's GitHub repository.

---
This README provides a detailed overview of the **Post-Quantum File Encryption Tool**, explaining the underlying technologies, how to use the tool, and important security considerations. Feel free to customize it further to suit any specific needs or contexts!

