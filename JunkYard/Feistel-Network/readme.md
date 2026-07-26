Feistel Network Encryption App

Table of Contents
Introduction
Features
Dependencies
Installation
Usage
Encrypting a File
Decrypting a File
Security Considerations
Enhancements
License
Disclaimer
Introduction
The Feistel Network Encryption App is a command-line tool written in Rust that implements a Feistel network-based encryption and decryption mechanism. This tool allows users to securely encrypt and decrypt any file using a user-provided key. While custom encryption algorithms can be educational and provide flexibility, it's essential to understand that they may not offer the same security guarantees as well-established cryptographic standards like AES.

Features
File Encryption & Decryption: Encrypt and decrypt any file type.
Feistel Network Structure: Implements a Feistel network with customizable rounds and block sizes.
Secure Key Handling: Prompts users to enter encryption keys securely without echoing them to the terminal.
Initialization Vector (IV): Uses a random IV for each encryption operation to ensure ciphertext uniqueness.
Authentication: Incorporates HMAC-SHA256 to verify data integrity and authenticity.
Padding: Utilizes PKCS#7 padding to handle data that isn't a multiple of the block size.
Efficient I/O: Uses buffered readers and writers for improved performance with large files.
Memory Safety: Employs Rust's memory safety features and zeroizes sensitive data after use.
Dependencies
The project relies on the following Rust crates:

sha2 = "0.10.8" - For SHA-256 hashing.
hmac = "0.12.1" - For HMAC-SHA256 authentication.
rand = "0.8.5" - For generating random IVs.
zeroize = "1.5.6" - For securely clearing sensitive data from memory.
rpassword = "7.0.1" - For secure password input without echoing.
Installation
Prerequisites
Rust: Ensure you have Rust installed. If not, download it from rust-lang.org.
Steps
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/feistel_cipher.git
cd feistel_cipher
Update Cargo.toml:

Ensure your Cargo.toml includes the necessary dependencies:

toml
Copy code
[package]
name = "feistel_cipher"
version = "0.2.0"
edition = "2021"

[dependencies]
sha2 = "0.10.8"
hmac = "0.12.1"
rand = "0.8.5"
zeroize = "1.5.6"
rpassword = "7.0.1"
Build the Project:

Compile the project in release mode for optimized performance.

bash
Copy code
cargo build --release
The compiled binary will be located at ./target/release/feistel_cipher.

Usage
The Feistel Network Encryption App operates via the command line and supports two primary modes: encrypt and decrypt.

Command-Line Syntax
bash
Copy code
feistel_cipher <mode> <input_file> <output_file>
<mode>: Operation mode. Use encrypt to encrypt a file or decrypt to decrypt a file.
<input_file>: Path to the input file to be encrypted or decrypted.
<output_file>: Path where the output (encrypted or decrypted) file will be saved.
Note: The program will prompt you to enter the encryption/decryption key securely.

Encrypting a File
Run the Encryption Command:

bash
Copy code
./target/release/feistel_cipher encrypt <input_file> <output_file>
Example:

bash
Copy code
./target/release/feistel_cipher encrypt secret.txt secret.enc
Enter the Encryption Key:

After running the command, you'll be prompted to enter your encryption key. The input will be hidden for security.

mathematica
Copy code
Enter encryption key:
Encryption Completion:

Upon successful encryption, you'll see:

Copy code
Encryption completed successfully.
Decrypting a File
Run the Decryption Command:

bash
Copy code
./target/release/feistel_cipher decrypt <input_file> <output_file>
Example:

bash
Copy code
./target/release/feistel_cipher decrypt secret.enc decrypted.txt
Enter the Decryption Key:

Enter the same key used during encryption.

mathematica
Copy code
Enter encryption key:
Decryption Completion:

Upon successful decryption, you'll see:

Copy code
Decryption completed successfully.
Security Considerations
While this tool incorporates several security best practices, it's essential to understand its limitations and ensure proper usage:

Custom Encryption Algorithms: Custom implementations may have vulnerabilities not present in standardized algorithms. Use with caution, especially for sensitive data.
Key Security: Ensure your encryption key is strong, kept confidential, and not reused across different applications or services.
HMAC Verification: The tool uses HMAC-SHA256 to verify data integrity. If HMAC verification fails during decryption, it indicates possible data tampering.
Initialization Vector (IV): A new random IV is generated for each encryption operation, enhancing security by ensuring unique ciphertexts for identical plaintexts.
Memory Safety: Sensitive data, like encryption keys, are zeroized after use to prevent residual data from lingering in memory.
Enhancements
For further improvements and to bolster security, consider implementing the following enhancements:

Key Derivation Function (KDF):

Integrate a KDF like Argon2, PBKDF2, or scrypt to derive a secure encryption key from a user-provided password. This adds resistance against brute-force attacks.

Authenticated Encryption Modes:

Explore authenticated encryption modes such as Galois/Counter Mode (GCM) to combine encryption and authentication, simplifying the process and enhancing security.

Stream Processing for Large Files:

Modify the encryption and decryption functions to process files in streams or fixed-size chunks. This approach reduces memory usage and improves performance for large files.

Parallel Processing:

Utilize Rust's concurrency features to encrypt/decrypt multiple blocks in parallel, leveraging multi-core processors for improved performance.

Configuration Files:

Allow users to specify encryption parameters (e.g., number of rounds, block size) via configuration files, providing flexibility and adaptability.

Progress Indicators:

Implement progress bars or indicators to provide feedback during lengthy encryption or decryption operations, enhancing user experience.

License
This project is licensed under the MIT License.

Disclaimer
Security Warning: This Feistel Network Encryption App is intended for educational purposes and to demonstrate the implementation of a Feistel network in Rust. It is not recommended for securing sensitive or production data. Custom cryptographic solutions can have unforeseen vulnerabilities and may not provide the robust security guarantees that established algorithms like AES offer. For securing sensitive information, always use well-reviewed and standardized cryptographic libraries and protocols.

How to Create and Download the README
Create the README.md File:

Open your terminal or command prompt.

Navigate to your project directory.

Use a text editor to create and open the README.md file. For example, using nano:

bash
Copy code
nano README.md
Paste the above content into the file.

Save and Exit:

If using nano, press CTRL + O to write the changes, then ENTER to confirm.
Press CTRL + X to exit the editor.
Verify the File:

bash
Copy code
cat README.md
You should see the content as provided above.

