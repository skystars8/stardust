# Secure File Encryptor

This project is a command-line tool that allows you to encrypt and decrypt files using XOR encryption, with additional security provided by a random salt and nonce. The tool uses the Argon2 key derivation function to generate a secure key based on a password provided by the user. This makes the encryption more resistant to brute-force attacks and adds randomness to each encryption operation.

## Features
- **Encryption and Decryption**: Provides simple XOR-based encryption and decryption of files.
- **Key Derivation**: Uses Argon2 to derive a key from a user-provided password.
- **Salt and Nonce**: Adds security by generating a random salt and nonce for each encryption.

## Dependencies
- `argon2`: Used for secure key derivation.
- `rand`: Used to generate random salt and nonce values.

## Usage
### Compile the Program
To compile the program, run:
```sh
cargo build
```

### Run the Program
The program requires four arguments:
1. **Mode**: Either `e` for encryption or `d` for decryption.
2. **Input File**: The path to the input file to be encrypted or decrypted.
3. **Output File**: The path where the output file will be saved.
4. **Password**: A password to derive the encryption key.

#### Example Commands

**Encrypt a File**
```sh
cargo run e input.txt encrypted.txt your_password
```
- `e`: Specifies encryption mode.
- `input.txt`: The input file to be encrypted.
- `encrypted.txt`: The output file where the encrypted data will be saved.
- `your_password`: The password used for key generation.

**Decrypt a File**
```sh
cargo run d encrypted.txt decrypted.txt your_password
```
- `d`: Specifies decryption mode.
- `encrypted.txt`: The input file to be decrypted.
- `decrypted.txt`: The output file where the decrypted data will be saved.
- `your_password`: The password used to generate the key (must match the encryption password).

## How It Works
1. **Encryption (`e`)**:
   - A random salt and nonce are generated for each encryption.
   - The key is derived from the password and salt using Argon2.
   - XOR encryption is performed using the derived key and nonce.
   - The salt, nonce, and encrypted data are written to the output file.

2. **Decryption (`d`)**:
   - The salt and nonce are extracted from the beginning of the input file.
   - The key is derived using the password and extracted salt.
   - XOR decryption is performed using the derived key and nonce.
   - The decrypted data is saved to the output file.

## Important Notes
- **Password Consistency**: Make sure to use the same password for decryption as was used during encryption.
- **Salt and Nonce**: The salt and nonce are saved as part of the encrypted file, allowing them to be used during decryption.
- **Security Warning**: XOR encryption is a simple method and not suitable for highly sensitive data. This implementation includes random salt and nonce to increase its security, but it should not be considered a replacement for more advanced encryption algorithms.

## Compilation and Running Requirements
- **Rust**: This program requires Rust to compile and run. Install Rust from [rust-lang.org](https://www.rust-lang.org/).

## License
This project is licensed under the MIT License.

