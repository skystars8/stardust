# Secure File Encryptor

This project is a command-line tool that allows you to encrypt and decrypt files using XOR encryption. The tool is enhanced with additional security measures, such as using Argon2 for key derivation, a random salt, and nonce. These measures make the encryption more resistant to brute-force attacks and add randomness to each encryption operation, ensuring strong security. This README provides an extensive overview of the features, security mechanisms, usage instructions, and best practices for using this tool securely.

## Features
- **Encryption and Decryption**: Offers simple XOR-based encryption and decryption of files.
- **Key Derivation**: Uses Argon2id to derive a key from a user-provided password, making the key secure against attacks targeting weak passwords.
- **Salt and Nonce**: Adds security by generating a random salt (32 bytes) and nonce (32 bytes) for each encryption to ensure uniqueness and randomness.
- **Strong Argon2 Parameters**: Uses increased computational parameters for Argon2 to provide enhanced resistance to brute-force attacks.
- **Same Directory Constraint**: Ensures that input and output files must be in the same directory as the executable, preventing potential abuse or hijacking of files outside the working directory.
- **No Overwriting Files**: Prevents accidental overwriting of output files, forcing users to specify a new output file name each time.

## Dependencies
- **Rust**: This project is written in Rust, requiring Rust for compilation and execution. You can install Rust from [rust-lang.org](https://www.rust-lang.org/).
- `argon2`: For secure key derivation.
- `rand`: For generating random values such as the salt and nonce.

## How It Works
1. **Password-Based Key Derivation**: The provided password is hashed using the Argon2id algorithm. This generates a strong 256-bit key using a random salt for each encryption/decryption session.
2. **XOR Encryption**: Data is encrypted or decrypted using XOR with a derived key and a nonce. The nonce ensures that identical data produces different outputs with each encryption.
3. **Salt and Nonce Management**: A unique salt and nonce are generated for every encryption, making sure that even if the same password is used repeatedly, the output is distinct.
4. **Directory and File Constraints**: Input and output files must be located in the same directory as the executable to avoid unauthorized access to files outside of the controlled directory. Additionally, files are never overwritten to prevent data loss.

## Usage
### Compile the Program
To compile the program, run:
```sh
cargo build
```

### Run the Program
The program requires four arguments:
1. **Mode**: Either `e` for encryption or `d` for decryption.
2. **Input File**: The name of the input file to be encrypted or decrypted (must be in the same directory as the executable).
3. **Output File**: The name of the output file where the results will be saved (must also be in the same directory as the executable).
4. **Password**: A password that will be used to derive the encryption/decryption key.

### Example Commands

#### Encrypt a File
```sh
cargo run e input.txt encrypted.txt your_password
```
- `e`: Specifies encryption mode.
- `input.txt`: The input file to be encrypted (must be in the same directory as the executable).
- `encrypted.txt`: The output file where the encrypted data will be saved.
- `your_password`: The password used for key generation.

#### Decrypt a File
```sh
cargo run d encrypted.txt decrypted.txt your_password
```
- `d`: Specifies decryption mode.
- `encrypted.txt`: The input file to be decrypted (must be in the same directory as the executable).
- `decrypted.txt`: The output file where the decrypted data will be saved.
- `your_password`: The password used to generate the key (must match the encryption password).

## Security Measures
1. **Salt (32 Bytes)**: The salt is randomly generated for each encryption operation, ensuring that the key derived from the password is unique each time, even with the same password. A 32-byte salt provides a high level of security, protecting against rainbow table and precomputed attacks.

2. **Nonce (32 Bytes)**: The nonce is also randomly generated for each encryption. It ensures that even when the same plaintext is encrypted multiple times with the same password, the output is different each time. This prevents pattern analysis and increases the unpredictability of the encrypted output.

3. **Argon2id Key Derivation**: Argon2id is a memory-hard function used to derive a secure encryption key from the password. By setting a high memory cost (128MB) and time cost (5 iterations), the implementation significantly raises the computational cost for an attacker trying to brute-force or guess the password.

4. **File Directory Restrictions**: Both input and output files must be in the same directory as the executable. This restriction prevents attackers from tricking the user into modifying files in sensitive locations on their system.

5. **Prevention of File Overwriting**: To avoid accidental data loss, the program checks if the output file already exists. If it does, it forces the user to specify a new output file name, ensuring that no files are overwritten unintentionally.

## Best Practices
- **Use Strong Passwords**: To maximize security, use long, complex passwords that include a combination of upper and lower case letters, numbers, and symbols.
- **Encrypt Multiple Times for Extra Security**: For especially sensitive files, consider encrypting the file multiple times with different passwords. This adds multiple independent layers of encryption.
- **Keep the Executable Directory Secure**: Ensure that the directory containing the executable and the input/output files is secure and not accessible by unauthorized users.

## Limitations
- **XOR Encryption**: The application uses XOR encryption, which, while simple, is not as secure as more advanced encryption algorithms like AES. However, the use of Argon2, salt, and nonce provides additional layers of security to make it more robust.
- **File Size**: The entire input file is loaded into memory during encryption and decryption. For very large files, this could lead to high memory usage.

## License
This project is licensed under the MIT License.

## Disclaimer
This tool is intended for educational purposes and light use cases where high levels of security are not strictly required. For highly sensitive data, consider using more sophisticated cryptographic methods, such as AES-GCM, that provide authenticated encryption.

