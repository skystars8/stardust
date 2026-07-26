
# version 000

# XOR File Encryptor with Rijndael S-box Randomization

## Overview




This project is a command-line file encryption and decryption utility written in Rust. It uses a custom XOR-based encryption method enhanced with a **256-byte nonce** that is shuffled and further randomized using the **Rijndael S-box** (the S-box used in AES encryption). This approach helps mitigate the risk of repeating patterns that can emerge when using simpler XOR encryption, especially with repetitive plaintexts and keys.

### Key Features:
- **XOR Encryption**: Encrypts/decrypts files by XOR-ing data with a key and a large nonce.
- **256-byte Nonce**: A large nonce is used to prevent repeating patterns in the ciphertext, even with repetitive plaintext and key material.
- **Rijndael S-box Randomization**: The nonce is generated and randomized using the Rijndael S-box to introduce additional non-linearity, making the encrypted output much more secure.

## How It Works
### Encryption
1. **Key File**: The key is read from a file named `key.key`. This key is used for both encryption and decryption. It must be kept secret for the encryption to remain secure.
2. **Nonce Generation**: A 256-byte nonce is generated. Each byte is initially assigned a unique value (0-255). The nonce is then shuffled to create a unique sequence and transformed using the **Rijndael S-box** to add non-linearity and randomness.
3. **XOR Operation**: The plaintext is encrypted by XOR-ing each byte with the corresponding byte of the key and the nonce, cycling through both if the data is longer than either.
4. **Output**: The resulting ciphertext is written to the output file, with the nonce prepended to ensure it can be used for decryption.

### Decryption
1. **Read Nonce**: The nonce is extracted from the beginning of the input file.
2. **XOR Operation**: The ciphertext is decrypted by XOR-ing each byte of the encrypted message with the corresponding byte of the key and the nonce.
3. **Output**: The decrypted plaintext is written to the specified output file.

## Usage
This utility can be run from the command line using the following syntax:

```sh
cargo run -- <mode> <input_file> <output_file>
```

- **`mode`**: Either `E` for encryption or `D` for decryption.
- **`input_file`**: The path to the file you want to encrypt or decrypt.
- **`output_file`**: The path where you want to save the result.

Example to **encrypt** a file:
```sh
cargo run -- E plaintext.txt encrypted_output.txt
```

Example to **decrypt** a file:
```sh
cargo run -- D encrypted_output.txt decrypted_output.txt
```

## Key File
The key must be stored in a file called `key.key`. If this file is missing or empty, the program will exit with an error. Make sure this key file is kept secure, as anyone with access to the key can decrypt the encrypted data.

## How the Nonce Works
- The **nonce** used in this implementation is a **256-byte array** where each possible byte value (0-255) appears exactly once, ensuring there are no repeated values.
- The nonce is **shuffled** randomly to create an unpredictable sequence, and then each byte is transformed using the **Rijndael S-box**. This ensures the nonce is highly random, effectively eliminating any discernible patterns in the output, even when the plaintext or key is repetitive.

### Why Use a 256-byte Nonce?
- A large nonce of 256 bytes provides **extremely high variability**, reducing the chances of patterns appearing in the ciphertext.
- This is particularly important when dealing with repetitive keys or plaintext (e.g., strings of `"aaaa..."`), where smaller nonces might lead to visible repeating patterns in the encrypted output.
- The **Rijndael S-box** adds non-linearity, making the nonce even harder to predict or reverse-engineer.

## Security Considerations
- **XOR-based encryption** is not inherently secure without additional precautions, as it can be vulnerable to **known-plaintext** or **repeating key** attacks. However, the use of a large, randomized nonce mitigates these risks significantly.
- **Key Management**: The key file (`key.key`) must be kept secure. If an attacker gains access to both the key and the encrypted file, they can easily decrypt the contents.
- **Nonce Uniqueness**: The nonce is unique for each encryption, ensuring that even if the same plaintext and key are used multiple times, the output will be different each time.

## Limitations
- **Key and Nonce Length**: The key is expected to be read from a file, and if it is shorter than the data, it will be reused cyclically. Similarly, the nonce is also reused in a cyclical fashion if the data is longer than 256 bytes.
- **Overhead**: The use of a 256-byte nonce adds a fixed overhead to the encrypted file size, which may be unnecessary for small files. However, this is a trade-off for enhanced security.

## Dependencies
- **`clap`**: Used for command-line argument parsing.
- **`rand`**: Used for shuffling the nonce to ensure randomness.

## Building and Running
To build and run the project, ensure you have Rust installed, and then run:
```sh
cargo build
cargo run -- <mode> <input_file> <output_file>
```

Ensure that `key.key` is present in the same directory as the executable or specify its correct path.

## Example
1. Create a key file:
   ```sh
   echo "mysecurekey" > key.key
   ```
2. Encrypt a plaintext file:
   ```sh
   cargo run -- E input.txt encrypted.bin
   ```
3. Decrypt the file back:
   ```sh
   cargo run -- D encrypted.bin decrypted.txt
   ```

## Conclusion
This XOR-based file encryptor uses a custom approach to enhance the security of the standard XOR method. By leveraging a **256-byte nonce** that is shuffled and transformed with the **Rijndael S-box**, it ensures that patterns are eliminated from the encrypted output, making it more resistant to attacks. While the method may have more overhead than conventional XOR schemes, it is well-suited for scenarios where preventing any discernible pattern in the encrypted output is crucial.

