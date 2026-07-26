


# OTP3 Streaming-Based OTP File Encryptor

This project is a command-line tool that performs XOR-based encryption and decryption using a key file, implemented using a **streaming approach** to efficiently process large files. It is written in Rust and utilizes buffered reading and writing to minimize memory usage, making it suitable for encrypting or decrypting large data sets without loading the entire file into memory.

## Features
- **Streaming-Based Processing**: Uses a streaming approach to read, process, and write data in small chunks, allowing efficient encryption or decryption for very large files.
- **Buffered File Handling**: Utilizes `BufReader` and `BufWriter` for enhanced performance and minimal memory usage during file I/O operations.
- **Simple One-Time Pad (OTP) Encryption**: Performs XOR encryption/decryption using a provided key file, showcasing the one-time pad encryption concept.

## Prerequisites
- **Rust** (version 1.56 or later recommended)
- A valid key file (`key.key`) that is at least as long as the total size of the file to be encrypted or decrypted.

## Installation
1. **Clone the repository** or download the source code:
   ```sh
   git clone <repository-url>
   cd streaming_xor_encryptor
   ```

2. **Build the project** using Cargo:
   ```sh
   cargo build --release
   ```

## Usage
1. **Prepare a key file** named `key.key` in the current directory. The key should contain enough random data to cover the size of the file you want to encrypt or decrypt.

2. **Run the program**:
   ```sh
   cargo run --release
   ```

3. **Provide input and output file names**:
   - You will be prompted to enter the input file name and the desired output file name.

   Example:
   ```
   Enter input file name:
   large_file.txt
   Enter output file name:
   encrypted_large_file.txt
   ```

4. The program will read chunks of the input file, XOR each byte with the corresponding byte in the key, and write the result to the output file. If the key is shorter than the input, it will wrap around and reuse the key as needed.

## Example Workflow
1. **Create a key file** named `key.key` with sufficient data:
   ```sh
   dd if=/dev/urandom of=key.key bs=4096 count=100
   ```

2. **Create an input file** named `example.txt`:
   ```sh
   echo "Hello, world!" > example.txt
   ```

3. **Run the program** to encrypt the file:
   ```sh
   cargo run --release
   ```

4. Enter `example.txt` as the input file and provide a name for the output file, e.g., `encrypted_example.txt`.

5. To decrypt, simply run the program again with the encrypted file as input and use the same key.

## Understanding OTP Security

The One-Time Pad (OTP) encryption method can be extremely secure when used correctly. For OTP to achieve perfect secrecy, the key must be truly random, at least as long as the message, and used only once. When these conditions are met, OTP encryption is theoretically unbreakable, as each possible message of the same length is equally probable.

However, improper key usage can lead to significant vulnerabilities. If the same key is reused for multiple messages, an attacker can compare ciphertexts and apply statistical analysis or a **crib-dragging attack** to reveal information about the plaintexts. Furthermore, if the key is predictable or non-random, an attacker could use **frequency analysis** or **chosen-plaintext attacks** to deduce parts of the original data, compromising the security of the encrypted message.

## Notes
- This application uses a simple XOR operation for both encryption and decryption. **XOR encryption is not secure** unless the key is truly random, is used only once, and is kept secret.
- The streaming-based approach ensures minimal memory usage, as data is read, processed, and written incrementally in small chunks.

## License
This project is licensed under the MIT License.

## Disclaimer
The XOR encryption method used here is intended for educational purposes and is not suitable for securing sensitive information. Use this tool for learning or simple non-critical use cases only.


