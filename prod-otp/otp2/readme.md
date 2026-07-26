# OTP2  Chunk-Based OTP File Encryptor

This project is a command-line tool that performs XOR-based encryption and decryption using a key file, processing files in **chunks** for better memory efficiency. It is implemented in Rust and designed to handle large files efficiently by reading and writing in chunks instead of loading the entire file into memory.

## Features
- **Chunk-Based Processing**: Encrypt or decrypt files using chunk-based XOR processing, suitable for large files without consuming too much memory.
- **Buffered File Handling**: Utilizes buffered reading and writing for enhanced performance when dealing with large files.
- **Simple One-Time Pad (OTP) Encryption**: Performs XOR encryption/decryption using a provided key file, offering a straightforward demonstration of one-time pad techniques.

## Prerequisites
- **Rust** (version 1.56 or later recommended)
- A valid key file (`key.key`) that is at least as long as the total size of the file to be encrypted or decrypted.

## Installation
1. **Clone the repository** or download the source code:
   ```sh
   git clone <repository-url>
   cd otp_chunk_based_encryptor
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

4. The program reads chunks of the input file, XORs each byte with the corresponding byte in the key, and writes the result to the output file. If the key is shorter than the input, it wraps around.

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

## Notes
- This application uses a simple XOR operation for both encryption and decryption. **XOR encryption is not secure** unless the key is truly random, is used only once, and is kept secret.
- The **chunk size** is set to **4KB** by default, which can be adjusted by modifying the `CHUNK_SIZE` constant in the code. This chunk size allows the program to handle large files without consuming excessive memory.

## License
This project is licensed under the MIT License.

## Disclaimer
The XOR encryption method used here is intended for educational purposes and is not suitable for securing sensitive information. Use this tool for learning or simple non-critical use cases only.

