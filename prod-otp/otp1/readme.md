

# OTP1 File Encryptor

This is a simple command-line program written in Rust that performs XOR encryption and decryption of files using a key file. The program uses memory mapping for efficient file handling and allows you to encrypt or decrypt files by XORing them with a key.

## Features
- XOR encryption and decryption using a key file.
- Memory-mapped file handling for efficient processing of large files.
- Simple and lightweight implementation.

## Prerequisites
- Rust (version 1.56 or later recommended)
- A valid key file (`key.key`) that contains enough data to match the size of the input file.

## Installation
1. Clone this repository or download the source code.
   ```sh
   git clone <repository-url>
   cd otp_file_encryptor
   ```

2. Build the project using Cargo:
   ```sh
   cargo build --release
   ```

## Usage
1. Ensure you have a key file named `key.key` in the current directory. The key file must be at least as large as the input file to ensure proper encryption.

2. Run the program:
   ```sh
   cargo run --release
   ```

3. You will be prompted to enter the input file name and output file name.

   Example:
   ```
   Enter input file name:
   example.txt
   Enter output file name:
   encrypted_example.txt
   ```

4. The program will read the input file, XOR it with the key, and save the result to the output file.

## Example Workflow
1. Create a key file named `key.key` with sufficient data:
   ```sh
   echo "This is a sample key data for XOR." > key.key
   ```

2. Create an input file named `example.txt`:
   ```sh
   echo "Hello, world!" > example.txt
   ```

3. Run the program:
   ```sh
   cargo run --release
   ```

4. Enter `example.txt` as the input file and provide a name for the output file, e.g., `encrypted_example.txt`.

## Notes
- The program uses a simple XOR operation for both encryption and decryption. To decrypt a file, simply run the program again with the encrypted file as input and use the same key.
- The key must be at least as long as the input file for the encryption to work correctly.

## License
This project is licensed under the MIT License.

## Disclaimer
This encryption method (XOR) is not secure for protecting sensitive data and is intended for educational or simple use cases only.

