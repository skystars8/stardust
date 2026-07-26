# Feistel Network Encryption CLI

## Overview
This is a command-line application written in Rust that uses a Feistel network encryption scheme with the Rijndael S-box (used in AES) for non-linearity. The application allows you to encrypt or decrypt files using a specified number of Feistel rounds.

## Rijndael S-box Explained
The Rijndael S-box, used in this application, is a fundamental part of the AES encryption algorithm. It introduces non-linearity to the encryption process, making it more resistant to cryptanalytic attacks. The S-box is constructed using a combination of the multiplicative inverse in the Galois Field \( GF(2^8) \) and an affine transformation, ensuring strong non-linear substitution properties. This combination provides significant security by diffusing the bits and ensuring that small changes in the input propagate throughout the output. The Rijndael S-box is designed to be resistant to both linear and differential cryptanalysis, which are common techniques used to break simpler ciphers.

## Features
- **Encryption and Decryption**: Supports both encryption and decryption of files.
- **Feistel Network**: Utilizes a symmetric Feistel network structure, ensuring that encryption and decryption processes are straightforward to reverse.
- **Default Key Handling**: If a key file named `key.key` is not present, a new 16-byte key will be generated automatically.

## Usage
The CLI accepts four arguments:
1. **Mode**: `encrypt` or `decrypt`
2. **Input File**: The file to be encrypted or decrypted
3. **Output File**: The file where the resulting output will be saved
4. **Rounds (Optional)**: The number of Feistel rounds to use (default is 16)

### Example Commands
#### Encrypt a File
```sh
fiestel encrypt input.txt encrypted.txt
```
#### Decrypt a File
```sh
fiestel decrypt encrypted.txt decrypted.txt
```
#### Specify the Number of Rounds
```sh
fiestel encrypt input.txt encrypted.txt --rounds 20
```

## Important Notes
- **Key File Handling**: The application uses a key file named `key.key` by default, located in the same directory as the executable. If `key.key` does not exist, it will automatically generate a new key each time the program is run. **This means that if you encrypt a file, lose the `key.key` file, and then rerun the program, the new key will be different, and you will not be able to decrypt the original file.** Always store the `key.key` file securely if you wish to decrypt your data later.

- **Output File Overwriting**: The specified output file will be overwritten if it already exists. Be careful not to accidentally overwrite important data when specifying the output file.

## Dependencies
- **`rand`**: Used for generating random keys.
- **`clap`**: Used for command-line argument parsing.

### Adding Dependencies
Ensure that your `Cargo.toml` includes the following dependencies:
```toml
[dependencies]
rand = "0.8.5"
clap = "4.5.20"
```

## Compilation
To compile the application, run:
```sh
cargo build --release
```

This will create an executable in the `target/release` directory.

## Security Considerations
- **Key Security**: The security of the encryption depends on the secrecy of `key.key`. Make sure to store it securely.
- **File Overwriting**: The output file will be overwritten without any warning if it already exists. Be cautious when specifying output filenames.


