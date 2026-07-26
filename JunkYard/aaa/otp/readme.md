# OTP XOR Encryption App - README

## Overview
This application is a simple, yet powerful, **OTP (One-Time Pad) XOR Encryption tool** built in Rust. It uses a key file to encrypt or decrypt an input file using an XOR-based approach, which is highly secure when the key management is done properly. The main focus of this application is **simplicity and reliability**, with a design that minimizes the complexity of key handling while ensuring that users can easily encrypt or decrypt files without complicated configurations.

## Design Choices
The design choices of this application were made with simplicity, reliability, and usability in mind. Let's go through these choices in detail:

### 1. **No Chunk-Based Processing**
- The application reads the entire input file and the key into memory at once rather than processing the data in chunks. This design choice was made to keep the implementation simple and minimize the risk of issues arising from incorrect handling of data chunks.
- Users are expected to have a key length at least as large as the file being encrypted. Since both the key and the input are read entirely into memory, this approach works well when the key and file sizes are appropriate for the available system memory.

### 2. **Independent Key Management**
- **No Overwrites or Modifications to Key File**: The key file (`key.key`) is used strictly in read-only mode. This ensures that the key file is not accidentally modified, which could lead to data loss or the inability to decrypt previously encrypted data.
- **Static Key File**: The design avoids dynamic generation or modification of keys. Users are responsible for providing and managing the key file, which ensures more control over key security. This is also beneficial for OTP-like security, where keys should never be reused.

### 3. **No Mode Selection - Symmetric Encryption**
- This version of the app removes the need for an explicit encryption or decryption mode (`E` or `D`). Since the XOR operation is symmetric, the same operation is used for both encryption and decryption. This means that the process is simplified—users just need to provide an input file, an output file, and a key.
- The lack of mode selection keeps the user interaction straightforward and minimizes potential user errors related to choosing the wrong mode.

### 4. **No Nonce or Initialization Vector (IV)**
- To keep the design simple and deterministic, **no nonce or IV** is used. This is intended for scenarios where users explicitly understand and manage their keys, ensuring that the same key and input will produce predictable results.
- Since there is no nonce, the system can handle **executable files or any other type of file** without additional data added to the file, which is important for ensuring the output is consistent with the expectations of binary or executable content.

### 5. **File Size Consistency Check**
- After processing, the application verifies that the **output file size matches the input file size**. This is a simple yet effective way to verify that the encryption or decryption process hasn't inadvertently altered the data length, which is crucial for reliability, especially when dealing with executable files.
- If the sizes do not match, the application halts with an error, ensuring that the user is aware of any potential issues.

### 6. **No File Overwriting**
- **Input and Output Files Are Separate**: The application explicitly asks for an input file and an output file to avoid accidental overwriting of the original data. This design is in line with the goal of ensuring reliability and minimizing user errors.
- By enforcing separate files, users can be confident that their original data will remain intact, which is particularly useful for secure operations.

### 7. **Encryption and Decryption Symmetry**
- The encryption and decryption processes are **identical** due to the XOR operation's reversible nature. Encrypting twice with the same key will yield the original plaintext, which makes the operation simple and intuitive.


## Features Overview
### 1. **Simple User Interaction**
- The user is prompted to enter the **input file** and **output file** names. The straightforward prompt-based interaction helps non-technical users understand how to operate the tool with ease.

### 2. **Full Memory-Based Processing**
- Both the **input data** and the **key** are read into memory in their entirety. This approach ensures that XOR operations are performed efficiently, making the app suitable for relatively large files, provided the user's system has sufficient memory.

### 3. **Static Key Length Requirement**
- The **key file** must be at least as long as the input file. This requirement ensures that every byte of the input can be XOR-ed with a corresponding byte of the key, maintaining the **security properties** expected of OTP encryption.
- If the key is shorter than the input data, the program will immediately halt and notify the user, avoiding partial or insecure encryption.

### 4. **Warning for Identical Input and Key**
- If the input data and key are identical, the output will consist of all zero bytes due to the nature of the XOR operation. Users are encouraged to manage their keys carefully to avoid such scenarios.

### 5. **Cross-Platform Compatibility**
- The app avoids using platform-specific features or permissions that could complicate compatibility. By keeping the operations basic (file reading, writing, and XOR), the app can run on any system where Rust is supported.

### 6. **Error Handling and User Feedback**
- The app provides **clear feedback** for common errors, such as missing files, insufficient key length, and incorrect input. This is important for usability, as it helps users understand what went wrong and how to correct it.
- Consistent error messages make troubleshooting easier, allowing the user to quickly correct input issues or key management problems.

## How to Use the Application
1. **Prepare a Key File** (`key.key`): Ensure the key file is at least as long as the input file to guarantee secure encryption.
2. **Run the Application**: Execute the compiled binary. The app will prompt for:
   - **Input File**: The file to be encrypted or decrypted.
   - **Output File**: The name of the resulting output file. This should be different from the input file to prevent overwrites.
3. **Review the Results**: The application will confirm successful completion. If there are issues, such as mismatched file sizes, an error message will be provided.

## Security Considerations
- **One-Time Use of Keys**: For this application to maintain **OTP-level security**, the key should be used only once. Reusing keys can lead to vulnerabilities, especially if an attacker gains access to two ciphertexts encrypted with the same key.
- **Key Management**: This app does not handle key generation or deletion. Users should consider implementing a separate key management strategy to securely create, store, and delete keys.

## Conclusion
This application prioritizes **simplicity, reliability, and predictability**. By minimizing complex features such as chunk processing, nonce generation, or automatic key modification, the app ensures that users have **direct control** over both the key and the data. This makes it suitable for scenarios where users are comfortable managing their own security processes and need a straightforward tool for encryption and decryption without unnecessary complexity.

If you have questions or require modifications for additional features, feel free to explore or modify the code as needed. This tool is designed to be a foundation for reliable and understandable file encryption.
