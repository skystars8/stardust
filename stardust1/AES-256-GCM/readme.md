enc encrypt a.tst b.tst

enc decrypt b.tst c.tst

see readme.html from a browser


How the App Works
The Encryptor app works by taking an input file and a password from the user to perform encryption or decryption. Here's a step-by-step explanation:

User Interaction:

The user runs the app via the command line, specifying whether to encrypt or decrypt, along with the input and output file paths.
The app prompts the user to enter a password, which is used for key derivation.
Key Derivation using Argon2id:

A random 16-byte salt is generated for each encryption operation.
The user's password and the salt are used with Argon2id to derive a 256-bit key.
Argon2id provides resistance against GPU and ASIC attacks due to its memory-hard properties.
Encryption with AES-256-GCM:

A random 12-byte nonce is generated for AES-256-GCM.
The plaintext file is read into memory.
The plaintext is encrypted using the derived key and nonce.
AES-256-GCM provides both confidentiality and integrity through authenticated encryption.
Writing Encrypted Data:

The salt, nonce, and ciphertext are concatenated and written to the output file.
The format ensures that all necessary components for decryption are stored together.
Decryption Process:

The encrypted file is read, and the salt, nonce, and ciphertext are extracted.
The same key derivation process is repeated using the user's password and extracted salt.
The ciphertext is decrypted using the derived key and nonce.
The resulting plaintext is written to the specified output file.
Error Handling:

The app provides meaningful error messages if any step fails, such as incorrect passwords or corrupted files.
Security Considerations
Password Security:

The strength of the encryption relies heavily on the strength of the user's password.
Users are encouraged to use long, complex passwords that are difficult to guess.
Salt and Nonce Randomization:

Salts and nonces are randomly generated for each operation to ensure that identical plaintexts encrypted with the same password will result in different ciphertexts.
Authenticated Encryption:

AES-256-GCM ensures that any tampering with the encrypted data can be detected during decryption.
Dependency Management:

The app uses well-maintained Rust crates for cryptography, ensuring reliability and security.

By following modern cryptographic practices and utilizing strong algorithms, Encryptor offers a reliable solution for file encryption needs. Whether you're securing personal documents or sensitive information, this tool provides a balance between ease of use and robust security.

Feel free to modify and extend the application to fit your requirements, and consider contributing back to the project to help others benefit from your enhancements.
