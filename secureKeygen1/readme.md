# Secure Key Generator

## Overview

The Secure Key Generator is a Rust application designed to create a random cryptographic key of user-specified size. The key can be generated in a range from **1 byte to 5 gigabytes**, ensuring it meets different security needs. The generated key is saved to a binary file named `key.key`, and the application prevents overwriting an existing key by checking if the file already exists.

## Features

- **Random Key Generation**: Uses a cryptographically secure RNG (`OsRng`) for randomness, making the key suitable for cryptographic applications.
- **Flexible Key Sizes**: Users can specify the key size in bytes, megabytes (MB), or gigabytes (GB).
- **Safety Feature**: The program checks for an existing key file (`key.key`) to avoid accidental overwriting.

## Usage

### Prerequisites

- **Rust**: Ensure you have Rust installed. You can install Rust using [rustup](https://rustup.rs/).
- **rand Crate**: The project requires the `rand` crate, version `0.8.5`. This is already specified in the `Cargo.toml` file.

### Running the Application

1. Clone the repository or download the source code.
2. Navigate to the project directory.
3. Run the following command to compile and run the application:

   ```sh
   cargo run
   ```

4. You will be prompted to enter the key size. You can specify the size in bytes, MB, or GB. Examples:
   - `1024B` for 1024 bytes
   - `10MB` for 10 megabytes
   - `1GB` for 1 gigabyte

5. The program will generate the key and save it to `key.key`. If `key.key` already exists, the program will output an error to avoid overwriting the file.

### Example

```sh
Enter the key size (e.g., 1024B, 10MB, 1GB):
10MB
Random key of size 10485760 bytes generated and saved to 'key.key'.
```

## Code Explanation

- **Key Generation**: The key is generated using `OsRng`, which utilizes the operating system's secure random number generator to ensure high-quality randomness.
- **Chunked Writing**: For memory efficiency, the key is generated and written to the file in 10 MB chunks, making it feasible to create very large keys without consuming excessive memory.
- **No Overwriting**: Before generating the key, the program checks if `key.key` already exists. If it does, it outputs an error message to prevent accidental data loss.

## Dependencies

The application relies on the following dependencies:

- `rand = "0.8.5"`: Provides cryptographically secure random number generation.

## Testing

The project includes unit tests for the `parse_size` function, which validates the parsing of user inputs like `1024B`, `10MB`, and `1GB` to ensure correct size calculation.

To run the tests, use:

```sh
cargo test
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contribution

Contributions are welcome! Feel free to submit a pull request or open an issue to suggest improvements or report bugs.

## Author

- **Your Name** - Initial work - [Your GitHub Profile](https://github.com/your-profile)

## Disclaimer

This application is intended for educational and general-purpose key generation. For sensitive cryptographic operations, please ensure you follow best practices and guidelines suitable for your specific use case.

