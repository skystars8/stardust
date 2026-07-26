use std::fs::{metadata, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use aes::Aes256;
use argon2::{Argon2, Params};
use clap::{Parser, Subcommand};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

/// A versatile crypto tool for key generation and XOR encryption/decryption.
#[derive(Parser)]
#[command(
    disable_help_flag = true,
    disable_version_flag = true,
    help_expected = false
)]
struct Cli {
    /// Subcommands for the crypto tool.
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a key file.
    Keygen {
        /// Size of the key file (e.g., 32bytes, 20mb, 5gb).
        size: String,
        /// Mode of key generation: random or deterministic.
        #[arg(long)]
        mode: String,
        /// Password for deterministic key generation.
        #[arg(long)]
        password: Option<String>,
    },
    /// Perform XOR encryption/decryption.
    Xor {
        /// Input file path.
        input_file: String,
        /// Output file path.
        output_file: String,
        /// Key file path.
        key_file: String,
    },
}

fn main() -> io::Result<()> {
    let cli_result = Cli::try_parse();

    match cli_result {
        Ok(cli) => match cli.command {
            Commands::Keygen { size, mode, password } => {
                keygen(size, mode, password)?;
            }
            Commands::Xor {
                input_file,
                output_file,
                key_file,
            } => {
                xor_process(&input_file, &output_file, &key_file)?;
            }
        },
        Err(_) => {
            eprintln!("Usage: crypt <COMMAND>");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Key generation function.
fn keygen(size_arg: String, mode: String, password: Option<String>) -> io::Result<()> {
    if mode != "random" && mode != "deterministic" {
        eprintln!("Error: Mode must be 'random' or 'deterministic'.");
        eprintln!("Usage: crypt <COMMAND>");
        std::process::exit(1);
    }

    if mode == "deterministic" && password.is_none() {
        eprintln!("Error: --password is required in deterministic mode.");
        eprintln!("Usage: crypt <COMMAND>");
        std::process::exit(1);
    }

    // Parse the size argument
    let size_in_bytes = match parse_size(&size_arg) {
        Ok(size) => size,
        Err(err) => {
            eprintln!("Error parsing size: {}", err);
            std::process::exit(1);
        }
    };

    let output_file = "key.key";

    // Check if the file already exists
    if Path::new(output_file).exists() {
        eprintln!("Error: File '{}' already exists.", output_file);
        std::process::exit(1);
    }

    // Create the file
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_file)?;

    // Buffer settings
    let buffer_size = 1024 * 1024; // 1 MB buffer
    let mut buffer = vec![0u8; buffer_size];
    let mut bytes_written = 0;

    if mode == "random" {
        // Initialize the random number generator
        let mut rng = OsRng;

        // Write random data to the file in chunks
        while bytes_written < size_in_bytes {
            let bytes_to_write = std::cmp::min(buffer_size, size_in_bytes - bytes_written);

            // Fill the buffer with random bytes
            rng.fill_bytes(&mut buffer[..bytes_to_write]);

            // Write the buffer to the file
            file.write_all(&buffer[..bytes_to_write])?;
            bytes_written += bytes_to_write;
        }
    } else {
        // Deterministic mode using password
        // Compile-time configurable parameters
        const SALT: &[u8] = b"your_salt_here"; // Must be at least 8 bytes
        const IV: [u8; 16] = [
            12, 85, 240, 66, 171, 19, 55, 129, 200, 33, 147, 89, 78, 123, 211, 34,
        ]; // Must be 16 bytes

        // Argon2 parameters
        const ARGON2_MEMORY_COST: u32 = 65536; // Memory cost in kibibytes
        const ARGON2_TIME_COST: u32 = 3; // Number of iterations
        const ARGON2_PARALLELISM: u32 = 1; // Degree of parallelism

        // Define type for AES-256 CTR mode
        type Aes256Ctr = ctr::Ctr64BE<Aes256>;

        // Derive a key using Argon2
        let params = Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to create Argon2 parameters: {}", e),
            )
        })?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let password_str = password.unwrap();
        let password_bytes = password_str.as_bytes();

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password_bytes, SALT, &mut derived_key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Failed to derive key with Argon2: {}", e),
                )
            })?;

        // Initialize AES-256 in CTR mode with derived key and IV
        let mut cipher = Aes256Ctr::new(&derived_key.into(), &IV.into());

        // Use a CSPRNG seeded with the derived key for additional randomness
        let mut rng = ChaCha20Rng::from_seed(derived_key);

        while bytes_written < size_in_bytes {
            let bytes_to_write = std::cmp::min(buffer_size, size_in_bytes - bytes_written);

            // Fill the buffer with random bytes
            rng.fill_bytes(&mut buffer[..bytes_to_write]);

            // Encrypt the buffer
            cipher.apply_keystream(&mut buffer[..bytes_to_write]);

            // Write the buffer to the file
            file.write_all(&buffer[..bytes_to_write])?;
            bytes_written += bytes_to_write;
        }

        // Zeroize sensitive data
        derived_key.zeroize();
        buffer.zeroize();
    }

    // Print success message
    println!(
        "Successfully generated '{}' with size {} bytes.",
        output_file, size_in_bytes
    );

    Ok(())
}

/// XOR encryption/decryption function.
fn xor_process(input_file: &str, output_file: &str, key_file: &str) -> io::Result<()> {
    // Get input, output, and key file paths
    let input_path = Path::new(input_file);
    let output_path = Path::new(output_file);
    let key_path = Path::new(key_file);

    // Open the key file
    let mut key_file = File::open(&key_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Key file '{}' not found or cannot be opened: {}",
                key_path.display(),
                e
            ),
        )
    })?;
    let mut key = Vec::new();
    key_file.read_to_end(&mut key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read key file '{}': {}", key_path.display(), e),
        )
    })?;

    // Check if the key file is empty
    if key.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Key file '{}' is empty. Please provide a valid key.",
                key_path.display()
            ),
        ));
    }

    // Open the input file
    let mut input_file = File::open(&input_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Unable to open input file '{}': {}",
                input_path.display(),
                e
            ),
        )
    })?;
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read input file '{}': {}", input_path.display(), e),
        )
    })?;

    // Check if the input file is empty
    if input_data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Input file '{}' is empty. Nothing to process.",
                input_path.display()
            ),
        ));
    }

    // Ensure key length is at least as long as the input data
    if key.len() < input_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key is shorter than input data. Please provide a key of sufficient length.",
        ));
    }

    // Encrypt or decrypt using XOR
    let processed_data = input_data
        .iter()
        .zip(key.iter())
        .map(|(&data_byte, &key_byte)| data_byte ^ key_byte)
        .collect::<Vec<u8>>();

    // Write the processed data to the output file
    let mut output_file = File::create(&output_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to create output file '{}': {}",
                output_path.display(),
                e
            ),
        )
    })?;
    output_file.write_all(&processed_data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "Failed to write to output file '{}': {}",
                output_path.display(),
                e
            ),
        )
    })?;

    // Verify output file size matches input file size
    let input_size = metadata(&input_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to read input file metadata '{}': {}",
                input_path.display(),
                e
            ),
        )
    })?
    .len();
    let output_size = metadata(&output_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to read output file metadata '{}': {}",
                output_path.display(),
                e
            ),
        )
    })?
    .len();
    if input_size != output_size {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Output file size does not match input file size.",
        ));
    }

    println!("Operation completed successfully.");

    Ok(())
}

/// Parses the size string and returns the size in bytes.
fn parse_size(size_str: &str) -> Result<usize, String> {
    let size_str = size_str.to_lowercase();

    // Separate the numeric part and the unit part
    let (number_part, unit) = size_str
        .trim()
        .chars()
        .partition::<String, _>(|c| c.is_digit(10));

    // Parse the number part as usize
    let size: usize = number_part
        .parse()
        .map_err(|_| "Invalid number format".to_string())?;

    // Match the unit to calculate the size in bytes
    let bytes = match unit.as_str() {
        "b" | "bytes" => size,
        "kb" => size * 1024,
        "mb" => size * 1024 * 1024,
        "gb" => size * 1024 * 1024 * 1024,
        _ => return Err("Unknown unit".to_string()),
    };

    Ok(bytes)
}

