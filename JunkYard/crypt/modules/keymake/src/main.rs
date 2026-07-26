use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::process;

use argon2::{Argon2, Params};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

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

fn print_usage(program_name: &str) {
    eprintln!("Usage:");
    eprintln!(
        "  {} <size> --mode <random|deterministic> [--password <password>]",
        program_name
    );
    eprintln!("Examples:");
    eprintln!("  {} 32bytes --mode random", program_name);
    eprintln!("  {} 20mb --mode deterministic --password mypass", program_name);
    eprintln!("  {} 5gb --mode random", program_name);
}

fn main() -> io::Result<()> {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();
    let program_name = &args[0];

    if args.len() < 3 {
        print_usage(program_name);
        process::exit(1);
    }

    // Default values
    let mut size_arg = String::new();
    let mut mode = String::new();
    let mut password = None;

    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --mode requires an argument.");
                    print_usage(program_name);
                    process::exit(1);
                }
                mode = args[i].clone();
            }
            "--password" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --password requires an argument.");
                    print_usage(program_name);
                    process::exit(1);
                }
                password = Some(args[i].clone());
            }
            _ => {
                if size_arg.is_empty() {
                    size_arg = args[i].clone();
                } else {
                    eprintln!("Error: Unexpected argument '{}'", args[i]);
                    print_usage(program_name);
                    process::exit(1);
                }
            }
        }
        i += 1;
    }

    if mode != "random" && mode != "deterministic" {
        eprintln!("Error: Mode must be 'random' or 'deterministic'.");
        print_usage(program_name);
        process::exit(1);
    }

    if mode == "deterministic" && password.is_none() {
        eprintln!("Error: --password is required in deterministic mode.");
        print_usage(program_name);
        process::exit(1);
    }

    // Parse the size argument
    let size_in_bytes = match parse_size(&size_arg) {
        Ok(size) => size,
        Err(err) => {
            eprintln!("Error parsing size: {}", err);
            process::exit(1);
        }
    };

    let output_file = "key.key";

    // Check if the file already exists
    if Path::new(output_file).exists() {
        eprintln!("Error: File '{}' already exists.", output_file);
        process::exit(1);
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
            12, 85, 240, 66, 171, 19, 55, 129,
            200, 33, 147, 89, 78, 123, 211, 34,
        ]; // Must be 16 bytes

        // Argon2 parameters
        const ARGON2_MEMORY_COST: u32 = 65536; // Memory cost in kibibytes
        const ARGON2_TIME_COST: u32 = 3;       // Number of iterations
        const ARGON2_PARALLELISM: u32 = 1;     // Degree of parallelism

        // Define type for AES-256 CTR mode
        type Aes256Ctr = ctr::Ctr64BE<Aes256>;

        // Derive a key using Argon2
        let params = match Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(32),
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to create Argon2 parameters: {}", e);
                process::exit(1);
            }
        };

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let password_str = password.unwrap();
        let password_bytes = password_str.as_bytes();

        let mut derived_key = [0u8; 32];
        if let Err(e) = argon2.hash_password_into(password_bytes, SALT, &mut derived_key) {
            eprintln!("Failed to derive key with Argon2: {}", e);
            process::exit(1);
        }

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
