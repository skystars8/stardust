use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process;

use argon2::{Argon2, Params};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

// Compile-time configurable parameters
const OUTPUT_FILENAME: &str = "key1.key1";

// The following constants can be adjusted at compile time
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

fn main() {
    // Retrieve command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <size> <bytes|mb|gb> <password>", args[0]);
        process::exit(1);
    }

    // Parse size argument
    let size_str = &args[1];
    let size_unit = &args[2];
    let password = &args[3];

    let size_in_bytes: usize = match size_str.parse::<usize>() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Invalid size value: {}", size_str);
            process::exit(1);
        }
    };

    let total_size = match size_unit.as_str() {
        "bytes" => size_in_bytes,
        "mb" => size_in_bytes * 1024 * 1024,
        "gb" => size_in_bytes * 1024 * 1024 * 1024,
        _ => {
            eprintln!("Invalid size unit: {}. Use 'bytes', 'mb', or 'gb'", size_unit);
            process::exit(1);
        }
    };

    if total_size < 1 || total_size > 5 * 1024 * 1024 * 1024 {
        eprintln!("Size must be between 1 byte and 5 GB.");
        process::exit(1);
    }

    let output_path = Path::new(OUTPUT_FILENAME);
    if output_path.exists() {
        eprintln!(
            "Error: File '{}' already exists and will not be overwritten.",
            OUTPUT_FILENAME
        );
        process::exit(1);
    }

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

    let password_bytes = password.as_bytes();

    let mut derived_key = [0u8; 32];
    if let Err(e) = argon2.hash_password_into(password_bytes, SALT, &mut derived_key) {
        eprintln!("Failed to derive key with Argon2: {}", e);
        process::exit(1);
    }

    // Initialize AES-256 in CTR mode with derived key and IV
    let mut cipher = Aes256Ctr::new(&derived_key.into(), &IV.into());

    // Use a CSPRNG seeded with the derived key for additional randomness
    let mut rng = ChaCha20Rng::from_seed(derived_key);

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating file: {}", e);
            process::exit(1);
        }
    };

    let mut bytes_written = 0;
    let buffer_size = 1024 * 1024; // 1 MB buffer
    let mut buffer = vec![0u8; buffer_size];

    while bytes_written < total_size {
        let current_size = std::cmp::min(buffer_size, total_size - bytes_written);
        rng.fill_bytes(&mut buffer[..current_size]);
        cipher.apply_keystream(&mut buffer[..current_size]);

        if let Err(e) = file.write_all(&buffer[..current_size]) {
            eprintln!("Error writing to file: {}", e);
            process::exit(1);
        }

        bytes_written += current_size;
    }

    // Zeroize sensitive data
    derived_key.zeroize();
    buffer.zeroize();

    println!("Key file '{}' generated successfully.", OUTPUT_FILENAME);
}
