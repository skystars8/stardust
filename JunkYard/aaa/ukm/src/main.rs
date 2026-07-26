use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use std::process;


// Initialization Vector (IV) - Change last 16 numbers to produce different deterministic keys at each compile
const IV: [u8; 16] = [12, 85, 240, 66, 171, 19, 55, 129, 200, 33, 147, 89, 78, 123, 211, 34];

const MAX_HKDF_OUTPUT_SIZE: usize = 255 * 32; // Maximum output size for HKDF expansion

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

    let output_path = Path::new("key1.key1");
    if output_path.exists() {
        eprintln!("Error: File 'key1.key1' already exists and will not be overwritten.");
        process::exit(1);
    }

    // Open file for writing
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&output_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating file: {}", e);
            process::exit(1);
        }
    };

    // Generate a unique salt by hashing the password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let salt = hasher.finalize();

    // Generate a deterministic key using HKDF in chunks with AES-CTR for extra randomness
    let hk = Hkdf::<Sha256>::new(Some(&salt), password.as_bytes());
    let mut key_material = [0u8; 32];
    if let Err(e) = hk.expand(b"key_generation_info", &mut key_material) {
        eprintln!("Error generating key material: {}", e);
        process::exit(1);
    }

    // Initialize AES-256 in CTR mode with derived key and IV (Initialization Vector)
    let mut cipher = Aes256Ctr::new(&key_material.into(), &IV.into());

    let mut bytes_written = 0;
    let mut buffer = vec![0u8; MAX_HKDF_OUTPUT_SIZE];

    while bytes_written < total_size {
        let current_size = std::cmp::min(MAX_HKDF_OUTPUT_SIZE, total_size - bytes_written);
        buffer[..current_size].fill(0);
        cipher.apply_keystream(&mut buffer[..current_size]);

        // Remove any whitespace characters from the buffer to ensure no whitespace in key
        buffer.iter_mut().for_each(|byte| if *byte == b' ' || *byte == b'\n' || *byte == b'\t' { *byte = 0; });

        if let Err(e) = file.write_all(&buffer[..current_size]) {
            eprintln!("Error writing to file: {}", e);
            process::exit(1);
        }
        bytes_written += current_size;
    }

    println!("Key file 'key1.key1' generated successfully.");
}

// Add dependencies to your Cargo.toml
// [dependencies]
// hkdf = "0.12.4"
// sha2 = "0.10.8"
// aes = "0.8.4"
// ctr = "0.9.2"
