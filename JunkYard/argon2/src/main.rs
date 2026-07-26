use clap::Parser;
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use std::fs::File;
use std::io::{self, Read, Write, stdin};
use std::path::PathBuf;
use std::time::Instant;

// Configurable variables
const DEFAULT_KEY_SIZE: usize = 32; // Default size of the key in bytes
const OUTPUT_FILE_PATH: &str = "1.key";
const SALT_FILE_PATH: &str = "salt.dat"; // Salt file path
const MAX_KEY_SIZE_BYTES: usize = 5 * 1024 * 1024 * 1024; // Maximum key size: 5GB

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {}

fn main() -> io::Result<()> {
    // Start measuring time
    let start_time = Instant::now();

    // Ask for key size
    println!("Enter the size of the key (e.g., 1GB, 500MB, 1024B) [default: {} bytes]:", DEFAULT_KEY_SIZE);
    let mut size_input = String::new();
    stdin().read_line(&mut size_input)?;

    // Validate key size input before parsing
    let key_size: usize = match parse_key_size(size_input.trim()) {
        Ok(size) if (1..=MAX_KEY_SIZE_BYTES).contains(&size) => size,
        Ok(_) | Err(_) if size_input.trim().is_empty() => DEFAULT_KEY_SIZE,
        _ => {
            eprintln!("Invalid input. Please enter a valid key size between 1 byte and 5GB.");
            std::process::exit(1);
        }
    };

    // Inform user that large key generation may take time
    println!("Note: Generating a cryptographic key of size {} bytes may take some time. Please be patient.", key_size);

    // Enforce a minimum password length
    println!("Enter a password to generate a deterministic key:");
    let mut password = String::new();
    stdin().read_line(&mut password)?;

    let password = password.trim().as_bytes();

    // Read or generate the salt
    let salt = get_salt()?;

    // Define the output file path
    let output_path = PathBuf::from(OUTPUT_FILE_PATH);

    // Check if the file already exists
    if output_path.exists() {
        // Ask for confirmation before overwriting
        println!("The file '{}' already exists. Do you want to overwrite it? [y/N]", OUTPUT_FILE_PATH);
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        // If the user doesn't explicitly say "y", cancel the operation
        if input != "y" {
            println!("Operation canceled. The key was not overwritten.");
            return Ok(());
        }
    }

    // Initialize the Argon2 hasher with default parameters
    let argon2 = Argon2::default();

    // Generate the hash with progress feedback
    let mut derived_key = vec![0u8; key_size];
    let chunk_size = key_size / 10;
    for i in 0..10 {
        let start = i * chunk_size;
        let end = if i == 9 { key_size } else { start + chunk_size };
        argon2.hash_password_into(&password, &salt, &mut derived_key[start..end])
            .expect("Error hashing password");
        println!("Progress: {}% complete", (i + 1) * 10);
    }

    // Write the derived key to the output file
    let mut file = File::create(&output_path)?;
    file.write_all(&derived_key)?;

    // Print the duration of the operation
    let duration = start_time.elapsed();
    println!(
        "Successfully generated a {}-byte key and saved it to '{}'.",
        key_size, OUTPUT_FILE_PATH
    );
    println!("Operation completed in {:.2?} seconds.", duration);

    Ok(())
}

fn parse_key_size(input: &str) -> Result<usize, &'static str> {
    if input.is_empty() {
        return Err("Empty input");
    }

    let lower_input = input.to_lowercase();
    if let Some(value) = lower_input.strip_suffix("gb") {
        value.trim().parse::<usize>().map(|v| v * 1024 * 1024 * 1024).map_err(|_| "Invalid GB value")
    } else if let Some(value) = lower_input.strip_suffix("mb") {
        value.trim().parse::<usize>().map(|v| v * 1024 * 1024).map_err(|_| "Invalid MB value")
    } else if let Some(value) = lower_input.strip_suffix("kb") {
        value.trim().parse::<usize>().map(|v| v * 1024).map_err(|_| "Invalid KB value")
    } else if let Some(value) = lower_input.strip_suffix("b") {
        value.trim().parse::<usize>().map_err(|_| "Invalid B value")
    } else {
        input.parse::<usize>().map_err(|_| "Invalid byte value")
    }
}

fn get_salt() -> io::Result<Vec<u8>> {
    let salt_path = PathBuf::from(SALT_FILE_PATH);

    if salt_path.exists() {
        // Read the salt from the file
        let mut file = File::open(&salt_path)?;
        let mut salt = Vec::new();
        file.read_to_end(&mut salt)?;
        println!("Using existing salt from '{}'.", SALT_FILE_PATH);
        Ok(salt)
    } else {
        // Generate a random salt
        let mut salt = vec![0u8; 32]; // 256-bit salt
        OsRng.fill_bytes(&mut salt);

        // Save the salt to the file
        let mut file = File::create(&salt_path)?;
        file.write_all(&salt)?;
        println!("Generated new salt and saved to '{}'.", SALT_FILE_PATH);
        Ok(salt)
    }
}
