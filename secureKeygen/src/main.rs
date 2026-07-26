use argon2::Argon2;
use clap::Parser;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

/// Command-line arguments structure
#[derive(Parser)]
#[command(
    name = "Key Generator",
    version = "1.0",
    about = "Generates deterministic cryptographically secure keys."
)]
struct Cli {
    /// Password for key derivation
    #[arg(short = 'p', long)]
    password: String,

    /// Path to the salt file (salt.bin)
    #[arg(short = 'f', long, value_name = "FILE")]
    salt_file: PathBuf,

    /// Size of the key to generate (e.g., 1K, 5M, 1G)
    #[arg(short = 's', long)]
    size: String,

    /// Output file path (defaults to stdout if not provided)
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,
}

/// Parses the size string and converts it to a number of bytes
fn parse_size(size_str: &str) -> Result<usize, String> {
    let mut chars = size_str.chars();
    let mut num_str = String::new();
    while let Some(c) = chars.next() {
        if c.is_digit(10) {
            num_str.push(c);
        } else {
            let unit = c.to_ascii_uppercase();
            let num: usize = num_str.parse().map_err(|_| "Invalid size number".to_string())?;
            return match unit {
                'B' => Ok(num),
                'K' => Ok(num * 1024),
                'M' => Ok(num * 1024 * 1024),
                'G' => Ok(num * 1024 * 1024 * 1024),
                _ => Err("Unknown size unit".to_string()),
            };
        }
    }
    num_str.parse().map_err(|_| "Invalid size number".to_string())
}

fn main() -> io::Result<()> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Parse and validate the size input
    let size = match parse_size(&cli.size) {
        Ok(size) => size,
        Err(e) => {
            eprintln!("Error parsing size: {}", e);
            std::process::exit(1);
        }
    };

    // Ensure size is within the allowed range (1 byte to 5GB)
    const MAX_SIZE: usize = 5 * 1024 * 1024 * 1024;
    if size < 1 || size > MAX_SIZE {
        eprintln!("Size must be between 1 byte and 5GB");
        std::process::exit(1);
    }

    // Read the salt from the specified file
    let mut salt_file = File::open(&cli.salt_file).map_err(|e| {
        eprintln!("Error opening salt file: {}", e);
        e
    })?;
    let mut salt = Vec::new();
    salt_file.read_to_end(&mut salt).map_err(|e| {
        eprintln!("Error reading salt file: {}", e);
        e
    })?;

    // Derive a key using Argon2id
    let argon2 = Argon2::default();
    let password_bytes = cli.password.as_bytes();

    let mut key_bytes = [0u8; 32]; // ChaCha20 requires a 256-bit key
    argon2
        .hash_password_into(password_bytes, &salt, &mut key_bytes)
        .map_err(|e| {
            eprintln!("Error during key derivation: {:?}", e);
            io::Error::new(io::ErrorKind::Other, "Key derivation failed")
        })?;

    // Zeroize the password to remove it from memory
    let mut password = cli.password;
    password.zeroize();

    // Initialize ChaCha20 cipher with the derived key and a zero nonce for deterministic output
    let mut key = chacha20::Key::clone_from_slice(&key_bytes);

    // Zeroize key_bytes after use
    key_bytes.zeroize();

    let nonce_bytes = [0u8; 12]; // ChaCha20 nonce size
    let nonce = chacha20::Nonce::from_slice(&nonce_bytes);

    let mut cipher = ChaCha20::new(&key, nonce);

    // Zeroize the key after use
    key.zeroize();

    // Generate the key data
    let mut data = vec![0u8; size];
    cipher.apply_keystream(&mut data);

    // Write the output to the specified file or stdout
    if let Some(output_path) = cli.output {
        let mut output_file = File::create(&output_path).map_err(|e| {
            eprintln!("Error creating output file: {}", e);
            e
        })?;
        output_file.write_all(&data)?;
    } else {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(&data)?;
    }

    // Zeroize sensitive data before exiting
    salt.zeroize();
    data.zeroize();

    Ok(())
}
