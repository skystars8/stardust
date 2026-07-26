use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::fs::{self, File};
use std::io::{Read, Write};
use zeroize::Zeroize;

/// Custom SPN Encryption Application
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new encryption key
    GenerateKey {
        /// Key length in bytes (must be at least 16)
        #[arg(short, long, default_value_t = 32)]
        length: usize,
        /// Output file for the key
        #[arg(short, long, default_value = "key.key")]
        output: String,
    },
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: String,
        /// Output file for encrypted data
        #[arg(short, long)]
        output: String,
        /// Key file
        #[arg(short, long, default_value = "key.key")]
        key: String,
        /// Number of rounds
        #[arg(short = 'r', long, default_value_t = 16)]
        rounds: usize,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: String,
        /// Output file for decrypted data
        #[arg(short, long)]
        output: String,
        /// Key file
        #[arg(short, long, default_value = "key.key")]
        key: String,
        /// Number of rounds
        #[arg(short = 'r', long, default_value_t = 16)]
        rounds: usize,
    },
}

const AES_SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

const BLOCK_SIZE: usize = 16;

/// Generate a random key and save it securely
fn generate_key(length: usize, output: &str) -> Result<()> {
    if length < 16 {
        anyhow::bail!("Key length must be at least 16 bytes.");
    }

    let mut key = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut key);

    let mut file = File::create(output).with_context(|| "Failed to create key file.")?;
    file.write_all(&key)
        .with_context(|| "Failed to write key to file.")?;

    // Zero out key from memory
    key.zeroize();

    println!("Key generated and saved to {}", output);
    Ok(())
}

/// Load the key from a file
fn load_key(key_path: &str) -> Result<Vec<u8>> {
    let key = fs::read(key_path)
        .with_context(|| format!("Failed to read key file '{}'.", key_path))?;

    if key.len() < 16 {
        anyhow::bail!("Invalid key length. Key must be at least 16 bytes.");
    }

    Ok(key)
}

/// Improved key schedule function
fn generate_round_keys(key: &[u8], rounds: usize) -> Vec<[u8; BLOCK_SIZE]> {
    let mut round_keys = Vec::with_capacity(rounds);
    let mut prev_key = [0u8; BLOCK_SIZE];

    // Initialize with the first BLOCK_SIZE bytes of the key
    prev_key.copy_from_slice(&key[..BLOCK_SIZE]);

    for round in 0..rounds {
        let mut current_key = [0u8; BLOCK_SIZE];

        // Simple key schedule algorithm
        for i in 0..BLOCK_SIZE {
            current_key[i] = prev_key[i]
                .wrapping_add(key[(round + i) % key.len()])
                .wrapping_add(round as u8);
        }

        round_keys.push(current_key);
        prev_key = current_key;
    }

    round_keys
}

/// Apply substitution using AES S-box
fn apply_substitution(block: &mut [u8]) {
    for byte in block.iter_mut() {
        *byte = AES_SBOX[*byte as usize];
    }
}

/// Apply inverse substitution using AES inverse S-box
fn apply_inverse_substitution(block: &mut [u8]) {
    for byte in block.iter_mut() {
        *byte = AES_INV_SBOX[*byte as usize];
    }
}

/// Apply a more complex permutation to the block
fn apply_permutation(block: &mut [u8]) {
    let permutation = [
        3,  0,  4,  12, 9,  7,  5,  15,
        2,  14, 1,  8,  13, 6,  11, 10,
    ];

    let mut temp = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        temp[i] = block[permutation[i]];
    }
    block.copy_from_slice(&temp);
}

/// Apply the inverse permutation to the block
fn apply_inverse_permutation(block: &mut [u8]) {
    let inverse_permutation = [
        1, 10, 8, 0, 2, 6, 13, 5,
        11, 4, 15, 14, 3, 12, 9, 7,
    ];

    let mut temp = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        temp[i] = block[inverse_permutation[i]];
    }
    block.copy_from_slice(&temp);
}

/// Encrypt data using SPN
fn spn_encrypt(data: &[u8], key: &[u8], rounds: usize) -> Vec<u8> {
    let round_keys = generate_round_keys(key, rounds);
    let mut result = Vec::with_capacity(data.len());

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);

        // Pre-whitening
        for i in 0..BLOCK_SIZE {
            block[i] ^= key[i % key.len()];
        }

        for round in 0..rounds {
            apply_substitution(&mut block);
            apply_permutation(&mut block);

            // XOR with round key
            for i in 0..BLOCK_SIZE {
                block[i] ^= round_keys[round][i];
            }
        }

        result.extend_from_slice(&block);
    }

    result
}

/// Decrypt data using SPN
fn spn_decrypt(data: &[u8], key: &[u8], rounds: usize) -> Vec<u8> {
    let round_keys = generate_round_keys(key, rounds);
    let mut result = Vec::with_capacity(data.len());

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);

        for round in (0..rounds).rev() {
            // XOR with round key
            for i in 0..BLOCK_SIZE {
                block[i] ^= round_keys[round][i];
            }

            apply_inverse_permutation(&mut block);
            apply_inverse_substitution(&mut block);
        }

        // Reverse pre-whitening
        for i in 0..BLOCK_SIZE {
            block[i] ^= key[i % key.len()];
        }

        result.extend_from_slice(&block);
    }

    result
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey { length, output } => {
            generate_key(length, &output)?;
        }
        Commands::Encrypt {
            input,
            output,
            key,
            rounds,
        } => {
            let key_data = load_key(&key)?;
            let data = fs::read(&input).with_context(|| "Failed to read input file.")?;

            let encrypted_data = spn_encrypt(&data, &key_data, rounds);

            let mut output_file =
                File::create(&output).with_context(|| "Failed to create output file.")?;
            output_file
                .write_all(&encrypted_data)
                .with_context(|| "Failed to write encrypted data.")?;

            println!("File encrypted and saved to {}", output);
        }
        Commands::Decrypt {
            input,
            output,
            key,
            rounds,
        } => {
            let key_data = load_key(&key)?;
            let data = fs::read(&input).with_context(|| "Failed to read input file.")?;

            let decrypted_data = spn_decrypt(&data, &key_data, rounds);

            let mut output_file =
                File::create(&output).with_context(|| "Failed to create output file.")?;
            output_file
                .write_all(&decrypted_data)
                .with_context(|| "Failed to write decrypted data.")?;

            println!("File decrypted and saved to {}", output);
        }
    }

    Ok(())
}
