use clap::Parser;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Command line arguments parser
#[derive(Parser, Debug)]
#[command(name = "XOR File Encryptor")]
#[command(version = "1.0")]
#[command(about = "Encrypt and decrypt files using XOR and a 256-byte nonce with S-box randomization")]
struct Args {
    /// Mode: either "E" for encrypt or "D" for decrypt
    mode: String,

    /// Input file to encrypt or decrypt
    input_file: String,

    /// Output file to save the result
    output_file: String,
}

const NONCE_SIZE: usize = 256; // 256-byte nonce for XOR-based encryption

// Rijndael S-box (AES S-box)
const RIJNDAEL_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Function to generate a 256-byte nonce with no repeated values and randomize with S-box
fn generate_sbox_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce: [u8; NONCE_SIZE] = [0; NONCE_SIZE];
    for (i, val) in nonce.iter_mut().enumerate() {
        *val = i as u8;
    }

    // Shuffle the nonce to randomize it
    let mut rng = thread_rng();
    nonce.shuffle(&mut rng);

    // Apply the Rijndael S-box transformation to each byte in the nonce
    for val in nonce.iter_mut() {
        *val = RIJNDAEL_SBOX[*val as usize];
    }

    nonce
}

// XOR encrypt/decrypt using the key and the 256-byte nonce
fn xor_encrypt_decrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());

    // XOR each byte of the plaintext with the corresponding key and nonce byte
    for (i, byte) in data.iter().enumerate() {
        let xor_byte = byte ^ key[i % key.len()] ^ nonce[i % nonce.len()];
        output.push(xor_byte);
    }

    output
}

// Read the key from key.key, if not found, exit with a warning
fn read_key_file() -> io::Result<Vec<u8>> {
    let path = Path::new("key.key");
    if !path.exists() {
        eprintln!("Error: Key file 'key.key' not found. Exiting.");
        std::process::exit(1);
    }

    let mut file = File::open(&path)?;
    let mut key = Vec::new();
    file.read_to_end(&mut key)?;

    if key.is_empty() {
        eprintln!("Error: Key file 'key.key' is empty. Exiting.");
        std::process::exit(1);
    }

    Ok(key)
}

// Read the input file (plaintext or ciphertext)
fn read_input_file(file_in: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_in)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

// Write the output file (encrypted or decrypted)
fn write_output_file(file_out: &str, data: &[u8]) -> io::Result<()> {
    if Path::new(file_out).exists() {
        eprintln!("Error: Output file '{}' already exists. Operation aborted to prevent overwriting.", file_out);
        std::process::exit(1);
    }

    let mut file = File::create(file_out)?;
    file.write_all(data)?;
    Ok(())
}

// Encrypt the input file
fn encrypt_file(file_in: &str, file_out: &str) -> io::Result<()> {
    let key = read_key_file()?;  // Read the key from key.key
    let contents = read_input_file(file_in)?;  // Read the input file (plaintext)

    // Generate a new nonce for encryption
    let nonce = generate_sbox_nonce();

    // Encrypt the plaintext using the generated nonce
    let encrypted_message = xor_encrypt_decrypt(&contents, &key, &nonce);

    // Prepend the nonce to the encrypted message
    let mut result = Vec::with_capacity(NONCE_SIZE + encrypted_message.len());
    result.extend_from_slice(&nonce);  // Add the nonce at the beginning
    result.extend_from_slice(&encrypted_message);  // Add the encrypted message

    // Double-check the nonce size to ensure it is correct
    assert_eq!(nonce.len(), NONCE_SIZE, "Generated nonce is not 256 bytes");

    // Write the result to the output file
    write_output_file(file_out, &result)?;

    println!("Encryption complete. Nonce used is 256 bytes.");

    Ok(())
}

// Decrypt the input file
fn decrypt_file(file_in: &str, file_out: &str) -> io::Result<()> {
    let key = read_key_file()?;  // Read the key from key.key
    let contents = read_input_file(file_in)?;  // Read the input file (ciphertext)

    if contents.len() <= NONCE_SIZE {
        eprintln!("Error: Input file is too small to contain a valid nonce.");
        std::process::exit(1);
    }

    // Extract the nonce from the beginning of the file
    let (nonce, encrypted_message) = contents.split_at(NONCE_SIZE);

    // Double-check the nonce size to ensure it is correct
    assert_eq!(nonce.len(), NONCE_SIZE, "Extracted nonce is not 256 bytes");

    // Decrypt the file using the extracted nonce
    let decrypted_message = xor_encrypt_decrypt(encrypted_message, &key, nonce);

    // Write the decrypted message to the output file
    write_output_file(file_out, &decrypted_message)?;

    println!("Decryption complete. Nonce used is 256 bytes.");

    Ok(())
}

fn main() {
    let args = Args::parse();  // Parse command line arguments

    // Ensure the key file cannot be altered
    let key_path = Path::new("key.key");
    if !key_path.exists() {
        eprintln!("Error: Key file 'key.key' not found. Exiting.");
        std::process::exit(1);
    }
    if key_path.metadata().map(|m| m.permissions().readonly()).unwrap_or(false) {
        eprintln!("Error: Key file 'key.key' is read-only, preventing any modification during encryption or decryption.");
    }

    match args.mode.as_str() {
        "E" => {
            if let Err(e) = encrypt_file(&args.input_file, &args.output_file) {
                eprintln!("Error encrypting file: {}", e);
                std::process::exit(1);
            }
        }
        "D" => {
            if let Err(e) = decrypt_file(&args.input_file, &args.output_file) {
                eprintln!("Error decrypting file: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Error: Mode must be either 'E' for encrypt or 'D' for decrypt.");
            std::process::exit(1);
        }
    }
}
